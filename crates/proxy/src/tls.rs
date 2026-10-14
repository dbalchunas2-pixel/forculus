//! TLS certificate authority generation, leaf-cert caching, and TLS connector
//! configuration for the Forculus proxy.

use std::sync::Arc;

use lru::LruCache;
use parking_lot::Mutex;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use tokio_rustls::TlsConnector;

use forculus_config::expand_tilde;

/// Shared TLS state: the CA identity, a leaf-cert cache, and an outbound TLS
/// connector using system root certificates.
pub struct TlsState {
    /// The CA certificate (rcgen's type, used as the issuer for leaf certs).
    ca_cert: rcgen::Certificate,
    /// The CA's key pair (used to sign leaf certs).
    ca_key: KeyPair,
    /// The DER-encoded CA certificate (included in leaf cert chains).
    ca_cert_der: CertificateDer<'static>,
    /// LRU cache of generated leaf certificates keyed by hostname.
    leaf_cache: Mutex<LruCache<String, Arc<CertifiedKey>>>,
    /// Outbound TLS connector for connections to real servers.
    pub server_connector: TlsConnector,
}

impl std::fmt::Debug for TlsState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsState")
            .field("ca_cert_der_len", &self.ca_cert_der.len())
            .finish()
    }
}

impl TlsState {
    /// Build TLS state: load or generate a CA, set up the leaf-cert cache,
    /// and prepare the outbound TLS connector.
    pub fn new(ca_dir: &str) -> forculus_common::Result<Self> {
        // Ensure the aws-lc-rs crypto provider is installed (needed when
        // multiple rustls backends are present, e.g. in tests with reqwest).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let ca_dir = expand_tilde(ca_dir);
        std::fs::create_dir_all(&ca_dir).map_err(|e| {
            forculus_common::ForculusError::Tls(format!("cannot create CA directory: {e}"))
        })?;

        let cert_path = std::path::Path::new(&ca_dir).join("ca.pem");
        let key_path = std::path::Path::new(&ca_dir).join("ca-key.pem");

        let (ca_cert, ca_key, ca_cert_der) = if cert_path.exists() && key_path.exists() {
            load_ca(&cert_path, &key_path)?
        } else {
            let (cert, key, der) = generate_ca()?;
            write_ca(&cert_path, &key_path, &cert, &key)?;
            (cert, key, der)
        };

        let fingerprint = fnv_fingerprint(&ca_cert_der);
        tracing::info!(fingerprint, "CA ready");

        let server_connector = build_server_connector()?;

        let cache_cap = std::num::NonZeroUsize::new(1000).expect("non-zero");
        Ok(Self {
            ca_cert,
            ca_key,
            ca_cert_der,
            leaf_cache: Mutex::new(LruCache::new(cache_cap)),
            server_connector,
        })
    }

    /// Return the DER-encoded CA certificate (useful for tests that need to
    /// trust the proxy's CA).
    pub fn ca_cert_der(&self) -> &CertificateDer<'static> {
        &self.ca_cert_der
    }

    /// Obtain (from cache or freshly generated) a leaf certificate for the
    /// given hostname, signed by the CA.
    pub fn get_or_create_leaf_cert(&self, hostname: &str) -> Arc<CertifiedKey> {
        let mut cache = self.leaf_cache.lock();
        if let Some(existing) = cache.get(hostname) {
            return Arc::clone(existing);
        }
        let ck = Arc::new(self.generate_leaf_cert(hostname));
        cache.put(hostname.to_string(), Arc::clone(&ck));
        ck
    }

    fn generate_leaf_cert(&self, hostname: &str) -> CertifiedKey {
        let leaf_key =
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key generation");

        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, hostname);
        params.subject_alt_names = vec![SanType::DnsName(hostname.try_into().expect("valid DNS"))];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.is_ca = IsCa::NoCa;

        // 1-day validity.
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(1);

        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .expect("leaf cert signing");

        let cert_der: CertificateDer<'static> = CertificateDer::from(leaf_cert.der().to_vec());
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der().to_vec()));

        let signing_key =
            rustls::crypto::aws_lc_rs::sign::any_supported_type(&key_der).expect("signing key");

        CertifiedKey::new(vec![cert_der, self.ca_cert_der.clone()], signing_key)
    }
}

impl ResolvesServerCert for TlsState {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let hostname = client_hello.server_name()?.to_string();
        Some(self.get_or_create_leaf_cert(&hostname))
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn generate_ca() -> forculus_common::Result<(rcgen::Certificate, KeyPair, CertificateDer<'static>)>
{
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| {
        forculus_common::ForculusError::Tls(format!("CA key generation failed: {e}"))
    })?;

    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Forculus Local CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(3650);

    let cert = params
        .self_signed(&key)
        .map_err(|e| forculus_common::ForculusError::Tls(format!("CA self-sign failed: {e}")))?;
    let der = CertificateDer::from(cert.der().to_vec());

    Ok((cert, key, der))
}

fn load_ca(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> forculus_common::Result<(rcgen::Certificate, KeyPair, CertificateDer<'static>)> {
    let cert_pem = std::fs::read_to_string(cert_path)
        .map_err(|e| forculus_common::ForculusError::Tls(format!("read CA cert: {e}")))?;
    let key_pem = std::fs::read_to_string(key_path)
        .map_err(|e| forculus_common::ForculusError::Tls(format!("read CA key: {e}")))?;

    let key = KeyPair::from_pem(&key_pem)
        .map_err(|e| forculus_common::ForculusError::Tls(format!("parse CA key: {e}")))?;
    let params = CertificateParams::from_ca_cert_pem(&cert_pem)
        .map_err(|e| forculus_common::ForculusError::Tls(format!("parse CA cert: {e}")))?;

    // Read the original DER bytes from disk (for the cert chain).
    let cert_der = pem_to_der(&cert_pem)?;

    // Re-self-sign to get an rcgen::Certificate we can use as an issuer.
    // The subject DN and key are identical, so leaf certs signed by this
    // object will validate against the original CA cert from disk.
    let ca_cert = params
        .self_signed(&key)
        .map_err(|e| forculus_common::ForculusError::Tls(format!("CA re-sign failed: {e}")))?;

    tracing::info!(?cert_path, "loaded existing CA");
    Ok((ca_cert, key, cert_der))
}

fn pem_to_der(pem_str: &str) -> forculus_common::Result<CertificateDer<'static>> {
    let mut reader = std::io::BufReader::new(pem_str.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| forculus_common::ForculusError::Tls(format!("PEM decode: {e}")))?;
    certs
        .into_iter()
        .next()
        .ok_or_else(|| forculus_common::ForculusError::Tls("no certificate in PEM".to_string()))
}

fn write_ca(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    cert: &rcgen::Certificate,
    key: &KeyPair,
) -> forculus_common::Result<()> {
    use std::io::Write;

    // Write cert PEM (rcgen provides this when pem feature is enabled).
    let cert_pem = cert.pem();
    std::fs::File::create(cert_path)
        .and_then(|mut f| f.write_all(cert_pem.as_bytes()))
        .map_err(|e| forculus_common::ForculusError::Tls(format!("write CA cert: {e}")))?;

    // Write key PEM.
    let key_pem = key.serialize_pem();
    std::fs::File::create(key_path)
        .and_then(|mut f| f.write_all(key_pem.as_bytes()))
        .map_err(|e| forculus_common::ForculusError::Tls(format!("write CA key: {e}")))?;

    tracing::info!(?cert_path, "generated new CA");
    Ok(())
}

fn build_server_connector() -> forculus_common::Result<TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        // Ignore individual cert errors — some system certs may be malformed.
        let _ = roots.add(cert);
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Compute a short FNV-1a fingerprint of a DER-encoded certificate for
/// human-readable log output.
fn fnv_fingerprint(cert_der: &CertificateDer<'_>) -> String {
    use std::fmt::Write;
    let bytes = cert_der.as_ref();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0100_0000_01b3); // FNV-1a prime
    }
    let mut out = String::new();
    for b in hash.to_be_bytes() {
        let _ = write!(out, "{b:02X}");
    }
    out
}
