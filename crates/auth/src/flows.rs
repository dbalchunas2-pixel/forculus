//! OAuth 2.1 flows — authorization code + PKCE, code exchange, service token validation.

use forculus_common::ForculusError;
use openidconnect::{
    AccessToken, AuthorizationCode, CsrfToken, EmptyAdditionalClaims, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, Scope, TokenResponse, UserInfoClaims,
};

use crate::claims::{MappedClaims, hash_subject, resolve_operator};
use crate::provider::{AuthProvider, extract_groups_from_jwt};

/// Everything needed to resume an authorization code flow after the browser redirect.
pub struct AuthorizationRequest {
    /// The URL to redirect the browser to for authentication.
    pub authorization_url: url::Url,
    /// CSRF protection state token. Must match the `state` parameter in the callback.
    pub csrf_state: CsrfToken,
    /// Nonce for ID token validation. Must be stored and provided during code exchange.
    pub nonce: Nonce,
    /// PKCE verifier. Must be stored and provided during code exchange.
    pub pkce_verifier: PkceCodeVerifier,
}

impl AuthProvider {
    /// Generate an authorization URL for the interactive flow (Authorization Code + PKCE).
    ///
    /// Returns everything the caller needs to redirect the user's browser and later
    /// complete the flow via [`exchange_code`](Self::exchange_code).
    pub fn authorization_url(&self, scopes: &[String]) -> AuthorizationRequest {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut auth_request = self.client.authorize_url(
            openidconnect::core::CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );

        for scope in scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.clone()));
        }

        auth_request = auth_request.set_pkce_challenge(pkce_challenge);

        let (authorization_url, csrf_state, nonce) = auth_request.url();

        AuthorizationRequest {
            authorization_url,
            csrf_state,
            nonce,
            pkce_verifier,
        }
    }

    /// Exchange an authorization code for tokens. Validates the ID token (signature,
    /// issuer, audience, expiry, nonce) and extracts claims.
    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: PkceCodeVerifier,
        nonce: &Nonce,
    ) -> Result<MappedClaims, ForculusError> {
        // 1. Exchange authorization code for token response
        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .map_err(|e| {
                ForculusError::OidcTokenExchange(format!("token endpoint not configured: {e}"))
            })?
            .set_pkce_verifier(pkce_verifier)
            .request_async(&self.http_client)
            .await
            .map_err(|e| ForculusError::OidcTokenExchange(format!("code exchange failed: {e}")))?;

        // 2. Extract and verify ID token
        let id_token = token_response.id_token().ok_or_else(|| {
            ForculusError::OidcTokenValidation(
                "token response did not contain an ID token".to_string(),
            )
        })?;

        // Get the raw JWT string before verification (for group extraction later)
        let jwt_str = id_token.to_string();

        let verifier = self.client.id_token_verifier();
        let claims = id_token.claims(&verifier, nonce).map_err(|e| {
            ForculusError::OidcTokenValidation(format!("ID token validation failed: {e}"))
        })?;

        // 3. Extract standard claims
        let sub = claims.subject().to_string();
        let preferred_username = claims.preferred_username().map(|u| u.as_str().to_string());
        let email = claims.email().map(|e| e.as_str().to_string());

        // 4. Extract groups from the raw JWT payload.
        //    The ID token has been cryptographically verified above; this just
        //    reads the dynamic group claim from the already-verified payload.
        let groups = extract_groups_from_jwt(&jwt_str, &self.group_claim);

        // 5. Run group mapping
        let resolved = self.group_mapping.resolve(&groups);

        // 6. Build MappedClaims
        Ok(MappedClaims {
            operator: resolve_operator(preferred_username.as_deref(), email.as_deref(), &sub),
            team: resolved.team,
            environment: resolved.environment,
            agent_type: resolved.agent_type,
            labels: resolved.labels,
            ttl: self.default_session_ttl,
            provider_subject_hash: hash_subject(&sub),
        })
    }

    /// Validate a service account token (client credentials grant).
    ///
    /// The caller has already obtained a token via client_credentials flow with the IdP.
    /// This method validates the token via the IdP's userinfo endpoint and extracts claims.
    pub async fn validate_service_token(&self, token: &str) -> Result<MappedClaims, ForculusError> {
        if !self.service_accounts_enabled {
            return Err(ForculusError::OidcConfiguration(
                "service account authentication is not enabled".to_string(),
            ));
        }

        // Use the userinfo endpoint to validate the access token and get claims
        let userinfo_response: UserInfoClaims<
            EmptyAdditionalClaims,
            openidconnect::core::CoreGenderClaim,
        > = self
            .client
            .user_info(AccessToken::new(token.to_string()), None)
            .map_err(|e| {
                ForculusError::OidcTokenValidation(format!("userinfo endpoint not configured: {e}"))
            })?
            .request_async(&self.http_client)
            .await
            .map_err(|e| {
                ForculusError::OidcTokenValidation(format!(
                    "userinfo request failed (token may be invalid): {e}"
                ))
            })?;

        // Extract standard claims from userinfo
        let sub = userinfo_response.subject().to_string();

        let preferred_username = userinfo_response
            .preferred_username()
            .map(|u| u.as_str().to_string());
        let email = userinfo_response.email().map(|e| e.as_str().to_string());

        // Service accounts typically don't have group memberships via userinfo
        let groups: Vec<String> = vec![];
        let resolved = self.group_mapping.resolve(&groups);

        Ok(MappedClaims {
            operator: resolve_operator(preferred_username.as_deref(), email.as_deref(), &sub),
            team: resolved.team,
            environment: resolved.environment,
            agent_type: resolved.agent_type,
            labels: resolved.labels,
            ttl: self.default_session_ttl,
            provider_subject_hash: hash_subject(&sub),
        })
    }
}

#[cfg(test)]
mod tests {
    use openidconnect::{CsrfToken, Nonce, PkceCodeChallenge, PkceCodeVerifier, Scope};

    #[test]
    fn authorization_request_struct_fields() {
        let pkce_verifier = PkceCodeVerifier::new("test-verifier".to_string());
        let csrf_state = CsrfToken::new("test-state".to_string());
        let nonce = Nonce::new("test-nonce".to_string());
        let url = url::Url::parse(
            "https://example.com/authorize?code_challenge=abc&state=test-state&nonce=test-nonce",
        )
        .unwrap();

        let request = super::AuthorizationRequest {
            authorization_url: url,
            csrf_state,
            nonce,
            pkce_verifier,
        };

        assert!(request.authorization_url.as_str().contains("example.com"));
        assert_eq!(request.csrf_state.secret(), "test-state");
        assert_eq!(request.nonce.secret(), "test-nonce");
    }

    #[test]
    fn pkce_challenge_produces_valid_pair() {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        assert!(!verifier.secret().is_empty());
        assert!(!challenge.as_str().is_empty());
    }

    #[test]
    fn csrf_state_is_random() {
        let state1 = CsrfToken::new_random();
        let state2 = CsrfToken::new_random();
        assert_ne!(state1.secret(), state2.secret());
    }

    #[test]
    fn nonce_is_random() {
        let nonce1 = Nonce::new_random();
        let nonce2 = Nonce::new_random();
        assert_ne!(nonce1.secret(), nonce2.secret());
    }

    #[test]
    fn scope_construction() {
        let scope = Scope::new("openid".to_string());
        assert_eq!(scope.as_str(), "openid");
    }
}
