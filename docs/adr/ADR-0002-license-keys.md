# ADR-0002: Offline License-Key System

**Status:** Accepted (2026-10-14)
**Deciders:** David Balchunas

## Context

Forculus's business model starts with 100 lifetime founder licenses at $99. The product is local-first (see ADR-0001): no phone-home, no account server, no license API. We still need licenses that (a) cannot be trivially forged, (b) verify with zero network access, and (c) are cheap to issue and honor forever.

## Decision

1. **Ed25519-signed license files.** A license is a small signed document (JSON: licensee name, email, license class, issue date, license ID) with an Ed25519 signature. Verification is a public-key check inside the binary.
2. **No phone-home.** Verification is pure cryptography, offline. Forculus never calls a server to validate a license. This is both a privacy stance and a reliability guarantee (licenses work forever, even if Balchunas Sustainability disappears).
3. **Public key baked into the binary; private key never touches a build machine.** The private signing key is generated once, stored per KEY-INVENTORY.md (password manager + offline backup), and used only to issue licenses.
4. **Keypair generated before the first distributable build.** The public key is embedded at compile time. Rotating it later means shipping a new binary for everyone - this is a one-way door, hence this ADR existing before F2.
5. **Lifetime licenses are honored permanently.** The license file has no expiry field for founder licenses. If a paid tier with subscriptions ever exists, it uses a separate license class in the same format - never by expiring founder licenses retroactively.
6. **Enforcement posture: gentle.** Failed/missing license verification nags and disables founder-gated features (e.g. future paid GUI themes, priority support routing) but NEVER breaks core firewall function. A security tool that hard-bricks itself over a license check betrays its users; a cracked copy that still protects someone is acceptable losses. Revenue comes from goodwill and founder pricing, not DRM.

## Consequences

- Issuing a license is a local script + email attachment. No license server to run, secure, or pay for.
- License sharing is technically easy. Accepted at founder scale; the business model does not depend on perfect DRM.
- Future revocation (e.g. chargeback fraud) is handled by a revocation list shipped in threat-feed updates, opt-in to check, never a blocking call.
- Build task added to F2: embed `LICENSE_VERIFY_PUBKEY` at compile time; `license verify` CLI command for users to self-check.
