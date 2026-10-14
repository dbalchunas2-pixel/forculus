# Key Inventory and Recovery Plan

**Created:** 2026-10-14
**Owner:** David Balchunas (sole founder - you are the single point of failure; this document is the recovery plan)

## Rules

1. Every key Forculus will ever have is listed here BEFORE it is generated, with its storage location.
2. Private keys NEVER live in the repo, a build machine's repo checkout, or chat context. Generation output goes straight to storage.
3. Each private key has TWO offline backups minimum (password manager + encrypted offline copy), stored separately.
4. Losing the update-signing key kills the update channel for every installed copy. Losing the license-signing key means founder licenses cannot be issued or honored via new signatures. Treat both as irreplaceable.

## Key Register

| # | Key | Purpose | Generated | Storage (primary) | Backup | Rotation plan |
|---|-----|---------|-----------|-------------------|--------|---------------|
| 1 | Forculus update signing keypair | Signs auto-update manifests (Tauri updater, minisign-style). Public key embedded in shipped binaries. | [ ] Pending - generate before Checkpoint A (Nov 16) | Password manager (2FA-protected) | Encrypted USB + printed recovery sheet, stored separately | Post-launch rotation requires new binary release + user re-verification; document procedure in F2 |
| 2 | Forculus license signing keypair (Ed25519) | Signs license files. Public key embedded at compile time (ADR-0002). | [ ] Pending - generate before first distributable build (F2) | Password manager | Encrypted USB + printed recovery sheet, stored separately | Never rotate without honoring all lifetime licenses; new keys must coexist with old during transition |
| 3 | Apple Developer ID (cert + private key) | Signs + notarizes macOS app (Gatekeeper). | [ ] Pending - Apple Developer enrollment (user action, $99) | Login keychain, Mac only | Export .p12 to password-manager-protected archive | Apple-managed renewal annually; re-export after renewal |
| 4 | Threat feed signing keypair (future, DBA-8) | Signs published threat-feed bundles so clients verify authenticity. | [ ] Deferred until DBA-8 architecture ADR | TBD at generation | TBD | Per DBA-8 |

## Recovery

If a private key is lost:
1. Stop. Do not generate a replacement and pretend nothing happened.
2. Update-signing key lost: users must manually download + verify the next release; publish recovery instructions via SECURITY.md contact and all channels.
3. License-signing key lost: founder licenses already issued remain verifiable (public key still in binary), but NO new licenses can be signed. Restore from offline backup; if unavailable, re-issue requires a binary update embedding a new public key + manual license migration for affected users.
4. Update this register with incident notes at the bottom.

## Incident notes

(none)
