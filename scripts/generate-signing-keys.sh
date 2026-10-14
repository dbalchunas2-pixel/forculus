#!/usr/bin/env bash
# Forculus key generation - run ONCE, output goes to storage, NOT to chat or terminal history display
# Usage: bash scripts/generate-signing-keys.sh
set -euo pipefail

KEYS_DIR="${HOME}/.forculus-keys"
mkdir -p "${KEYS_DIR}"
chmod 700 "${KEYS_DIR}"

echo "=== Forculus Signing Key Generation ==="
echo "Keys will be written to ${KEYS_DIR} (gitignored, local only)."
echo "You must move them into your password manager + offline backup afterward"
echo "and then DELETE them from this directory. See docs/KEY-INVENTORY.md."
echo

# 1. Tauri update-signing keypair (minisign-compatible)
if command -v cargo >/dev/null 2>&1; then
  echo "--> Generating Tauri update signing keypair via tauri signer..."
  echo "    You will be prompted for a password. USE A UNIQUE, STRONG PASSWORD."
  echo "    Store that password in your password manager BEFORE continuing."
  read -r -p "Press Enter when ready... "
  cargo tauri signer generate -w "${KEYS_DIR}/forculus-update.key"
  echo "    Written: ${KEYS_DIR}/forculus-update.key (+ .pub)"
else
  echo "cargo not found; install Rust first."
  exit 1
fi

# 2. Ed25519 license-signing keypair
if command -v openssl >/dev/null 2>&1; then
  echo "--> Generating Ed25519 license signing keypair via openssl..."
  openssl genpkey -algorithm ed25519 -out "${KEYS_DIR}/forculus-license.key"
  openssl pkey -in "${KEYS_DIR}/forculus-license.key" -pubout -out "${KEYS_DIR}/forculus-license.pub"
  echo "    Written: ${KEYS_DIR}/forculus-license.key (+ .pub)"
else
  echo "openssl not found; cannot generate license keypair."
  exit 1
fi

echo
echo "=== NEXT STEPS (do not skip) ==="
echo "1. Copy BOTH private keys into your password manager as secure notes/attachments."
echo "2. Create one encrypted offline backup (USB) stored separately from the Mac."
echo "3. Record generation date in docs/KEY-INVENTORY.md and check the boxes."
echo "4. shred/rm the files from ${KEYS_DIR}:  rm -P ${KEYS_DIR}/*.key"
echo "5. Keep the .pub files - the license public key gets embedded at compile time (ADR-0002)."
