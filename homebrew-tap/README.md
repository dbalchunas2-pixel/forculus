# Homebrew Tap for Forculus

Open-source governance layer for AI agents.

## Install

```bash
brew tap bpolania/tap
brew install forculus
```

Or in one command:

```bash
brew install bpolania/tap/forculus
```

## Upgrade

```bash
brew update
brew upgrade forculus
```

## Uninstall

```bash
brew uninstall forculus
brew untap bpolania/tap
```

## Publishing a new release

1. Build release binaries for all targets:
   - `aarch64-apple-darwin`
   - `x86_64-apple-darwin`
   - `aarch64-unknown-linux-gnu`
   - `x86_64-unknown-linux-gnu`

2. Create `.tar.gz` archives containing the `forculus` binary.

3. Upload them to a GitHub Release tagged `vX.Y.Z`.

4. Compute SHA256 checksums:
   ```bash
   shasum -a 256 forculus-*.tar.gz
   ```

5. Update `Formula/forculus.rb` with the new version, URLs, and SHA256 values.

6. Commit and push to this repository.
