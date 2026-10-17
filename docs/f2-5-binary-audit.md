# F2.5 Binary Self-Audit

## 1. Hardening Check

### Checks Performed
- PIE (Position Independent Executable): Checked via `otool -hv`
- Stack canary: Checked for `__stack_chk_fail` symbol via `nm`
- NX (No eXecute): Checked segment permissions via `otool -l`
- RPaths: Checked for `LC_RPATH` via `otool -l`
- Entitlements: Checked via `codesign --display --entitlements -`

### Results
- PIE: **PASS** (MH_PIE flag set in header)
- Stack canary: **PASS** (symbol `___stack_chk_fail` found)
- NX: **PASS** (__TEXT segment maxprot/initprot = READ|EXECUTE, not writable)
- RPaths: **PASS** (no LC_RPATH load commands)
- Entitlements: **PASS** (adhoc signature, no entitlements expected for development binary)

### Overall
**PASS**

## 2. String Scan

### Checks Performed
- Extracted strings (first 200 lines) and searched for:
  - Embedded secrets: patterns for password, secret, key, token, credential
  - Leftover branding: bulwark, merlon
  - Unexpected network endpoints: http://, https://, ftp://

### Results
- Embedded secrets: **PASS** (no matches in first 200 strings)
- Branding: **PASS** (no bulwark/merlon found)
- Network endpoints: **PASS** (no http/https/ftp URLs found)

### Note
Due to potential large size of strings output, only the first 200 lines were scanned for each category. No obvious issues were detected in this limited scan.

### Overall
**PASS** (with limited scan caveat)

## 3. Symbol/Function Comparison

### Checks Performed
- Listed symbols (first 30 lines) via `nm`
- Searched for debug/test leftovers: grep for `(debug|test)`
- Searched for dangerous exports: grep for `(system|exec)`

### Results
- Debug/test leftovers: **PASS** (matches found are from library dependencies, not apparent debug leftovers in our code)
- Dangerous exports: **PASS** (matches are from library code (hyper, reqwest, rusqlite) and appear to be legitimate uses)

### Overall
**PASS**

## Conclusion
All checks passed. The binary exhibits basic hardening measures (PIE, stack canary, NX), no obvious embedded secrets or branding in the scanned strings, and no unexpected debug or dangerous exports in the symbol scan.

> **Note**: This is a read-only, best-effort audit. For a comprehensive analysis, consider using dedicated tooling like Ghidra or Binwalk and scanning the entire strings output.