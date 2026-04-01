# Axios macOS Scan

macOS-focused triage for the Axios / `plain-crypto-js` supply-chain incident.

This toolkit is meant for practical first-response on a Mac:
- scan for the primary published host IOC
- search current lockfiles and manifests for the compromised Axios versions
- search installed `node_modules` for `axios` and `plain-crypto-js`
- search npm execution logs, shell history, temp paths, and a limited macOS unified-log window
- export a Markdown report
- print a short terminal verdict

It is intentionally host-local only.
It does **not** query routers, DNS, proxies, or any external telemetry source.

## Files

- Script: [`scan.sh`](./scan.sh)

## What It Checks

1. Primary macOS IOC path
- `/Library/Caches/com.apple.act.mond`

2. Live runtime indicators
- suspicious process strings
- open network handles matching the published IOC set

3. Local retained evidence
- 7-day unified logs
- temp and staging paths
- shell history
- npm execution logs
- npm cache index metadata

4. Package exposure
- lockfiles under the selected scan roots
- `package.json` manifests under the selected scan roots
- installed `node_modules/axios/package.json`
- installed `node_modules/plain-crypto-js/package.json`
- installed compromised Axios versions in `node_modules`, even if lockfiles or manifests are no longer present

## Why this tool can still be useful even though the malware cleans up after itself

This campaign includes cleanup logic designed to reduce obvious forensic traces.

According to public analysis, the malicious `plain-crypto-js@4.2.1` dependency executes an obfuscated `postinstall` script, then deletes `setup.js`, removes the tampered `package.json`, and replaces it with a clean copy. That means simple checks of `node_modules/plain-crypto-js`, `npm ls`, or the current package state may look normal after execution.

This scanner is therefore not based on one artifact alone.

Instead, it looks for multiple residual signals that may still remain after cleanup, such as:

- the primary published macOS IOC path: `/Library/Caches/com.apple.act.mond`
- exact campaign strings and runtime indicators such as `sfrclak`, `142.11.206.73`, `6202033`, and `packages.npm.org/product0`
- retained local traces in temp paths, shell history, npm logs, npm cache metadata, and a limited unified-log window
- package exposure evidence in lockfiles, manifests, and installed `node_modules`

A simple package-state check can miss this incident after execution because the malicious install hook attempts to erase its own obvious footprint.

This does **not** defeat anti-forensic cleanup in every case.
If the install happened only briefly, logs rotated, temp artifacts disappeared, caches were cleared, or the affected workspace was deleted, false negatives are still possible.

So the tool should be understood as practical host-local triage:
it can materially lower uncertainty and sometimes find strong indicators, but it does not replace full forensics or external telemetry.

## What It Does Not Do

- no router / firewall / DNS / proxy checks
- no Time Machine or backup inspection unless you explicitly include those paths as scan roots
- no inspection of other user accounts unless you run it with access to those homes
- no full forensic reconstruction of deleted artifacts

## Requirements

The script is designed for stock macOS tooling and avoids third-party dependencies.

Expected tools:
- `/bin/bash`
- `find`
- `grep`
- `ps`
- `lsof`
- `log`
- `file`
- `shasum`
- `codesign`
- `python3`

`python3` is used only for two small helpers:
- bounding the unified-log query with a timeout
- truncating oversized result sections in the exported Markdown report

## Recommended macOS download and run workflow

On macOS, the most reliable way to use this script is to get it through Terminal, not through a browser download.

Reason:
- the script intentionally contains published malware IOC strings
- a browser-downloaded copy, especially from Safari, may get a `com.apple.quarantine` attribute
- Gatekeeper / XProtect may then block that downloaded copy even though the script is a defensive scanner

### Preferred: clone the repository

```bash
git clone <this-repository-url>
cd <repo>/scripts/axios-macos-scan
bash ./scan.sh
```

### Lightweight alternative: download the script with `curl`

```bash
mkdir -p ~/tools/axios-macos-scan
cd ~/tools/axios-macos-scan
curl -fsSLO https://raw.githubusercontent.com/<owner>/<repo>/<branch>/scripts/axios-macos-scan/scan.sh
chmod +x scan.sh
bash ./scan.sh
```

Why these two methods are preferred:
- Terminal-based `git clone` and `curl` downloads usually do not carry the same browser quarantine behavior as a Safari-downloaded standalone file
- this avoids the misleading macOS warning that can appear for a browser-downloaded copy

### If you already downloaded `scan.sh` in a browser and macOS blocks it

The safest recommendation is:
1. delete the browser-downloaded copy
2. get the script again via `git clone` or `curl`
3. run it with `bash ./scan.sh`

If you intentionally want to keep the already-downloaded file, first make sure it is the exact file you expect, then remove the quarantine attribute manually:

```bash
xattr -d com.apple.quarantine ./scan.sh
bash ./scan.sh
```

That should not be the default path for most users.

## Running the script

Make it executable once:

```bash
chmod +x ./scan.sh
```

Run with default scan roots:

```bash
bash ./scan.sh
```

Default scan roots are all existing directories among:
- `~/GitHub`
- `~/Projects`
- `~/Code`
- `~/Developer`

If none of those exist, it falls back to `HOME`.

Important:
- the script does **not** care what your repository is called
- it only cares whether the repository lives somewhere under one of the selected scan roots

Examples:
- if your repository has a different name but lives under `~/GitHub`, it is still scanned
- if your repository lives under one of the default roots such as `~/Projects` or `~/Developer`, it is scanned automatically
- if your repository lives somewhere else under `HOME`, such as `~/Work/client-x`, it is **not** scanned automatically as long as at least one default root exists on that Mac
- if none of the default roots exist, the script falls back to scanning all of `HOME`, which would also cover `~/Work/client-x` but is usually slower
- if you want predictable coverage for a path such as `~/Work/client-x`, add it explicitly with `--scan-root ~/Work/client-x`

Practical implication:
- the default root list is mainly a speed optimization so the script does not scan all of `HOME` on every run
- do not assume the default root list covers every project on your Mac
- if your repository lives under `HOME` but outside the default roots, it is usually **not** scanned automatically
- it is only covered by the `HOME` fallback when none of the default roots exist on that Mac
- if your repository lives outside `HOME`, it is **not** scanned automatically
- if you keep active workspaces outside those locations, add them explicitly with `--scan-root`
- if you want a faster and more predictable scan, keep your main development directories in the default-root list or pass them explicitly with `--scan-root`

Write the report to a chosen directory:

```bash
bash ./scan.sh --output-dir ~/Desktop
```

Scan one or more explicit roots:

```bash
bash ./scan.sh \
  --scan-root ~/GitHub \
  --scan-root /Volumes/Archive \
  --output-dir ~/Desktop
```

Skip the unified-log query if you want a faster run or if `log show` is too slow on a given host:

```bash
bash ./scan.sh --skip-unified-log
```

## Terminal Verdicts

The script prints one of three verdicts and exits with a matching code.

- `ENTWARNUNG` / exit `0`
  - no evidence found in the checked sources
- `ACHTUNG` / exit `1`
  - package exposure evidence found, but no strong host IOC
- `ALARM` / exit `2`
  - strong host IOC found

Example output:

```text
Verdict: ENTWARNUNG
No evidence found in the checked sources. This is triage, not full forensics.
Report written to: /path/to/axios-macos-scan-20260331-224947.md
```

## Report Output

The script exports a Markdown file like:

```text
axios-macos-scan-YYYYMMDD-HHMMSS.md
```

The report includes:
- scan roots
- verdict and interpretation
- summary counts
- raw findings sections for every checked source
- limitations

## Interpretation Guidance

- `ENTWARNUNG` means the script did not find evidence in the checked sources.
- It does **not** mathematically prove the Mac was never exposed.
- `ACHTUNG` includes compromised package references or installed package evidence, even if there is no current host IOC.
- `ALARM` is reserved for strong host-side signals such as the primary IOC path or exact runtime/log artifacts from the published campaign.
- If you get `ACHTUNG`, treat it as suspicious and investigate further.
- If you get `ALARM`, treat the host as potentially compromised and escalate to incident response.

## Practical Notes

- Large scan roots can take time.
- The unified-log query is bounded with a timeout, because `log show` can otherwise run too long on some Macs.
- npm cache findings are supplementary only. `_cacache` is content-addressed and not a clean forensic source.
- For wider organizational assurance, combine this host-local scan with external telemetry such as DNS, firewall, router, or proxy logs.

## References

- [Datadog Security Labs — Compromised axios npm package delivers cross-platform RAT](https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/)
- [Snyk Advisory — Embedded Malicious Code in axios](https://security.snyk.io/vuln/SNYK-JS-AXIOS-15850650)
- [Axios GitHub issue #10604 — public incident discussion](https://github.com/axios/axios/issues/10604)
