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
It does **not** query UniFi, routers, DNS, proxies, or any external telemetry source.

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

## What It Does Not Do

- no router / firewall / DNS / proxy / UniFi checks
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

## Usage

Make it executable once:

```bash
chmod +x ./scan.sh
```

Run with default scan roots:

```bash
./scan.sh
```

Default scan roots are all existing directories among:
- `~/GitHub`
- `~/Projects`
- `~/Code`
- `~/Developer`
- `~/Documents`

If none of those exist, it falls back to `HOME`.

Write the report to a chosen directory:

```bash
./scan.sh --output-dir ~/Desktop
```

Scan one or more explicit roots:

```bash
./scan.sh \
  --scan-root ~/GitHub \
  --scan-root /Volumes/Archive \
  --output-dir ~/Desktop
```

Skip the unified-log query if you want a faster run or if `log show` is too slow on a given host:

```bash
./scan.sh --skip-unified-log
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
