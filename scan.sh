#!/bin/bash
set -euo pipefail

print_help() {
  cat <<'HELP'
Usage: scan.sh [options]

macOS-focused triage for the Axios/plain-crypto-js supply-chain incident.
The script scans the local host and one or more filesystem roots, writes a
Markdown report, and prints a short terminal verdict.

Options:
  --scan-root PATH     Add a filesystem root to scan. Repeatable.
                       Default: all existing roots among
                       ~/GitHub, ~/Projects, ~/Code, ~/Developer;
                       falls back to HOME if none exist.
  --output-dir PATH    Directory for the generated Markdown report.
                       Default: current working directory.
  --max-lines N        Max lines to keep per findings section.
                       Default: 200.
  --skip-unified-log   Skip the 7-day macOS unified log query.
  --help               Show this help text.

Exit codes:
  0  No evidence found in checked sources.
  1  Exposure evidence found (for example compromised package references),
     but no strong host IOC.
  2  Strong host IOC found (for example payload file or exact campaign runtime/log artifact).

Examples:
  bash ./scan.sh
  bash ./scan.sh --output-dir ~/Desktop
  bash ./scan.sh --scan-root ~/GitHub --scan-root /Volumes/Archive --output-dir ~/Desktop
HELP
}

SCAN_ROOTS=()
OUTPUT_DIR="$(pwd)"
MAX_LINES=200
SKIP_UNIFIED_LOG=0

discover_default_scan_roots() {
  local candidates=(
    "$HOME/GitHub"
    "$HOME/Projects"
    "$HOME/Code"
    "$HOME/Developer"
  )
  local root

  for root in "${candidates[@]}"; do
    [[ -d "$root" ]] && SCAN_ROOTS+=("$root")
  done

  if [[ ${#SCAN_ROOTS[@]} -eq 0 ]]; then
    SCAN_ROOTS=("$HOME")
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scan-root)
      [[ $# -lt 2 ]] && { echo "Missing value for --scan-root" >&2; exit 64; }
      SCAN_ROOTS+=("$2")
      shift 2
      ;;
    --output-dir)
      [[ $# -lt 2 ]] && { echo "Missing value for --output-dir" >&2; exit 64; }
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --max-lines)
      [[ $# -lt 2 ]] && { echo "Missing value for --max-lines" >&2; exit 64; }
      MAX_LINES="$2"
      shift 2
      ;;
    --skip-unified-log)
      SKIP_UNIFIED_LOG=1
      shift
      ;;
    --help|-h)
      print_help
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      print_help >&2
      exit 64
      ;;
  esac
done

if [[ ${#SCAN_ROOTS[@]} -eq 0 ]]; then
  discover_default_scan_roots
fi

for root in "${SCAN_ROOTS[@]}"; do
  if [[ ! -e "$root" ]]; then
    echo "Scan root does not exist: $root" >&2
    exit 66
  fi
done

mkdir -p "$OUTPUT_DIR"
TIMESTAMP_LOCAL="$(date '+%Y-%m-%d %H:%M:%S %Z')"
TIMESTAMP_FILE="$(date '+%Y%m%d-%H%M%S')"
START_DAY="$(date '+%Y-%m-%d')"
REPORT_PATH="$OUTPUT_DIR/axios-macos-scan-$TIMESTAMP_FILE.md"
HOSTNAME_FRIENDLY="$(scutil --get ComputerName 2>/dev/null || hostname)"
TMP_DIR="$(mktemp -d /tmp/axios-macos-scan.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

PRIMARY_IOC_PATH="/Library/Caches/com.apple.act.mond"
IOC_STRINGS_REGEX='plain-crypto-js|axios@1\.14\.1|axios@0\.30\.4|sfrclak|142\.11\.206\.73|6202033|com\.apple\.act\.mond|packages\.npm\.org/product0'
STRONG_IOC_REGEX='com\.apple\.act\.mond|sfrclak|142\.11\.206\.73|6202033|packages\.npm\.org/product0'
LOCKFILE_REGEX='axios@.*(1\.14\.1|0\.30\.4)|"axios"[[:space:]]*:[[:space:]]*"(\^|~)?(1\.14\.1|0\.30\.4)"|plain-crypto-js'
PACKAGE_REGEX='"axios"[[:space:]]*:[[:space:]]*"(\^|~)?(1\.14\.1|0\.30\.4)"|"plain-crypto-js"'
HISTORY_REGEX='plain-crypto-js|axios@1\.14\.1|axios@0\.30\.4|sfrclak|142\.11\.206\.73|6202033|com\.apple\.act\.mond|packages\.npm\.org/product0|npm install axios@1\.14\.1|npm install axios@0\.30\.4|yarn add axios@1\.14\.1|pnpm add axios@1\.14\.1|bun add axios@1\.14\.1'

PRIMARY_IOC_INFO="$TMP_DIR/primary_ioc_info.txt"
PRIMARY_IOC_EXISTS=0
PROCESS_HITS="$TMP_DIR/process_hits.txt"
NETWORK_HITS="$TMP_DIR/network_hits.txt"
UNIFIED_LOG_HITS="$TMP_DIR/unified_log_hits.txt"
UNIFIED_LOG_STATUS="$TMP_DIR/unified_log_status.txt"
TEMP_HITS="$TMP_DIR/temp_hits.txt"
USER_TEMP_HITS="$TMP_DIR/user_temp_hits.txt"
SHELL_HISTORY_HITS="$TMP_DIR/shell_history_hits.txt"
LOCKFILE_LIST="$TMP_DIR/lockfiles.list"
LOCKFILE_HITS="$TMP_DIR/lockfile_hits.txt"
PACKAGE_LIST="$TMP_DIR/package_json.list"
PACKAGE_HITS="$TMP_DIR/package_json_hits.txt"
NODE_MODULE_AXIOS_LIST="$TMP_DIR/node_module_axios.list"
NODE_MODULE_PLAIN_LIST="$TMP_DIR/node_module_plain.list"
NODE_MODULE_SUMMARY="$TMP_DIR/node_modules_summary.txt"
NPM_LOG_HITS="$TMP_DIR/npm_log_hits.txt"
NPM_CACHE_HITS="$TMP_DIR/npm_cache_hits.txt"
ALT_CACHE_STATUS="$TMP_DIR/alt_cache_status.txt"

: > "$PROCESS_HITS"
: > "$NETWORK_HITS"
: > "$UNIFIED_LOG_HITS"
: > "$UNIFIED_LOG_STATUS"
: > "$TEMP_HITS"
: > "$USER_TEMP_HITS"
: > "$SHELL_HISTORY_HITS"
: > "$LOCKFILE_LIST"
: > "$LOCKFILE_HITS"
: > "$PACKAGE_LIST"
: > "$PACKAGE_HITS"
: > "$NODE_MODULE_AXIOS_LIST"
: > "$NODE_MODULE_PLAIN_LIST"
: > "$NODE_MODULE_SUMMARY"
: > "$NPM_LOG_HITS"
: > "$NPM_CACHE_HITS"
: > "$ALT_CACHE_STATUS"

append_matches_from_list() {
  local list_file="$1"
  local regex="$2"
  local out_file="$3"
  local path

  while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    [[ ! -f "$path" ]] && continue
    LC_ALL=C grep -nH -E "$regex" "$path" >> "$out_file" 2>/dev/null || true
  done < "$list_file"
}

collect_project_files() {
  local out_file="$1"
  shift

  find "${SCAN_ROOTS[@]}" \
    \( -type d \( -name .git -o -name node_modules -o -name .venv -o -name venv -o -name dist -o -name build -o -name .next -o -name .nuxt -o -name DerivedData -o -name Pods -o -name target -o -name .Trash -o -name Library -o -name 'axios-macos-scan-regression*' -o -name 'axios-macos-scan-test*' \) -prune \) \
    -o "$@" -print 2>/dev/null | sort -u > "$out_file" || true
}

truncate_file() {
  local file="$1"
  if [[ -f "$file" ]]; then
    python3 - "$file" "$MAX_LINES" <<'PY'
import sys
from pathlib import Path
p = Path(sys.argv[1])
limit = int(sys.argv[2])
if not p.exists():
    raise SystemExit(0)
lines = p.read_text(errors='replace').splitlines()
if len(lines) > limit:
    p.write_text("\n".join(lines[:limit]) + f"\n... truncated after {limit} lines\n")
PY
  fi
}

count_lines() {
  local file="$1"
  [[ -s "$file" ]] && wc -l < "$file" | tr -d ' ' || echo 0
}

count_matching_lines() {
  local file="$1"
  local regex="$2"
  local count
  if [[ -s "$file" ]]; then
    count="$(LC_ALL=C grep -E -c "$regex" "$file" 2>/dev/null || true)"
    printf '%s\n' "${count:-0}"
  else
    echo 0
  fi
}

count_list_lines() {
  local file="$1"
  [[ -s "$file" ]] && sed '/^$/d' "$file" | wc -l | tr -d ' ' || echo 0
}

write_code_block_or_none() {
  local file="$1"
  if [[ -s "$file" ]]; then
    printf '```text\n' >> "$REPORT_PATH"
    cat "$file" >> "$REPORT_PATH"
    [[ "$(tail -c 1 "$file" 2>/dev/null || true)" != $'\n' ]] && printf '\n' >> "$REPORT_PATH"
    printf '```\n\n' >> "$REPORT_PATH"
  else
    printf '_No matches._\n\n' >> "$REPORT_PATH"
  fi
}

if [[ -e "$PRIMARY_IOC_PATH" ]]; then
  PRIMARY_IOC_EXISTS=1
  {
    ls -la "$PRIMARY_IOC_PATH" 2>&1 || true
    file "$PRIMARY_IOC_PATH" 2>&1 || true
    shasum -a 256 "$PRIMARY_IOC_PATH" 2>&1 || true
    codesign -dv --verbose=4 "$PRIMARY_IOC_PATH" 2>&1 || true
  } > "$PRIMARY_IOC_INFO"
else
  {
    echo "Path not present: $PRIMARY_IOC_PATH"
  } > "$PRIMARY_IOC_INFO"
fi

ps aux | grep -E 'com\.apple\.act\.mond|sfrclak|142\.11\.206\.73|curl.*6202033|packages\.npm\.org/product0' | grep -v grep | grep -v 'log show --style compact --last 7d --predicate' | grep -v 'axios-macos-scan/scan.sh' > "$PROCESS_HITS" 2>/dev/null || true
lsof -nP 2>/dev/null | grep -E 'sfrclak|142\.11\.206\.73' > "$NETWORK_HITS" || true

if [[ "$SKIP_UNIFIED_LOG" -eq 0 ]]; then
  python3 - "$UNIFIED_LOG_HITS" "$UNIFIED_LOG_STATUS" "$MAX_LINES" <<'PY'
import subprocess
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
status_path = Path(sys.argv[2])
max_lines = int(sys.argv[3])
cmd = [
    "log", "show",
    "--style", "compact",
    "--last", "7d",
    "--predicate",
    '(eventMessage CONTAINS[c] "sfrclak" OR eventMessage CONTAINS[c] "com.apple.act.mond" OR eventMessage CONTAINS[c] "6202033" OR eventMessage CONTAINS[c] "plain-crypto-js" OR eventMessage CONTAINS[c] "142.11.206.73" OR eventMessage CONTAINS[c] "packages.npm.org/product0")',
]

try:
    result = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=20)
    lines = result.stdout.splitlines()
    out_path.write_text("\n".join(lines[:max_lines]) + ("\n" if lines[:max_lines] else ""))
    status_path.write_text("Completed\n")
except subprocess.TimeoutExpired:
    out_path.write_text("")
    status_path.write_text("Timed out after 20 seconds\n")
PY
else
  echo "Skipped by user via --skip-unified-log" > "$UNIFIED_LOG_STATUS"
fi

find /tmp /private/tmp /var/folders -maxdepth 3 \
  \( -name '*6202033*' -o -iname '*plain-crypto-js*' -o -iname '*com.apple.act.mond*' \) \
  2>/dev/null | head -n "$MAX_LINES" > "$TEMP_HITS" || true

find "$HOME/.Trash" "$HOME/Downloads" "$HOME/Documents" "$HOME/Desktop" \
  \( -iname '*plain-crypto-js*' -o -iname '*com.apple.act.mond*' -o -iname '*6202033*' \) \
  2>/dev/null | head -n "$MAX_LINES" > "$USER_TEMP_HITS" || true

LC_ALL=C grep -nH -E "$HISTORY_REGEX" "$HOME/.zsh_history" "$HOME/.bash_history" > "$SHELL_HISTORY_HITS" 2>/dev/null || true

collect_project_files "$LOCKFILE_LIST" \( -name package-lock.json -o -name yarn.lock -o -name bun.lock -o -name pnpm-lock.yaml \) -type f
append_matches_from_list "$LOCKFILE_LIST" "$LOCKFILE_REGEX" "$LOCKFILE_HITS"

collect_project_files "$PACKAGE_LIST" -name package.json -type f
append_matches_from_list "$PACKAGE_LIST" "$PACKAGE_REGEX" "$PACKAGE_HITS"

if [[ -s "$PACKAGE_LIST" ]]; then
  while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    project_dir="$(dirname "$path")"
    [[ -f "$project_dir/node_modules/axios/package.json" ]] && printf '%s\n' "$project_dir/node_modules/axios/package.json" >> "$NODE_MODULE_AXIOS_LIST"
    [[ -f "$project_dir/node_modules/plain-crypto-js/package.json" ]] && printf '%s\n' "$project_dir/node_modules/plain-crypto-js/package.json" >> "$NODE_MODULE_PLAIN_LIST"
  done < "$PACKAGE_LIST"
  sort -u "$NODE_MODULE_AXIOS_LIST" -o "$NODE_MODULE_AXIOS_LIST" 2>/dev/null || true
  sort -u "$NODE_MODULE_PLAIN_LIST" -o "$NODE_MODULE_PLAIN_LIST" 2>/dev/null || true
fi

if [[ -s "$NODE_MODULE_AXIOS_LIST" ]]; then
  while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    version="$(LC_ALL=C grep -m1 '"version"' "$path" 2>/dev/null | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
    if [[ "$version" == "1.14.1" || "$version" == "0.30.4" ]]; then
      printf 'axios %s [COMPROMISED VERSION] -> %s\n' "${version:-unknown}" "$path" >> "$NODE_MODULE_SUMMARY"
    else
      printf 'axios %s -> %s\n' "${version:-unknown}" "$path" >> "$NODE_MODULE_SUMMARY"
    fi
  done < "$NODE_MODULE_AXIOS_LIST"
fi
if [[ -s "$NODE_MODULE_PLAIN_LIST" ]]; then
  while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    version="$(LC_ALL=C grep -m1 '"version"' "$path" 2>/dev/null | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
    printf 'plain-crypto-js %s -> %s\n' "${version:-unknown}" "$path" >> "$NODE_MODULE_SUMMARY"
  done < "$NODE_MODULE_PLAIN_LIST"
fi

if [[ -d "$HOME/.npm/_logs" ]]; then
  find "$HOME/.npm/_logs" -maxdepth 1 -type f -print 2>/dev/null | sort -u > "$TMP_DIR/npm_logs.list"
  append_matches_from_list "$TMP_DIR/npm_logs.list" "$IOC_STRINGS_REGEX" "$NPM_LOG_HITS"
fi

if [[ -d "$HOME/.npm/_cacache/index-v5" ]]; then
  find "$HOME/.npm/_cacache/index-v5" -type f -print 2>/dev/null | sort -u > "$TMP_DIR/npm_cache_index.list"
  append_matches_from_list "$TMP_DIR/npm_cache_index.list" 'plain-crypto-js|axios-1\.14\.1\.tgz|axios-0\.30\.4\.tgz|sfrclak|142\.11\.206\.73|6202033|com\.apple\.act\.mond' "$NPM_CACHE_HITS"
fi

for status_path in \
  "$HOME/.zsh_history:present if file exists" \
  "$HOME/.bash_history:present if file exists" \
  "$HOME/.npm:present if directory exists" \
  "$HOME/.npm/_cacache:present if directory exists" \
  "$HOME/Library/Caches/Yarn:present if directory exists" \
  "$HOME/.pnpm-store:present if directory exists" \
  "$HOME/Library/Caches/Bun:present if directory exists"
  do
    target="${status_path%%:*}"
    if [[ -e "$target" ]]; then
      printf '%s = present\n' "$target" >> "$ALT_CACHE_STATUS"
    else
      printf '%s = missing\n' "$target" >> "$ALT_CACHE_STATUS"
    fi
  done

truncate_file "$PROCESS_HITS"
truncate_file "$NETWORK_HITS"
truncate_file "$UNIFIED_LOG_HITS"
truncate_file "$UNIFIED_LOG_STATUS"
truncate_file "$TEMP_HITS"
truncate_file "$USER_TEMP_HITS"
truncate_file "$SHELL_HISTORY_HITS"
truncate_file "$LOCKFILE_HITS"
truncate_file "$PACKAGE_HITS"
truncate_file "$NODE_MODULE_SUMMARY"
truncate_file "$NPM_LOG_HITS"
truncate_file "$NPM_CACHE_HITS"
truncate_file "$ALT_CACHE_STATUS"

LOCKFILE_COUNT="$(count_list_lines "$LOCKFILE_LIST")"
PACKAGE_COUNT="$(count_list_lines "$PACKAGE_LIST")"
AXIOS_NODEMODULE_COUNT="$(count_list_lines "$NODE_MODULE_AXIOS_LIST")"
PLAIN_NODEMODULE_COUNT="$(count_list_lines "$NODE_MODULE_PLAIN_LIST")"
COMPROMISED_AXIOS_NODEMODULE_COUNT="$(count_matching_lines "$NODE_MODULE_SUMMARY" '^\s*axios (1\.14\.1|0\.30\.4) \[COMPROMISED VERSION\] -> ')"
PROCESS_HIT_COUNT="$(count_lines "$PROCESS_HITS")"
NETWORK_HIT_COUNT="$(count_lines "$NETWORK_HITS")"
UNIFIED_LOG_HIT_COUNT="$(count_lines "$UNIFIED_LOG_HITS")"
TEMP_HIT_COUNT="$(count_lines "$TEMP_HITS")"
USER_TEMP_HIT_COUNT="$(count_lines "$USER_TEMP_HITS")"
SHELL_HISTORY_HIT_COUNT="$(count_lines "$SHELL_HISTORY_HITS")"
LOCKFILE_HIT_COUNT="$(count_lines "$LOCKFILE_HITS")"
PACKAGE_HIT_COUNT="$(count_lines "$PACKAGE_HITS")"
NPM_LOG_HIT_COUNT="$(count_lines "$NPM_LOG_HITS")"
NPM_CACHE_HIT_COUNT="$(count_lines "$NPM_CACHE_HITS")"
UNIFIED_LOG_STRONG_HIT_COUNT="$(count_matching_lines "$UNIFIED_LOG_HITS" "$STRONG_IOC_REGEX")"
TEMP_STRONG_HIT_COUNT="$(count_matching_lines "$TEMP_HITS" "$STRONG_IOC_REGEX")"
USER_TEMP_STRONG_HIT_COUNT="$(count_matching_lines "$USER_TEMP_HITS" "$STRONG_IOC_REGEX")"

UNIFIED_LOG_EVIDENCE=0
if [[ -s "$UNIFIED_LOG_HITS" ]]; then
  UNIFIED_LOG_EVIDENCE=1
fi

STRONG_IOC=0
EXPOSURE_EVIDENCE=0

if [[ "$PRIMARY_IOC_EXISTS" -eq 1 ]]; then
  STRONG_IOC=1
fi
if [[ "$PROCESS_HIT_COUNT" -gt 0 || "$NETWORK_HIT_COUNT" -gt 0 ]]; then
  STRONG_IOC=1
fi
if [[ "$TEMP_STRONG_HIT_COUNT" -gt 0 || "$USER_TEMP_STRONG_HIT_COUNT" -gt 0 ]]; then
  STRONG_IOC=1
fi
if [[ "$UNIFIED_LOG_STRONG_HIT_COUNT" -gt 0 ]]; then
  STRONG_IOC=1
fi

if (( LOCKFILE_HIT_COUNT > 0 || PACKAGE_HIT_COUNT > 0 || PLAIN_NODEMODULE_COUNT > 0 || COMPROMISED_AXIOS_NODEMODULE_COUNT > 0 || NPM_LOG_HIT_COUNT > 0 || NPM_CACHE_HIT_COUNT > 0 || SHELL_HISTORY_HIT_COUNT > 0 || TEMP_HIT_COUNT > 0 || USER_TEMP_HIT_COUNT > 0 || UNIFIED_LOG_EVIDENCE == 1 )); then
  EXPOSURE_EVIDENCE=1
fi

VERDICT_CODE=0
VERDICT_LABEL="ENTWARNUNG"
VERDICT_DETAIL="No evidence found in the checked sources. This is triage, not full forensics."

if [[ "$STRONG_IOC" -eq 1 ]]; then
  VERDICT_CODE=2
  VERDICT_LABEL="ALARM"
  VERDICT_DETAIL="Strong host IOC found. Treat this Mac as potentially compromised and escalate to incident response."
elif [[ "$EXPOSURE_EVIDENCE" -eq 1 ]]; then
  VERDICT_CODE=1
  VERDICT_LABEL="ACHTUNG"
  VERDICT_DETAIL="Package exposure evidence found, but no strong host IOC. Treat as suspicious and investigate further."
fi

cat > "$REPORT_PATH" <<EOF2
# Axios Supply-Chain macOS Scan Report

- Generated: $TIMESTAMP_LOCAL
- Host: $HOSTNAME_FRIENDLY
- User: ${USER:-unknown}
- Scan roots:
EOF2
for root in "${SCAN_ROOTS[@]}"; do
  printf '  - `%s`\n' "$root" >> "$REPORT_PATH"
done
cat >> "$REPORT_PATH" <<EOF2
- Primary macOS IOC path:
  - $PRIMARY_IOC_PATH

## Verdict

- Verdict: **$VERDICT_LABEL**
- Detail: $VERDICT_DETAIL

## Summary counts

- Lockfiles inspected: $LOCKFILE_COUNT
- package.json manifests inspected: $PACKAGE_COUNT
- Installed axios package manifests found: $AXIOS_NODEMODULE_COUNT
- Installed compromised axios package manifests found: $COMPROMISED_AXIOS_NODEMODULE_COUNT
- Installed plain-crypto-js package manifests found: $PLAIN_NODEMODULE_COUNT
- Live process hits: $PROCESS_HIT_COUNT
- Live network-handle hits: $NETWORK_HIT_COUNT
- Unified log hits: $UNIFIED_LOG_HIT_COUNT
- Unified log status: $(tr '\n' ' ' < "$UNIFIED_LOG_STATUS" | sed 's/[[:space:]]*$//')
- Temp/staging hits: $TEMP_HIT_COUNT
- User temp area hits: $USER_TEMP_HIT_COUNT
- Shell history hits: $SHELL_HISTORY_HIT_COUNT
- Lockfile hits: $LOCKFILE_HIT_COUNT
- Manifest hits: $PACKAGE_HIT_COUNT
- npm log hits: $NPM_LOG_HIT_COUNT
- npm cache index hits: $NPM_CACHE_HIT_COUNT

## Interpretation

- ENTWARNUNG means no evidence was found in the checked sources.
- ACHTUNG means package exposure evidence was found, but no strong host IOC.
- ALARM means a strong host IOC was found and the Mac should be treated as potentially compromised.

This is a triage report, not a full forensic acquisition.

## Primary host IOC path

EOF2

write_code_block_or_none "$PRIMARY_IOC_INFO"

cat >> "$REPORT_PATH" <<EOF2
## Live process hits

EOF2
write_code_block_or_none "$PROCESS_HITS"

cat >> "$REPORT_PATH" <<EOF2
## Live network-handle hits

EOF2
write_code_block_or_none "$NETWORK_HITS"

cat >> "$REPORT_PATH" <<EOF2
## Unified log hits

EOF2
write_code_block_or_none "$UNIFIED_LOG_HITS"

cat >> "$REPORT_PATH" <<EOF2
## Unified log status

EOF2
write_code_block_or_none "$UNIFIED_LOG_STATUS"

cat >> "$REPORT_PATH" <<EOF2
## Temp and staging hits

EOF2
write_code_block_or_none "$TEMP_HITS"

cat >> "$REPORT_PATH" <<EOF2
## User temp area hits

EOF2
write_code_block_or_none "$USER_TEMP_HITS"

cat >> "$REPORT_PATH" <<EOF2
## Shell history hits

EOF2
write_code_block_or_none "$SHELL_HISTORY_HITS"

cat >> "$REPORT_PATH" <<EOF2
## Lockfile hits

EOF2
write_code_block_or_none "$LOCKFILE_HITS"

cat >> "$REPORT_PATH" <<EOF2
## Manifest hits

EOF2
write_code_block_or_none "$PACKAGE_HITS"

cat >> "$REPORT_PATH" <<EOF2
## Installed package summary

EOF2
write_code_block_or_none "$NODE_MODULE_SUMMARY"

cat >> "$REPORT_PATH" <<EOF2
## npm execution log hits

EOF2
write_code_block_or_none "$NPM_LOG_HITS"

cat >> "$REPORT_PATH" <<EOF2
## npm cache index hits

EOF2
write_code_block_or_none "$NPM_CACHE_HITS"

cat >> "$REPORT_PATH" <<EOF2
## Host cache and history path presence

EOF2
write_code_block_or_none "$ALT_CACHE_STATUS"

cat >> "$REPORT_PATH" <<'EOF2'
## Limitations

- This script does not inspect router, DNS, firewall, proxy, or external network telemetry.
- This script does not inspect Time Machine, detached external volumes, or other user accounts unless you include those paths as scan roots and have access.
- `ps`, `lsof`, and the unified log query only cover retained local state; they do not prove that no historical activity ever happened.
- npm cache results are supplementary only because `_cacache` is content-addressed and not a clean forensic source.
- A clean result materially lowers concern, but it is not a mathematical exclusion.
EOF2

printf '%s\n' "Verdict: $VERDICT_LABEL"
printf '%s\n' "$VERDICT_DETAIL"
printf '%s\n' "Report written to: $REPORT_PATH"

exit "$VERDICT_CODE"
