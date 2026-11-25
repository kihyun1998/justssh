#!/usr/bin/env bash
# Model-checks BrokerTokens.tla with TLC and compares each run with its expected outcome.
# Usage: check.sh [config ...]   (default: every config below)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
version=v1.7.4
sha=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
tmp="${TMPDIR:-${TEMP:-/tmp}}"
jar="${TLA2TOOLS:-$tmp/tla2tools-$version/tla2tools.jar}"

if [ ! -f "$jar" ]; then
  mkdir -p "$(dirname "$jar")"
  curl -sSLf -o "$jar" "https://github.com/tlaplus/tlaplus/releases/download/$version/tla2tools.jar"
fi
if command -v sha256sum >/dev/null; then got=$(sha256sum < "$jar" | cut -d' ' -f1)
else got=$(shasum -a 256 < "$jar" | cut -d' ' -f1); fi
if [ "$got" != "$sha" ]; then
  echo "tla2tools.jar at $jar is not TLC $version (sha256 $got)" >&2
  exit 2
fi
native() { cygpath -m "$1" 2>/dev/null || echo "$1"; }

# config:expected, where expected is "pass" or the invariant the run must violate.
expected=(
  "pins.cfg:pass"
  "launch.cfg:pass"
  "finding-pid-reuse.cfg:OnlyPinnedAfterGrace"
  "finding-idle-race.cfg:IdleDisposal"
)
if [ $# -gt 0 ]; then
  picked=()
  for want in "$@"; do
    for e in "${expected[@]}"; do [ "${e%%:*}" = "$want" ] && picked+=("$e"); done
  done
  expected=("${picked[@]}")
fi

logs="$tmp/justssh-broker-tokens-tlc"
mkdir -p "$logs"
status=0
for e in "${expected[@]}"; do
  cfg="${e%%:*}"; want="${e#*:}"
  log="$logs/${cfg%.cfg}.log"
  start=$(date +%s)
  (cd "$here" && java -XX:+UseParallelGC -cp "$(native "$jar")" tlc2.TLC -workers auto \
     -metadir "$(native "$logs/meta-${cfg%.cfg}")" -deadlock BrokerTokens.tla -config "$cfg") >"$log" 2>&1 || true
  secs=$(( $(date +%s) - start ))
  if grep -q "No error has been found" "$log"; then got=pass
  elif v=$(grep -o "Invariant [A-Za-z]* is violated" "$log" | head -1) && [ -n "$v" ]; then got=$(echo "$v" | cut -d' ' -f2)
  else got=broken; fi
  if [ "$got" = "$want" ]; then verdict=ok; else verdict=UNEXPECTED; status=1; fi
  printf '%-24s expected %-22s got %-22s %4ss  %s  log %s\n' "$cfg" "$want" "$got" "$secs" "$verdict" "$(native "$log")"
done
exit $status
