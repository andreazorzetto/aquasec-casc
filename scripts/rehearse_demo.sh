#!/usr/bin/env bash
# Run docs/demo.md against a live tenant, checking every exit code. Credentials as
# for any command. Touches only its own two throwaway policies, and removes them.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TAG=$(python3 -c 'import secrets; print(secrets.token_hex(3))')
INSTANCE="demo-$TAG"
NAME="demo-devtest-$TAG"
WORK=$(mktemp -d)
CASC=${CASC:-aquasec-casc}
PY=${PY:-python3}
failures=0

step() { printf '\n--- %s\n' "$1"; }
expect() {                         # expect CODE TEXT COMMAND...
  local want=$1 text=$2; shift 2
  local out code
  out=$("$@" 2>&1); code=$?
  printf '%s\n[exit %s]\n' "$out" "$code"
  if [ "$code" != "$want" ]; then echo "FAIL: wanted exit $want"; failures=$((failures + 1)); fi
  if [ -n "$text" ] && ! grep -qF -- "$text" <<<"$out"; then
    echo "FAIL: output lacks: $text"; failures=$((failures + 1)); fi
}
console() { "$PY" "$ROOT/scripts/_rehearsal_console.py" "$@"; }   # stands in for a person in the console

cleanup() {
  cd "$WORK" 2>/dev/null && rm -f ./*policy*.yaml
  "$CASC" apply -f "$WORK" --allow-empty --instance "$INSTANCE" >/dev/null 2>&1
  console delete "$NAME" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

step "Before: a policy made in the console, disabled"
console create "$NAME" || exit 1
cd "$WORK" && git init -q

step "1. Export"
expect 0 "1 exported" "$CASC" export --scope Global --name "$NAME" --kind RuntimePolicy -o . --instance "$INSTANCE"
FILE=runtime-policy-$NAME.yaml
cat "$FILE"
git add . && git -c user.name=demo -c user.email=demo@example.com commit -qm "Export from Aqua"

step "2. Applying it changes nothing"
expect 0 "+ ownership marker" "$CASC" plan -f .
expect 0 "1 adopted" "$CASC" apply -f .
expect 0 "1 unchanged" "$CASC" plan -f . --detailed-exitcode

step "3. One line in Git"
sed -i.bak '/blockNonCompliantImages: true/d' "$FILE" && rm "$FILE.bak"
git diff --stat | tail -2
git -c user.name=demo -c user.email=demo@example.com commit -qam "Dev/test does not block on the verdict"

step "4. Plan shows that one field"
expect 2 "controls.blockNonCompliantImages: true -> false" "$CASC" plan -f . --detailed-exitcode

step "5. Apply"
expect 0 "1 updated" "$CASC" apply -f .
console show "$NAME" block_disallowed_images false || failures=$((failures + 1))

step "6. Someone changes it in the console"
console tick "$NAME" block_disallowed_images
expect 2 "controls.blockNonCompliantImages: true -> false" "$CASC" plan -f . --detailed-exitcode
expect 0 "1 updated" "$CASC" apply -f .
expect 0 "1 unchanged" "$CASC" plan -f . --detailed-exitcode

step "7. Assurance policies work the same way"
sed "s/casc-playground-image/casc-demo-image-$TAG/" "$ROOT/examples/playground/assurance-policy-image.yaml" > assurance-policy-image.yaml
expect 0 "1 created" "$CASC" apply -f .
expect 0 "2 unchanged" "$CASC" plan -f . --detailed-exitcode

step "Clean up"
rm -f ./*policy*.yaml
expect 0 "no resources were loaded" "$CASC" apply -f .
expect 0 "2 deleted" "$CASC" apply -f . --allow-empty

printf '\n%s failure(s)\n' "$failures"
exit "$failures"
