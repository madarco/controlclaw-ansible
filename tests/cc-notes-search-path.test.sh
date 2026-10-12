#!/bin/bash
# Tests roles/controlclaw/files/cc-notes-search-path against a stand-in for the OpenClaw CLI that
# answers the way 2026.9.9 does (checked on a box, 12 October 2026). Needs python3, nothing else.
#   bash tests/cc-notes-search-path.test.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../roles/controlclaw/files/cc-notes-search-path"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
fails=0

# The stand-in: `config get` answers from $T/get.{out,err,rc}; `config set` records its arguments.
cat > "$T/openclaw" <<'FAKE'
#!/bin/bash
D="$(dirname "$0")"
if [ "$1 $2" = "config get" ]; then cat "$D/get.out"; cat "$D/get.err" >&2; exit "$(cat "$D/get.rc")"; fi
if [ "$1 $2" = "config set" ]; then printf '%s\n' "$*" >> "$D/set.calls"; exit "$(cat "$D/set.rc" 2>/dev/null || echo 0)"; fi
exit 2
FAKE
chmod +x "$T/openclaw"

# check <name> <stdout of get> <stderr of get> <rc of get> <expected first word> <expected value set, or "">
check() {
  local name="$1" out="$2" err="$3" rc="$4" want="$5" wantset="$6"
  printf '%s' "$out" > "$T/get.out"; printf '%s' "$err" > "$T/get.err"; echo "$rc" > "$T/get.rc"; rm -f "$T/set.calls"
  local said code
  said="$(OPENCLAW_BIN="$T/openclaw" python3 "$SCRIPT" 2>&1)"; code=$?
  local set=""
  [ -f "$T/set.calls" ] && set="$(sed -E 's/^config set memory\.search\.extraPaths (.*) --strict-json$/\1/' "$T/set.calls")"
  if [ "$code" = 0 ] && [ "${said%%:*}" = "$want" ] && [ "$set" = "$wantset" ]; then echo "  ok   $name"; else echo "  FAIL $name: said '$said' (exit $code), set '$set'"; fails=$((fails + 1)); fi
}

N='"/var/lib/controlclaw-notes/sets"'
UNSET='Config path is valid but unset: memory.search.extraPaths. The runtime default applies until you set an authored value.'
check "not set: the folder becomes the list"            ""                              "$UNSET"            1 changed "[$N]"
check "an empty list"                                   "[]"                            ""                  0 changed "[$N]"
check "a person's paths are kept, ours is added"        '["/data/a", {"path": "/b", "pattern": "*.md"}]' "" 0 changed '["/data/a", {"path": "/b", "pattern": "*.md"}, '"$N]"
check "already there: nothing is written"               '[ "/data/a",'$'\n'"  $N ]"       ""                  0 ok      ""
check "already there as an object"                      '[{"path": "/var/lib/controlclaw-notes/sets"}]' ""  0 ok      ""
check "the folder of an earlier build is taken out"     '["/data/a", "/opt/controlclaw/shared-notes"]' ""   0 changed '["/data/a", '"$N]"
check "a warning line before the list: nothing written" $'Config warnings: something\n["/data/a"]' ""       0 skipped ""
check "a warning line after the list: nothing written"  $'["/data/a"]\nConfig warnings: x' ""               0 skipped ""
check "not a list"                                      '{"a": 1}'                      ""                  0 skipped ""
check "a list of something else"                        '[1, 2]'                        ""                  0 skipped ""
check "an error that is not 'unset'"                    ""                              "Unknown config path: memory.search.extraPaths." 1 skipped ""
check "'unset' with a warning beside it"                ""                              "Config warnings: x"$'\n'"$UNSET" 1 skipped ""
check "'unset' for another key"                         ""                              "Config path is valid but unset: memory.search.sources." 1 skipped ""
check "an exit code with a list on stdout"              '["/data/a"]'                   ""                  1 skipped ""
echo 1 > "$T/set.rc"
check "OpenClaw refuses the write: said, not failed"    "[]"                            ""                  0 skipped "[$N]"
rm -f "$T/set.rc"
# A write that never answers: said, not a crash. The stand-in sleeps past a limit the test sets short.
sed -i 's|^if \[ "$1 $2" = "config set" \]; then|if [ "$1 $2" = "config set" ] \&\& [ -f "$D/set.slow" ]; then sleep 5; fi\nif [ "$1 $2" = "config set" ]; then|' "$T/openclaw"
touch "$T/set.slow"; printf '[]' > "$T/get.out"; : > "$T/get.err"; echo 0 > "$T/get.rc"
said="$(OPENCLAW_BIN="$T/openclaw" CC_NOTES_OPENCLAW_SECONDS=1 python3 "$SCRIPT" 2>&1)"; code=$?
[ "$code" = 0 ] && [ "${said%%:*}" = skipped ] && grep -q "did not answer" <<<"$said" && echo "  ok   a write that does not answer in time: said, not failed" || { echo "  FAIL slow write: '$said' (exit $code)"; fails=$((fails + 1)); }
rm -f "$T/set.slow"
said="$(OPENCLAW_BIN="$T/nothing-here" python3 "$SCRIPT" 2>&1)"
[ "$said" = "skipped: OpenClaw is not installed" ] && echo "  ok   OpenClaw is not installed" || { echo "  FAIL not installed: $said"; fails=$((fails + 1)); }

[ "$fails" = 0 ] && echo "all passed" || { echo "$fails failed"; exit 1; }
