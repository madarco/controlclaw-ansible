#!/bin/bash
# Tests roles/controlclaw/files/cc-notes: the real helper, run as root, called for a caller who is
# not root (SUDO_UID, as sudo sets it). What it must refuse, and that it writes nowhere but the
# notes folder.
#
#   bash tests/cc-notes.test.sh           runs itself in a throwaway container (needs docker)
#   bash tests/cc-notes.test.sh --here    runs on this machine, as root. ONLY on a test box: it
#                                         uses /var/lib/controlclaw-notes and deletes what is there.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
HELPER_SRC="$HERE/../roles/controlclaw/files/cc-notes"

if [ "${1:-}" != "--here" ]; then
  # SYS_ADMIN: the test mounts a folder over the notes folder, as an agent with an encrypted disk has it.
  exec docker run --rm --cap-add SYS_ADMIN --security-opt apparmor=unconfined -v "$HERE/cc-notes.test.sh:/t/cc-notes.test.sh:ro" -v "$HELPER_SRC:/t/cc-notes:ro" -e CC_NOTES_HELPER=/t/cc-notes ubuntu:24.04 bash /t/cc-notes.test.sh --here
fi
[ "$(id -u)" = 0 ] || { echo "run as root (or without --here, in a container)"; exit 2; }
# A box with an encrypted container counts as one whatever else is there, so the cases of an agent
# without one cannot be made on it. There, run the container form of this test.
[ ! -e /var/lib/controlclaw/secure.img ] || { echo "this box has an encrypted container: run this test without --here (in a container), not on it"; exit 2; }

HELPER="${CC_NOTES_HELPER:-$HELPER_SRC}"
BASE=/var/lib/controlclaw-notes
ROOT="$BASE/sets"
WORK="$BASE/work"
# The fake caller: an ordinary user, as the agent's user is. `nobody` is on every Ubuntu.
CALLER_UID="$(id -u nobody)"; CALLER_GID="$(id -g nobody)"
T="$(mktemp -d /tmp/cc-notes-test.XXXXXX)"
chmod 755 "$T"
fails=0
MARK=/etc/controlclaw/notes-in-container
# On a test box with an encrypted disk the notes folder is a mount and the marker is there. Both are
# put aside for the test and put back after it.
WAS_MOUNT=""; mountpoint -q "$BASE" 2>/dev/null && { WAS_MOUNT="$(findmnt -n -o FSROOT "$BASE")"; WAS_DEV="$(findmnt -n -o SOURCE "$BASE" | sed 's/\[.*//')"; umount "$BASE"; }
WAS_MARK=""; [ -e "$MARK" ] && { WAS_MARK=1; mv "$MARK" "$MARK.test-aside"; }
restore() {
  umount "$BASE" 2>/dev/null; rm -rf "$T" "$BASE" "$BASE.aside" "$MARK"
  [ -z "$WAS_MARK" ] || mv "$MARK.test-aside" "$MARK"
  if [ -n "$WAS_MOUNT" ]; then mkdir -p "$BASE"; mount --bind "$(findmnt -n -o TARGET "$WAS_DEV" | head -1)$WAS_MOUNT" "$BASE"; fi
}
trap restore EXIT
# The parent as the role makes it. The helper makes `sets` and `work` in it when they are missing.
fresh() { rm -rf "$BASE" "$BASE.aside"; install -d -o root -g root -m 0755 "$BASE"; }
fresh
# Where the marker of an agent with an encrypted disk is. On a box it is there already.
mkdir -p /etc/controlclaw

# The helper as sudo would start it for the caller.
notes() { SUDO_UID="$CALLER_UID" SUDO_GID="$CALLER_GID" bash "$HELPER" "$@"; }
# A staging folder of the caller's, with one good file.
stage() { rm -rf "$T/s"; mkdir -p "$T/s"; echo "# Good" > "$T/s/good.md"; chown -R "$CALLER_UID:$CALLER_GID" "$T/s"; }
own() { chown -R -h "$CALLER_UID:$CALLER_GID" "$T/s"; }
# What is on disk outside the notes folder and the test's own folder, to compare before and after.
# /var/lib itself is left out: it holds the helper's folder, so its time changes with it. So is what a
# running box writes by itself meanwhile (its disk report's cursor, caches in the agent's home).
outside() { find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path "$T" -o -path "$BASE" -o -path "$BASE.aside" -o -path "$MARK" -o -path "$MARK.test-aside" -o -path /etc/controlclaw/disk-audit.cursor -o -path '/home/*/.cache' -o -path '/home/*/.npm' -o -path /tmp -o -path /var/log -o -path /var/lib/systemd -o -path /var/cache \) -prune -o -printf '%p %y %s %T@ %M %u\n' 2>/dev/null | grep -v -e '^/var/lib d ' -e '^/etc/controlclaw d ' | sort; }

pass() { echo "  ok   $1"; }
fail() { echo "  FAIL $1"; fails=$((fails + 1)); }
# refused <name> <words expected in the message> <helper arguments...>: exits non-zero, says why, and the set is not there.
refused() {
  local name="$1" words="$2"; shift 2
  local said code
  said="$(notes "$@" 2>&1)"; code=$?
  if [ "$code" != 0 ] && grep -q -- "$words" <<<"$said" && [ ! -e "$ROOT/t" ]; then pass "$name"; else fail "$name: exit $code, said '$said', set there: $([ -e "$ROOT/t" ] && echo yes || echo no)"; fi
}

before="$(outside)"

echo "what a set is"
stage; mkdir -p "$T/s/people"; echo "# Who" > "$T/s/people/who is who.MD"; own
if notes put t "$T/s" >/dev/null 2>&1 && [ "$(cat "$ROOT/t/good.md")" = "# Good" ] && [ -f "$ROOT/t/people/who is who.MD" ]; then pass "a folder of Markdown is put, also in a subfolder and named .MD"; else fail "a good set was not put"; fi
[ "$(find "$ROOT" -printf '%u:%g %m %y\n' | sort -u | tr '\n' ' ')" = "root:root 644 f root:root 755 d " ] && pass "everything in the notes folder is root's, 0644 in 0755" || fail "ownership or modes: $(find "$ROOT" -printf '%u:%g %m %y %P\n' | tr '\n' ' ')"
setpriv --reuid="$CALLER_UID" --regid="$CALLER_GID" --clear-groups sh -c "cat '$ROOT/t/good.md' >/dev/null && ! touch '$ROOT/t/x.md' 2>/dev/null && ! rm '$ROOT/t/good.md' 2>/dev/null && ! ls '$WORK' 2>/dev/null" && pass "the caller reads the set, cannot write it, and cannot look in the work folder" || fail "the caller could write the set or see the work folder"
stage; echo "# Only" > "$T/s/only.md"; rm "$T/s/good.md"; own
notes put t "$T/s" >/dev/null 2>&1 && [ ! -e "$ROOT/t/good.md" ] && [ ! -e "$ROOT/t/people" ] && [ -f "$ROOT/t/only.md" ] && pass "a put replaces the whole set" || fail "a put left files of the old set"
[ -z "$(find "$WORK" -mindepth 1)" ] && [ -z "$(find "$ROOT" -mindepth 1 -maxdepth 1 -name '.*')" ] && pass "nothing is left in the work folder, and nothing hidden in the notes folder" || fail "leftovers: $(find "$WORK" "$ROOT" -mindepth 1 -maxdepth 1 | tr '\n' ' ')"
notes remove t && [ ! -e "$ROOT/t" ] && notes remove t && pass "remove deletes the set, and a set that is not there is no error" || fail "remove"

echo "what is refused (nothing of the set is written)"
stage; ln -s /etc/shadow "$T/s/link.md"; own;                         refused "a link to a file only root may read" "not an ordinary file" put t "$T/s"
stage; ln -s good.md "$T/s/other.md"; own;                            refused "a link to a file of the set" "not an ordinary file" put t "$T/s"
stage; mkdir "$T/away"; echo "# x" > "$T/away/a.md"; ln -s "$T/away" "$T/s/dir"; own; refused "a link to a folder" "not an ordinary file" put t "$T/s"
stage; mkfifo "$T/s/pipe.md"; own;                                    refused "a pipe" "not an ordinary file" put t "$T/s"
stage; echo x > "$T/s/-x.md"; own;                                    refused "a name that starts with a dash" "name files and folders" put t "$T/s"
stage; echo x > "$T/s/.hidden.md"; own;                               refused "a name that starts with a dot" "name files and folders" put t "$T/s"
stage; mkdir "$T/s/-d"; echo x > "$T/s/-d/a.md"; own;                 refused "a folder that starts with a dash" "name files and folders" put t "$T/s"
stage; echo x > "$T/s/run.sh"; own;                                   refused "a file that is not .md" "Markdown files" put t "$T/s"
stage; echo x > "$T/s/notes.md.txt"; own;                             refused "a file that only has .md in its name" "Markdown files" put t "$T/s"
stage; printf 'x' > "$T/s/"$'new\nline.md'; own;                      refused "a name with a line break" "name files and folders" put t "$T/s"
stage; for i in $(seq 1 200); do echo x > "$T/s/f$i.md"; done; own;   refused "201 files" "at most 200 files" put t "$T/s"
stage; head -c $((257 * 1024)) /dev/zero | tr '\0' 'a' > "$T/s/big.md"; own; refused "a 257 KB file" "larger than 256 KB" put t "$T/s"
stage; for i in $(seq 1 9); do head -c 250000 /dev/zero | tr '\0' 'a' > "$T/s/p$i.md"; done; own; refused "more than 2 MB in all" "at most 2 MB" put t "$T/s"
stage; rm "$T/s/good.md"; mkdir "$T/s/empty"; own;                    refused "a folder with no Markdown" "no Markdown files" put t "$T/s"
stage; echo secret > "$T/s/rootonly.md"; chmod 600 "$T/s/rootonly.md"; chown root:root "$T/s/rootonly.md"; refused "a file the caller may not read" "could not be read" put t "$T/s"
stage; mkdir -p "$T/s/a/b"; own;                                      refused "a source path with .. that leads nowhere" "not one the caller can read" put t "$T/s/a/../nowhere"
stage; mkdir -p "$T/s/1/2/3/4/5/6/7/8"; echo x > "$T/s/1/2/3/4/5/6/7/8/deep.md"; own; refused "a file under 8 folders (9 parts)" "at most 8 parts" put t "$T/s"
stage; mkdir -p "$T/s/1/2/3/4/5/6/7/8"; own;                          refused "an empty folder 8 folders deep, where no file could be" "at most 8 parts" put t "$T/s"
stage; for i in $(seq 1 600); do mkdir "$T/s/d$i"; done; own;         refused "600 empty folders beside one file" "more than 600 files and folders" put t "$T/s"
stage; mkdir -p "$T/s/1/2/3/4/5/6/7"; echo "# deep" > "$T/s/1/2/3/4/5/6/7/ok.md"; own
notes put t "$T/s" >/dev/null 2>&1 && [ -f "$ROOT/t/1/2/3/4/5/6/7/ok.md" ] && pass "a file under 7 folders (8 parts) is taken" || fail "8 parts was refused"; notes remove t
# A folder only root can see: the answer is the same whether it is there or not.
mkdir -p "$T/private/there"; chmod 700 "$T/private"
a="$(notes put t "$T/private/there" 2>&1)"; b="$(notes put t "$T/private/not-there" 2>&1)"; c="$(notes put t /root 2>&1)"
[ "$a" = "$b" ] && [ "$a" = "$c" ] && grep -q "not one the caller can read" <<<"$a" && pass "a folder the caller cannot see: one answer, whether it is there or not" || fail "existence oracle: '$a' / '$b' / '$c'"
rm -rf "$T/private"
stage
for bad in "../x" "a/../b" "a/b" ".." "." "-x" ".x" "Abc" "a b" "a_b" "" "$(printf 'a%.0s' $(seq 1 65))"; do
  said="$(notes put "$bad" "$T/s" 2>&1)"; code=$?
  [ "$code" != 0 ] && grep -q "a set's name is" <<<"$said" || fail "the set name '$bad' was taken: exit $code, '$said'"
  said="$(notes remove "$bad" 2>&1)"; code=$?
  [ "$code" != 0 ] || fail "remove took the set name '$bad'"
done
[ -z "$(find "$ROOT" -mindepth 1)" ] && pass "bad set names: ../x, a/../b, a/b, .., ., -x, .x, capitals, a space, an underscore, empty, 65 characters" || fail "a bad name wrote something: $(find "$ROOT" -mindepth 1 | tr '\n' ' ')"
said="$(setpriv --reuid="$CALLER_UID" --regid="$CALLER_GID" --clear-groups bash "$HELPER" list 2>&1)"; [ $? != 0 ] && grep -q "must run as root" <<<"$said" && pass "not root: refused" || fail "ran without root"
refused "an unknown command" "usage" frobnicate
refused "too many arguments" "usage" put t "$T/s" extra

echo "a caller that changes the folder while the helper runs"
# A file swapped for a pipe after the listing: the read has a time limit, so the helper ends.
# The swap is one rename, so the helper finds either the file or the pipe, never nothing.
stage; for i in $(seq 1 190); do echo x > "$T/s/a$i.md"; done; echo x > "$T/s/zz-last.md"; mkfifo "$T/pipe"; own; chown "$CALLER_UID:$CALLER_GID" "$T/pipe"
( while [ -e "$T/pipe" ]; do if [ -n "$(find "$WORK" -name listing -size +0 2>/dev/null)" ]; then mv -f "$T/pipe" "$T/s/zz-last.md"; fi; done
  # The read of the pipe now waits, as the caller. What it has open is looked at: the lock (fd 9 of
  # the helper) must not be among it, or the caller could hold the lock through /proc.
  for try in $(seq 1 200); do
    reader="$(pgrep -u "$CALLER_UID" -x head | head -1)"
    if [ -n "$reader" ]; then
      helper="$(pgrep -f "bash $HELPER put t" | head -1)"
      echo "reader-fds: $(ls /proc/"$reader"/fd 2>/dev/null | tr '\n' ' ')" > "$T/fds"
      echo "reader-has-lock: $(find /proc/"$reader"/fd -lname "$BASE/lock" 2>/dev/null | wc -l)" >> "$T/fds"
      echo "helper-has-lock: $(find /proc/"$helper"/fd -lname "$BASE/lock" 2>/dev/null | wc -l)" >> "$T/fds"
      break
    fi
    sleep 0.05
  done ) &
swapper=$!
start=$(date +%s); said="$(notes put t "$T/s" 2>&1)"; code=$?; took=$(( $(date +%s) - start ))
kill "$swapper" 2>/dev/null; wait "$swapper" 2>/dev/null
if [ -p "$T/s/zz-last.md" ] && [ "$code" != 0 ]; then
  grep -q "zz-last.md could not be read" <<<"$said" && [ "$took" -ge 9 ] && [ "$took" -lt 40 ] && [ ! -e "$ROOT/t" ] && pass "a file swapped for a pipe after the listing: given up after ${took}s, and the set refused" || fail "pipe swap: exit $code after ${took}s, '$said'"
  if [ -f "$T/fds" ]; then
    grep -q "^reader-has-lock: 0$" "$T/fds" && grep -q "^helper-has-lock: 1$" "$T/fds" && ! grep -q "^reader-fds:.* 9 " "$T/fds" && pass "what runs as the caller does not have the lock open (the helper does)" || fail "the lock was inherited: $(tr '\n' ';' < "$T/fds")"
  else
    fail "the reader was not seen, so whether it has the lock open is not known"
  fi
else
  echo "  skip the pipe swap landed too late on this machine (the set was put before it)"; notes remove t; rm -f "$T/pipe"
fi
# The lock is root's alone: the caller cannot open it, so cannot lock it and hold every run up.
[ "$(stat -c '%U %a' "$BASE/lock")" = "root 600" ] && ! setpriv --reuid="$CALLER_UID" --regid="$CALLER_GID" --clear-groups sh -c "exec 8<'$BASE/lock'" 2>/dev/null && pass "the lock is root's, 0600, and the caller cannot open it" || fail "the lock: $(stat -c '%U %a' "$BASE/lock")"
# A file swapped for a link to a root-only file: read as the caller, so its content never arrives.
stage; echo "TOP SECRET" > "$T/rootonly"; chmod 600 "$T/rootonly"; for i in $(seq 1 150); do echo x > "$T/s/a$i.md"; done; echo x > "$T/s/zz-last.md"; own
( while [ ! -L "$T/s/zz-last.md" ]; do if [ -d "$WORK" ] && [ -n "$(find "$WORK" -name listing 2>/dev/null)" ]; then ln -sf "$T/rootonly" "$T/s/zz-last.md"; fi; done ) &
swapper=$!
notes put t "$T/s" >/dev/null 2>&1; kill "$swapper" 2>/dev/null; wait "$swapper" 2>/dev/null
! grep -rqs "TOP SECRET" "$ROOT" "$WORK" && pass "a file swapped for a link to a root-only file: its content is not in the notes folder" || fail "root-only content reached the notes folder"
notes remove t 2>/dev/null

echo "limits and leftovers"
stage
for i in $(seq 1 60); do notes put "s$i" "$T/s" >/dev/null 2>&1 || fail "set $i of 60 was refused"; done
said="$(notes put s61 "$T/s" 2>&1)"; [ $? != 0 ] && grep -q "at most 60 sets" <<<"$said" && [ ! -e "$ROOT/s61" ] && pass "a 61st set is refused" || fail "61st set: '$said'"
notes put s1 "$T/s" >/dev/null 2>&1 && pass "with 60 sets, one of them can still be replaced" || fail "replacing one of 60 sets"
[ "$(notes list | wc -l)" = 60 ] && pass "list names the 60 sets" || fail "list: $(notes list | wc -l)"
for i in $(seq 1 60); do notes remove "s$i"; done
mkdir -p "$WORK/new-left/set" "$WORK/gone-left"; echo x > "$WORK/new-left/set/a.md"
notes put t "$T/s" >/dev/null 2>&1
[ -z "$(find "$WORK" -mindepth 1)" ] && pass "what an interrupted run left in the work folder is removed" || fail "leftovers stayed: $(find "$WORK" -mindepth 1 -maxdepth 1 | tr '\n' ' ')"
# Killed between taking the old set out and putting the new one in: the old set is in the work
# folder under its name, and nothing is in its place. The next run, of anything, puts it back.
mv "$ROOT/t" "$WORK/old.t"
notes remove some-other-set && [ "$(cat "$ROOT/t/good.md" 2>/dev/null)" = "# Good" ] && [ ! -e "$WORK/old.t" ] && pass "a set taken out by a run that was killed before its replacement arrived is put back by the next run" || fail "the set was lost: $(find "$ROOT" "$WORK" -mindepth 1 | tr '\n' ' ')"
# Killed after the new set arrived: the old copy is only deleted.
mkdir -p "$WORK/old.t"; echo "# Old" > "$WORK/old.t/good.md"
notes remove some-other-set && [ "$(cat "$ROOT/t/good.md")" = "# Good" ] && [ ! -e "$WORK/old.t" ] && pass "an old copy whose replacement is in place is deleted, not put back over it" || fail "an old copy replaced the new set"
# A name in the work folder that is no set's name is never moved into the notes folder.
mkdir -p "$WORK/old...x" "$WORK/old.Bad Name"; notes remove some-other-set; [ "$(notes list)" = t ] && pass "a leftover that is not named like a set is not put in the notes folder" || fail "a badly named leftover became a set: $(notes list | tr '\n' ' ')"
# A set that is somehow a link is replaced, not followed.
notes remove t; mkdir "$T/target"; echo keep > "$T/target/keep.md"; ln -s "$T/target" "$ROOT/t"
notes put t "$T/s" >/dev/null 2>&1; [ -d "$ROOT/t" ] && [ ! -L "$ROOT/t" ] && [ -f "$T/target/keep.md" ] && [ ! -e "$T/target/good.md" ] && pass "a set that is a link is replaced, and what it pointed at is untouched" || fail "a link in the notes folder was followed"
notes remove t

echo "folders that are not root's own: the helper does nothing at all"
# The folder above belongs to the caller, as /opt/controlclaw does on some boxes. Whoever owns a
# folder can rename what is in it and put a link there; a helper that runs as root would follow it.
echo "do not touch" > "$T/victim"; chmod 600 "$T/victim"; mkdir -p "$T/tree/victimdir"; echo keep > "$T/tree/victimdir/keep"
victims() { cat "$T/victim" 2>/dev/null; find "$T/tree" -printf '%P %y\n' | sort; }
intact="$(victims)"
# nothing_done <name> <words in the message>: put, remove and list each refuse, and the victims and the folders are as they were.
nothing_done() {
  local name="$1" words="$2" ok=1 said code state
  state="$(find "$BASE" "$BASE.aside" -printf '%p %y %u %m %l\n' 2>/dev/null | sort)"
  stage
  for args in "put t $T/s" "put victimdir $T/s" "remove victimdir" "remove x" "list"; do
    # shellcheck disable=SC2086
    said="$(notes $args 2>&1)"; code=$?
    [ "$code" = 70 ] && grep -q -- "$words" <<<"$said" || { ok=0; echo "       '$args': exit $code, '$said'"; }
  done
  [ "$(victims)" = "$intact" ] || { ok=0; echo "       a victim file or folder was changed"; }
  [ "$(find "$BASE" "$BASE.aside" -printf '%p %y %u %m %l\n' 2>/dev/null | sort)" = "$state" ] || { ok=0; echo "       the folders were changed"; }
  [ "$ok" = 1 ] && pass "$name" || fail "$name"
}
fresh; stage; notes put t "$T/s" >/dev/null; chown "$CALLER_UID" "$BASE"
nothing_done "the parent belongs to the caller" "does not belong to root"
fresh; chmod 0775 "$BASE"
nothing_done "the parent can be written by its group" "can be written by others"
fresh; chmod 0757 "$BASE"
nothing_done "the parent can be written by everyone" "can be written by others"
fresh; mv "$BASE" "$BASE.aside"; ln -s "$BASE.aside" "$BASE"
nothing_done "the parent is a link" "is not a folder"
fresh; ln -s "$T/victim" "$BASE/lock"
nothing_done "the lock is a link to a file of root's (it is not emptied)" "is not an ordinary file"
[ "$(cat "$T/victim")" = "do not touch" ] || fail "the file the lock pointed at was emptied"
fresh; echo "do not touch" > "$T/hard"; ln "$T/hard" "$BASE/lock"
nothing_done "the lock is a second name of another file" "is not root's own file"
fresh; mkdir "$BASE/lock"
nothing_done "the lock is a folder" "is not an ordinary file"
fresh; ln -s "$T/tree" "$BASE/sets"
nothing_done "the notes folder is a link to another tree (nothing in that tree is deleted)" "is not a folder"
fresh; install -d -o "$CALLER_UID" -m 0755 "$BASE/sets"
nothing_done "the notes folder belongs to the caller" "does not belong to root"
fresh; ln -s "$T/tree" "$BASE/work"
nothing_done "the work folder is replaced by a link" "is not a folder"
fresh; install -d -o "$CALLER_UID" -m 0700 "$BASE/work"; setpriv --reuid="$CALLER_UID" --regid="$CALLER_GID" --clear-groups ln -s "$T/tree/victimdir" "$BASE/work/old.victimdir"
nothing_done "the work folder is replaced by one of the caller's, with a link waiting in it" "does not belong to root"
fresh; install -d -m 0777 "$BASE/work"
nothing_done "the work folder can be written by everyone" "can be written by others"
fresh

echo "an agent with an encrypted disk: the notes are in the encrypted part, or nowhere"
# The marker says this box keeps its notes in the encrypted part. The folder is then the notes
# folder only while that part is mounted on it.
mkdir -p /etc/controlclaw; fresh; echo marker > "$MARK"; stage
ok=1
for args in "put t $T/s" "remove t" "list"; do
  # shellcheck disable=SC2086
  said="$(notes $args 2>&1)"; code=$?
  [ "$code" = 69 ] && grep -q "disk is locked" <<<"$said" || { ok=0; echo "       '$args': exit $code, '$said'"; }
done
[ "$ok" = 1 ] && [ -z "$(find "$BASE" -mindepth 1)" ] && pass "the disk is locked (the folder is not a mount): put, remove and list refuse, and nothing is written on the plain disk" || fail "locked disk: $(find "$BASE" -mindepth 1 | tr '\n' ' ')"
if mkdir -p "$T/inside" && chmod 755 "$T/inside" && mount --bind "$T/inside" "$BASE" 2>/dev/null; then
  notes put t "$T/s" >/dev/null 2>&1 && [ -f "$T/inside/sets/t/good.md" ] && [ "$(notes list)" = t ] && pass "the disk is open (the folder is the mount): the set is written inside it" || fail "open disk: the set was not put"
  # While a run holds the lock, which is a file inside the mount, the mount cannot be taken away
  # under it: so a disk cannot be locked between the helper's check and its writes.
  ( exec 9>>"$BASE/lock"; flock 9; sleep 3 ) & holder=$!; sleep 0.5
  ! umount "$BASE" 2>/dev/null && pass "the mount cannot be taken away while the lock inside it is held" || { fail "the mount went away under a held lock"; mount --bind "$T/inside" "$BASE"; }
  wait "$holder"
  umount "$BASE"
  [ -z "$(find "$BASE" -mindepth 1)" ] && [ -f "$T/inside/sets/t/good.md" ] && pass "with the mount gone again, the plain disk has nothing of the set" || fail "the plain disk has: $(find "$BASE" -mindepth 1 | tr '\n' ' ')"
  said="$(notes remove t 2>&1)"; [ $? = 69 ] && [ -f "$T/inside/sets/t/good.md" ] && pass "locked again: remove refuses, and the set inside is as it was" || fail "locked remove: '$said'"
  # The mounted folder has to be root's own too, like every folder in the path.
  mkdir "$T/theirs"; chown "$CALLER_UID" "$T/theirs"; mount --bind "$T/theirs" "$BASE"
  said="$(notes put t "$T/s" 2>&1)"; code=$?; umount "$BASE"
  [ "$code" = 70 ] && grep -q "does not belong to root" <<<"$said" && [ -z "$(find "$T/theirs" -mindepth 1)" ] && pass "a mounted folder that is not root's: refused, nothing written in it" || fail "caller-owned mount: exit $code, '$said'"
  mkdir "$T/open"; chmod 0777 "$T/open"; mount --bind "$T/open" "$BASE"
  said="$(notes put t "$T/s" 2>&1)"; code=$?; umount "$BASE"
  [ "$code" = 70 ] && grep -q "can be written by others" <<<"$said" && pass "a mounted folder others can write: refused" || fail "world-writable mount: exit $code, '$said'"
else
  echo "  skip mounting is not allowed here (run in the container this script starts, or on a box as root)"
fi
# No marker, and the container's image is there: still an agent with an encrypted disk.
rm -f "$MARK"; fresh; stage; mkdir -p /var/lib/controlclaw; : > /var/lib/controlclaw/secure.img
said="$(notes put t "$T/s" 2>&1)"; code=$?
[ "$code" = 69 ] && grep -q "disk is locked" <<<"$said" && [ -z "$(find "$BASE" -mindepth 1)" ] && pass "the marker is missing and the container's image is there: still refused, nothing on the plain disk" || fail "missing marker failed open: exit $code, '$said'"
rm -f /var/lib/controlclaw/secure.img; rmdir /var/lib/controlclaw 2>/dev/null
# A message is the reason and nothing after it.
said="$(notes put "Bad Name" "$T/s" 2>&1)"; [ "$said" = "cc-notes: a set's name is lowercase letters, digits and dashes" ] && pass "a refusal's message has no exit code in it" || fail "message: '$said'"
rm -f "$MARK"; fresh; stage
notes put t "$T/s" >/dev/null 2>&1 && [ -f "$ROOT/t/good.md" ] && pass "an agent whose disk is not encrypted (no marker, no image): the folder needs no mount" || fail "plain agent: the set was not put"
ln -s /nowhere "$MARK"; said="$(notes put t "$T/s" 2>&1)"; [ $? = 69 ] && pass "a marker that is a link still counts as a marker" || fail "link marker: '$said'"; rm -f "$MARK"
fresh

echo "nothing outside the notes folder"
rm -rf "$T/away" "$T/target" "$T/tree" "$T/victim" "$T/hard" "$T/inside" "$T/theirs" "$T/open"
after="$(outside)"
[ "$before" = "$after" ] && pass "no file outside the helper's folder and the test's own folder was made, changed or removed" || { fail "something outside changed:"; diff <(echo "$before") <(echo "$after") | head -10; }

[ "$fails" = 0 ] && echo "all passed" || { echo "$fails failed"; exit 1; }
