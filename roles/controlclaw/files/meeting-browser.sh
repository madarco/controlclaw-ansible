#!/bin/sh
# Starts the meeting browser (cc-meeting-browser.service), or with `signin` the window the owner
# signs in to Google in (cc-meeting-signin.service). vm-agent decides which profile a call uses by
# writing /opt/controlclaw/state/meeting-browser-signed before it starts the unit.
#
# Guest calls use a new profile under the unit's runtime directory, removed when the unit stops.
# Signed-in calls use /opt/controlclaw/state/meeting-profile: on the encrypted disk, outside the
# agent's home, in no backup. vm-agent removes it on sign-out and when the Google grant goes.
set -eu
umask 077
STATE=/opt/controlclaw/state
SIGNED="$STATE/meeting-profile"
CHROME=/usr/bin/google-chrome-stable
COMMON="--no-first-run --no-default-browser-check --disable-sync --disable-background-networking --password-store=basic"

if [ "${1:-}" = signin ]; then
  url=$(cat "$STATE/meeting-signin-url")
  case "$url" in
    https://accounts.google.com/*) ;;
    *) echo "meeting-browser: no sign-in page to open" >&2; exit 1 ;;
  esac
  mkdir -p "$SIGNED/Default"
  /usr/bin/python3 /opt/controlclaw/meeting-browser-preferences.py "$SIGNED/Default/Preferences"
  # No debugging port here: Google refuses sign-in in a browser started with one, and nothing on
  # the box can drive this window through Chrome while the owner types.
  # shellcheck disable=SC2086
  exec "$CHROME" --user-data-dir="$SIGNED" $COMMON --window-position=0,0 --window-size=1280,800 --app="$url"
fi

profile="$XDG_RUNTIME_DIR/cc-meetings/profile"
if [ -e "$STATE/meeting-browser-signed" ] && [ -d "$SIGNED" ]; then profile="$SIGNED"; fi
mkdir -p "$profile/Default"
/usr/bin/python3 /opt/controlclaw/meeting-browser-preferences.py "$profile/Default/Preferences"
# shellcheck disable=SC2086
exec "$CHROME" --user-data-dir="$profile" --remote-debugging-address=127.0.0.1 --remote-debugging-port=9223 $COMMON --force-webrtc-ip-handling-policy=disable_non_proxied_udp --autoplay-policy=no-user-gesture-required about:blank
