#!/usr/bin/env bash
set -euo pipefail

# The agent's live browser. One headful Chrome on a virtual display, mirrored over VNC so the
# customer can watch and drive it from the console, with CDP open on loopback so OpenClaw attaches
# to THIS window instead of spawning an invisible one of its own.
#
# Everything here binds 127.0.0.1. Caddy is the only way in (templates/Caddyfile.j2), and it asks
# the vm-agent (/__cc/verify-view) before it proxies a single frame.

export DISPLAY=:1
export HOME=/home/controlclaw
export XDG_CONFIG_HOME="${HOME}/.config"
export XDG_CACHE_HOME="${HOME}/.cache"

CDP_PORT="${CONTROLCLAW_BROWSER_CDP_PORT:-9222}"
VNC_PORT="${CONTROLCLAW_BROWSER_VNC_PORT:-5900}"
NOVNC_PORT="${CONTROLCLAW_BROWSER_NOVNC_PORT:-6080}"

# One geometry for both Xvfb and the Chrome window, or the desktop gets a border of dead space.
SCREEN_GEOMETRY="${CONTROLCLAW_BROWSER_GEOMETRY:-1280x800}"
WINDOW_SIZE="${SCREEN_GEOMETRY/x/,}"

mkdir -p "${HOME}/.chrome" "${XDG_CONFIG_HOME}" "${XDG_CACHE_HOME}" "${HOME}/.vnc"

# Start Xvfb
Xvfb :1 -screen 0 "${SCREEN_GEOMETRY}x24" -ac -nolisten tcp &
sleep 2

# A window manager. Without one Chrome's dialogs, <select> popups and file pickers open unmapped
# or without focus, which looks like a frozen browser to whoever is watching.
openbox &

# Chrome binds CDP directly on ${CDP_PORT}. There used to be a socat hop from an offset internal
# port, which bought nothing: OpenClaw reads /json/version from ${CDP_PORT} and then dials the
# webSocketDebuggerUrl it finds there, which points at Chrome's own port anyway. One fewer
# process is also one fewer way for `wait -n` to take the whole unit down.
#
# --disable-quic: on a secured box the nftables ruleset redirects TCP only. Chrome tries QUIC on
# UDP/443 first, gets nothing back, and eats a timeout before falling back — once per navigation.
#
# THE SANDBOX IS ON. There is deliberately no --no-sandbox / --disable-setuid-sandbox here: this
# browser parses whatever page an LLM decides to open, as the user that owns the gateway token,
# the customer's saved logins and the cc-install-ca sudo rule, so a renderer bug must not be a
# box compromise. The role installs Chrome's own AppArmor profile (Ubuntu 24.04 refuses
# unprivileged user namespaces without one) and asserts the setuid helper is intact, and
# verify_sandbox below refuses to serve an unsandboxed browser.
google-chrome-stable \
  --remote-debugging-address=127.0.0.1 \
  --remote-debugging-port=${CDP_PORT} \
  --user-data-dir=${HOME}/.chrome \
  --window-position=0,0 \
  --window-size=${WINDOW_SIZE} \
  --no-first-run \
  --no-default-browser-check \
  --disable-dev-shm-usage \
  --disable-background-networking \
  --disable-features=TranslateUI,DnsOverHttps \
  --disable-breakpad \
  --disable-crash-reporter \
  --metrics-recording-only \
  --disable-quic \
  about:blank &
CHROME_PID=$!

# Wait for Chrome to start
for _ in $(seq 1 50); do
  if curl -sS --max-time 1 "http://127.0.0.1:${CDP_PORT}/json/version" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

# Refuse to put an unsandboxed browser on the screen. Two independent signals, both read from
# the kernel rather than from Chrome's own claims:
#
#   * a renderer sits in its own user namespace, different from the browser process's (layer 1,
#     the namespace sandbox), or
#   * a renderer reports Seccomp: 2, a seccomp-bpf filter (layer 2).
#
# Either one means the renderer is confined. Neither means --no-sandbox has crept back, or the
# AppArmor profile is missing AND the setuid helper lost its bit, and this box would be running
# attacker-chosen content unconfined as the user that owns the gateway token.
verify_sandbox() {
  local browser_ns renderer_pid renderer_ns seccomp
  browser_ns="$(readlink "/proc/${CHROME_PID}/ns/user" 2>/dev/null || true)"
  for _ in $(seq 1 60); do
    renderer_pid="$(pgrep -f -- '--type=renderer' | head -1 || true)"
    [ -n "${renderer_pid}" ] && break
    sleep 0.5
  done
  if [ -z "${renderer_pid}" ]; then
    echo "browser-stream: no renderer appeared; cannot verify the sandbox" >&2
    return 1
  fi
  renderer_ns="$(readlink "/proc/${renderer_pid}/ns/user" 2>/dev/null || true)"
  seccomp="$(awk '/^Seccomp:/ {print $2}' "/proc/${renderer_pid}/status" 2>/dev/null || true)"
  if [ -n "${renderer_ns}" ] && [ "${renderer_ns}" != "${browser_ns}" ]; then
    echo "browser-stream: renderer sandboxed (user namespace ${renderer_ns})"
    return 0
  fi
  if [ "${seccomp}" = "2" ]; then
    echo "browser-stream: renderer sandboxed (seccomp-bpf)"
    return 0
  fi
  echo "browser-stream: RENDERER IS NOT SANDBOXED (ns=${renderer_ns:-none} seccomp=${seccomp:-none}) — refusing to start" >&2
  return 1
}

if ! verify_sandbox; then
  kill "${CHROME_PID}" 2>/dev/null || true
  exit 1
fi

# x11vnc and websockify stay unauthenticated on loopback on purpose: the session check belongs to
# Caddy + the vm-agent, which already knows who the customer is. Nothing off-box can reach either.
x11vnc -display :1 -rfbport "${VNC_PORT}" -shared -forever -nopw -localhost &

websockify --web /usr/share/novnc/ 127.0.0.1:"${NOVNC_PORT}" "localhost:${VNC_PORT}" &

# Wait for any process to exit
wait -n
