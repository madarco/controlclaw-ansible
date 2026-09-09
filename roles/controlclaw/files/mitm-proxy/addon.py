"""
ControlClaw egress proxy — mitmproxy addon.

Implements the security-critical core of the two-box architecture
(docs/mitm/plans/mitm-box-security-rollout.md):

  1. Per-tenant egress *rules* (allow / block / require_permission), priority-ordered.
  2. Domain-scoped *credential swap*: the agent box only ever holds `__PLACEHOLDER`s;
     this proxy injects the real secret, and ONLY on requests whose post-TLS host
     matches the credential's match_domain (so a leaked placeholder can't exfiltrate
     a secret off-domain).
  3. Metadata-only traffic logging: one JSONL record per request (host, method,
     query-stripped path, effect, rule, status, timing, placeholder names). No header
     values, bodies or query strings are ever logged. The mitm-agent ships the file to
     ControlClaw (`POST /api/vm-agent/activity`); see MITM_LOG_FILE / MITM_LOG_MAX_BYTES.

v1 loads rules/credentials from JSON files (hot-reloaded on mtime change). On real
boxes these come from the box-key-decrypted store (later parts). Tenant identity is
resolved by source for now; mTLS client-cert identity is a later part.

Dev-only escape hatches: any MITM_DEV_* flag makes the addon refuse to start unless
MITM_ALLOW_DEV_FLAGS=1 (set only by the smoke-test compose files). The production systemd
unit pins every MITM_DEV_* flag to 0.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any

import logging

from mitmproxy import http

try:  # raw-TCP passthrough layer (used by next_layer); guarded so a version skew can't break import
    from mitmproxy.proxy import layers as _proxy_layers
except Exception:  # pragma: no cover
    _proxy_layers = None

log = logging.getLogger("mitm")


# ----- config loading (hot-reloadable) --------------------------------------

RULES_PATH = os.environ.get("MITM_RULES_PATH", "/config/rules.json")
CREDS_PATH = os.environ.get("MITM_CREDENTIALS_PATH", "/config/credentials.json")
# Per-VM identity map [{private_ip, vm_id}] — synced from /api/vm-agent/identities (P8.1). Lets the
# proxy attribute a connection to a vm_id by source IP (redsocks connects from each box's private
# NIC), so VM-scoped rules/credentials apply and logs are attributed per VM.
IDENTITIES_PATH = os.environ.get("MITM_IDENTITIES_PATH", "/config/identities.json")
GRANTS_PATH = os.environ.get("MITM_GRANTS_PATH", "/config/grants.json")
PENDING_PATH = os.environ.get("MITM_PENDING_PATH", "/config/pending.jsonl")
PERMISSION_TTL = int(os.environ.get("MITM_PERMISSION_TTL", "300"))
LOG_PATH = os.environ.get("MITM_LOG_FILE", "")  # append JSONL here if set
# Rotate the traffic log once it passes this size: the live file is renamed to `<path>.1` (the
# previous `.1` is dropped). The proxy is the single writer, so disk stays bounded even when the
# mitm-agent shipper is down; the shipper follows the rename by inode.
LOG_MAX_BYTES = int(os.environ.get("MITM_LOG_MAX_BYTES", str(8 * 1024 * 1024)))
TENANT = os.environ.get("MITM_TENANT", "unknown")
# The ControlClaw control-plane host (e.g. controlclaw.com). Traffic to it is PASSED THROUGH
# without interception (real public TLS), so the JWT control channel never depends on this proxy's
# CA and the proxy can't MITM its own control plane. Matched by TLS SNI — robust even when the
# client reaches us via a transparent redirect (redsocks CONNECT-to-IP), where the CONNECT
# authority is an IP, not the hostname. See docs/security-design.md.
CONTROL_PLANE_HOST = os.environ.get("MITM_CONTROL_PLANE_HOST", "").strip().lower()

# Dev escape hatches. Every MITM_DEV_* flag is refused unless MITM_ALLOW_DEV_FLAGS=1, which only
# the smoke-test compose files set; the production systemd unit pins them all to 0. This makes
# "dev flags are off on secured boxes" a property of the proxy binary, not of a checklist.
_DEV_FLAGS = ("MITM_DEV_LOG_SECRETS", "MITM_DEV_ALLOW_PLAINTEXT_STORE",
              "MITM_DEV_INSECURE_UPSTREAM", "MITM_DEV_ALLOW_DIRECT_EGRESS")
_dev_set = [k for k in _DEV_FLAGS if os.environ.get(k, "") not in ("", "0")]
if _dev_set and os.environ.get("MITM_ALLOW_DEV_FLAGS") != "1":
    raise RuntimeError(f"refusing to start with dev flags set outside a smoke test: {_dev_set}")

DEFAULT_LOCATIONS = ["header:authorization", "header:x-api-key", "header:private-token"]
BLOCK_STATUS = 403
PERMISSION_STATUS = 451


class _Cache:
    def __init__(self, path: str):
        self.path = path
        self.mtime = -1.0
        self.data: list[dict[str, Any]] = []

    def get(self) -> list[dict[str, Any]]:
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return self.data
        if mtime != self.mtime:
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    self.data = json.load(fh)
                self.mtime = mtime
                log.info(f"[mitm] reloaded {self.path} ({len(self.data)} entries)")
            except (OSError, json.JSONDecodeError) as exc:
                log.warning(f"[mitm] failed to load {self.path}: {exc}")
        return self.data


_rules = _Cache(RULES_PATH)
_creds = _Cache(CREDS_PATH)
_identities = _Cache(IDENTITIES_PATH)


class _DictCache:
    """Like _Cache but for a JSON object (grants map), hot-reloaded on mtime."""

    def __init__(self, path: str):
        self.path = path
        self.mtime = -1.0
        self.data: dict[str, Any] = {}

    def get(self) -> dict[str, Any]:
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return self.data
        if mtime != self.mtime:
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    self.data = json.load(fh)
                self.mtime = mtime
            except (OSError, json.JSONDecodeError):
                self.data = {}
        return self.data


_grants = _DictCache(GRANTS_PATH)
# permission_ids already recorded as pending this process — avoid duplicate prompts.
_pending_seen: set[str] = set()


def permission_scope(method: str, host: str, path: str) -> str:
    """Stable scope key (query stripped) — a grant unblocks exactly this triple."""
    return f"{method} {host}{path.split('?', 1)[0]}"


def permission_id_for(scope: str) -> str:
    return "perm_" + hashlib.sha256(scope.encode("utf-8")).hexdigest()[:32]


def grant_active(permission_id: str) -> bool:
    grant = _grants.get().get(permission_id)
    if not grant:
        return False
    try:
        return float(grant.get("expires_at", 0)) > time.time()
    except (TypeError, ValueError):
        return False


def record_pending(permission_id: str, record: dict[str, Any]) -> None:
    if permission_id in _pending_seen:
        return
    _pending_seen.add(permission_id)
    try:
        with open(PENDING_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as exc:
        log.warning(f"[mitm] pending write failed: {exc}")


# ----- helpers --------------------------------------------------------------

def host_matches(pattern: str, host: str) -> bool:
    """Exact, full-wildcard (*), or suffix-wildcard (*.example.com) host match."""
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host.lower() == pattern.lower()


def _peer_ip(peername) -> str:
    try:
        return peername[0] or ""
    except Exception:
        return ""


def vm_id_for_ip(ip: str) -> str | None:
    """Resolve a connection's source IP to a vm_id via the synced identity map (None if unknown)."""
    if not ip:
        return None
    for ent in _identities.get():
        if ent.get("private_ip") == ip:
            return ent.get("vm_id")
    return None


def flow_vm_id(flow) -> str | None:
    """vm_id of the client behind an HTTP/TCP flow (by source IP)."""
    try:
        return vm_id_for_ip(_peer_ip(flow.client_conn.peername))
    except Exception:
        return None


def ctx_vm_id(ctx) -> str | None:
    """vm_id of the client behind a connection context (tls_clienthello / next_layer)."""
    try:
        return vm_id_for_ip(_peer_ip(ctx.client.peername))
    except Exception:
        return None


def _rule_applies_to_vm(rule: dict[str, Any], vm_id: str | None) -> bool:
    """A rule with no `vm_id` is org-wide (applies to all); a vm-scoped rule applies only to that VM."""
    rv = rule.get("vm_id")
    return rv is None or rv == vm_id


def match_rule(host: str, method: str, path: str, vm_id: str | None = None) -> dict[str, Any] | None:
    """First matching rule by ascending priority; None means default-allow. Honors `vm_id`:
    org-wide rules (no vm_id) always apply; vm-scoped rules apply only to the resolved VM."""
    rules = sorted(_rules.get(), key=lambda r: r.get("priority", 1000))
    for rule in rules:
        if not _rule_applies_to_vm(rule, vm_id):
            continue
        if not host_matches(rule.get("match_domain", "*"), host):
            continue
        rm = rule.get("match_method")
        if rm and rm.upper() != method.upper():
            continue
        mp = rule.get("match_path")
        if mp and mp not in path:
            continue
        return rule
    return None


def credentials_for(host: str, vm_id: str | None = None) -> list[dict[str, Any]]:
    """Credentials matching `host`, vm-scoped with ORG FALLBACK: a credential with no `vm_id` is
    org-wide; one with a `vm_id` applies only to that VM and OVERRIDES the org-wide credential for
    the same placeholder. So per-VM secrets take precedence, and VMs without a specific override
    still get the org credential."""
    by_placeholder: dict[str, dict[str, Any]] = {}
    for c in _creds.get():
        if not host_matches(c.get("match_domain", ""), host):
            continue
        cv = c.get("vm_id")
        if cv is not None and cv != vm_id:
            continue  # a different VM's scoped credential — not for this connection
        ph = c.get("placeholder") or ""
        # vm-scoped (cv == vm_id) overrides an org-wide (cv is None) entry for the same placeholder.
        existing = by_placeholder.get(ph)
        if existing is None or (existing.get("vm_id") is None and cv is not None):
            by_placeholder[ph] = c
    return list(by_placeholder.values())


def tunnel_match(host: str, port: int | None, vm_id: str | None = None) -> dict[str, Any] | None:
    """A `tunnel` (uninspected) rule matching this destination, or None.

    TLS destinations match by SNI/host (any port). Raw-TCP destinations have no SNI, so a rule may
    pin a `match_port` (matched against the connection's port). The user opts into each tunnel and is
    warned it bypasses inspection + credential swap; the box still redirects ALL TCP here, so a
    destination NOT covered by a tunnel rule (and not HTTP/TLS) is dropped (see `tcp_start`).
    """
    if not host and port is None:
        return None
    for rule in _rules.get():
        if rule.get("effect") != "tunnel":
            continue
        if not _rule_applies_to_vm(rule, vm_id):
            continue
        if host and not host_matches(rule.get("match_domain", ""), host):
            continue
        mp = rule.get("match_port")
        if mp is not None and port is not None and int(mp) != int(port):
            continue
        return rule
    return None


def _server_addr(ctx) -> tuple[str, int | None]:
    """(host_or_ip, port) of the upstream for this connection, best-effort."""
    try:
        addr = ctx.server.address
        return (addr[0] or ""), addr[1]
    except Exception:
        return "", None


def _secret_value(cred: dict[str, Any]) -> str | None:
    """Resolve the real secret from the credentials config.

    By design the proxy is the ONE place secrets are plaintext at runtime (it must see
    them to inject them; there is no TEE — the guarantee is containment + detection). On
    real boxes the mitm-agent decrypts the box-key/master-password store and writes this
    config to a RAM-only tmpfs; ControlClaw and the box disk only ever hold ciphertext.
    The proxy therefore trusts `secret` here directly — the security boundary is WHERE the
    file lives (agent-written tmpfs) and that it came from the encrypted store, enforced at
    provisioning, not in proxy code.
    """
    return cred.get("secret")


# ----- swap -----------------------------------------------------------------

def apply_swaps(flow: http.HTTPFlow, vm_id: str | None = None) -> list[tuple[str, str]]:
    """Replace placeholders with real secrets, domain-scoped (+ vm-scoped with org fallback).
    Returns [(secret, placeholder)] pairs applied, for later log redaction."""
    host = flow.request.pretty_host
    applied: list[tuple[str, str]] = []

    for cred in credentials_for(host, vm_id):
        placeholder = cred.get("placeholder")
        secret = _secret_value(cred)
        if not placeholder or not secret:
            continue
        locations = cred.get("locations") or DEFAULT_LOCATIONS
        hit = False

        for loc in locations:
            if loc.startswith("header:"):
                name = loc.split(":", 1)[1]
                for hname in list(flow.request.headers.keys()):
                    if hname.lower() == name.lower():
                        val = flow.request.headers[hname]
                        if placeholder in val:
                            flow.request.headers[hname] = val.replace(placeholder, secret)
                            hit = True
            elif loc == "query":
                for k in list(flow.request.query.keys()):
                    if placeholder in flow.request.query[k]:
                        flow.request.query[k] = flow.request.query[k].replace(placeholder, secret)
                        hit = True
            elif loc == "body":
                try:
                    text = flow.request.get_text(strict=False) or ""
                except ValueError:
                    text = ""
                if placeholder in text:
                    flow.request.set_text(text.replace(placeholder, secret))
                    hit = True

        if hit:
            applied.append((secret, placeholder))
            log.info(f"[mitm] swapped {placeholder} for host={host} (tenant={TENANT})")

    return applied


def _log(record: dict[str, Any]) -> None:
    """Append one traffic record (JSONL). Rotates the file by size first, see LOG_MAX_BYTES."""
    line = json.dumps(record, ensure_ascii=False)
    log.info(f"[mitm] {line}")
    if LOG_PATH:
        try:
            try:
                if os.path.getsize(LOG_PATH) >= LOG_MAX_BYTES:
                    os.replace(LOG_PATH, LOG_PATH + ".1")
            except FileNotFoundError:
                pass
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            log.warning(f"[mitm] log write failed: {exc}")


def _base_record(flow, vm_id: str | None) -> dict[str, Any]:
    """Fields every traffic record carries. `flow_id` is mitmproxy's per-flow uuid: the shipper's
    dedupe key, so an at-least-once upload never double-counts a request."""
    return {"flow_id": flow.id, "ts": time.time(), "tenant": TENANT, "vm_id": vm_id}


def _http_record(flow: http.HTTPFlow, effect: str) -> dict[str, Any]:
    """One record per HTTP request. `path` is query-stripped so a credential swapped into a query
    string can never end up in a log line."""
    rec = _base_record(flow, flow.metadata.get("cc_vm_id"))
    rec.update({
        "host": flow.request.pretty_host, "method": flow.request.method,
        "path": flow.request.path.split("?", 1)[0], "effect": effect,
        "rule": flow.metadata.get("cc_rule"),
    })
    return rec


def _log_once(flow: http.HTTPFlow, rec: dict[str, Any]) -> None:
    """mitmproxy can fire both `response` and `error` for one flow (e.g. the client goes away
    while the response is being written). Log each HTTP flow exactly once."""
    if flow.metadata.get("cc_logged"):
        return
    flow.metadata["cc_logged"] = True
    _log(rec)


# ----- hooks ----------------------------------------------------------------

def tls_clienthello(data) -> None:
    """Pass a connection through untouched (no TLS interception), matched by SNI: the control-plane
    host (so the JWT channel is never MITM'd) OR an opt-in `tunnel` rule (uninspected egress).

    Keys off the TLS ClientHello SNI rather than the CONNECT authority, so it works for the explicit
    proxy (CONNECT-by-host) AND transparent redsocks (CONNECT-by-IP). Defensive: a raised exception
    here would stall the handshake, so a match error never takes down an interceptable connection.
    """
    try:
        sni = (getattr(getattr(data, "client_hello", None), "sni", None) or "").lower()
        if not sni:
            return
        ctx = getattr(data, "context", None)
        _, port = _server_addr(ctx)
        if (CONTROL_PLANE_HOST and host_matches(CONTROL_PLANE_HOST, sni)) or tunnel_match(
            sni, port, ctx_vm_id(ctx)
        ):
            data.ignore_connection = True
    except Exception as exc:  # noqa: BLE001 — never break interception over a match error
        log.warning(f"[mitm] tls_clienthello passthrough check failed: {exc}")


def next_layer(data) -> None:
    """Raw-TCP (non-TLS) handling for the redirect-ALL model. TLS is handled by tls_clienthello.

    - A raw connection to a `tunnel` destination (by IP:port) is passed through uninspected.
    - Everything else non-TLS falls through to mitmproxy's default → a TCP flow → dropped in
      `tcp_start` (HTTP/TLS are detected by mitmproxy and intercepted as usual).
    Fully guarded: any error leaves mitmproxy's default layer selection untouched.
    """
    if _proxy_layers is None:
        return
    try:
        ctx = getattr(data, "context", None)
        host, port = _server_addr(ctx)
        peeked = b""
        try:
            peeked = bytes(data.data_client())
        except Exception:
            peeked = b""
        is_tls = len(peeked) >= 1 and peeked[0] == 0x16  # TLS handshake record
        if not is_tls and tunnel_match(host, port, ctx_vm_id(ctx)) is not None:
            data.layer = _proxy_layers.TCPLayer(ctx, ignore=True)
    except Exception as exc:  # noqa: BLE001
        log.warning(f"[mitm] next_layer passthrough check failed: {exc}")


def tcp_start(flow) -> None:
    """Central drop: any RAW TCP flow that reaches interception is non-HTTP/TLS and not an
    allowlisted tunnel (those are passed through in next_layer/tls_clienthello and never become a
    TCP flow). Since the box redirects ALL TCP here, this is the "drop everything not allowed" point.
    """
    try:
        host, port = "", None
        addr = getattr(getattr(flow, "server_conn", None), "address", None)
        if addr:
            host, port = addr[0] or "", addr[1]
        rec = _base_record(flow, flow_vm_id(flow))
        rec.update({"host": host, "port": port, "effect": "drop"})
        _log(rec)
        flow.kill()
    except Exception as exc:  # noqa: BLE001
        log.warning(f"[mitm] tcp_start drop failed: {exc}")


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    method = flow.request.method
    path = flow.request.path
    vm_id = flow_vm_id(flow)  # which VM (by source IP) this request belongs to; None if unknown
    flow.metadata["cc_vm_id"] = vm_id

    rule = match_rule(host, method, path, vm_id)
    effect = (rule or {}).get("effect", "allow")
    flow.metadata["cc_effect"] = effect
    flow.metadata["cc_rule"] = (rule or {}).get("name") or (rule or {}).get("match_domain")

    if effect == "tunnel":
        # A tunnel destination should have been passed through *before* the HTTP layer
        # (tls_clienthello / next_layer). If we somehow reach here, let it through but NEVER swap
        # credentials into an uninspected-intent flow.
        _log_once(flow, _http_record(flow, "tunnel"))
        return

    if effect == "block":
        flow.response = http.Response.make(
            BLOCK_STATUS,
            json.dumps({"error": "blocked_by_policy", "host": host, "tenant": TENANT}),
            {"Content-Type": "application/json"},
        )
        rec = _http_record(flow, "block")
        rec["status"] = BLOCK_STATUS
        _log_once(flow, rec)
        return

    if effect == "require_permission":
        scope = permission_scope(method, host, path)
        pid = permission_id_for(scope)
        if grant_active(pid):
            # Human approved this exact scope and it hasn't expired — let it through (and swap).
            effect = "allow"
            flow.metadata["cc_effect"] = "allow"
            flow.metadata["cc_granted"] = pid
        else:
            record_pending(pid, {
                "ts": time.time(), "tenant": TENANT, "vm_id": vm_id, "permission_id": pid,
                "scope": scope, "host": host, "method": method, "path": path.split("?", 1)[0],
            })
            flow.response = http.Response.make(
                PERMISSION_STATUS,
                json.dumps({
                    "permission_id": pid, "reason": "require_permission",
                    "summary": scope, "expires_at": int(time.time()) + PERMISSION_TTL,
                }),
                {"Content-Type": "application/json"},
            )
            rec = _http_record(flow, "require_permission")
            rec.update({"permission_id": pid, "status": PERMISSION_STATUS})
            _log_once(flow, rec)
            return

    # allow -> swap credentials in (vm-scoped with org fallback). Logged once the upstream
    # answers (response) or fails (error), so the record carries the real status and timing.
    applied = apply_swaps(flow, vm_id)
    flow.metadata["cc_applied"] = applied
    if flow.metadata.get("cc_granted"):
        flow.metadata["cc_rule"] = flow.metadata.get("cc_rule") or "grant"


def _allow_record(flow: http.HTTPFlow) -> dict[str, Any]:
    rec = _http_record(flow, "allow")
    rec["swapped"] = [p for _, p in flow.metadata.get("cc_applied", [])]
    if flow.metadata.get("cc_granted"):
        rec["permission_id"] = flow.metadata["cc_granted"]
    req_raw = flow.request.raw_content
    rec["bytes_out"] = len(req_raw) if req_raw else 0
    return rec


def response(flow: http.HTTPFlow) -> None:
    if flow.metadata.get("cc_effect") not in (None, "allow"):
        return
    rec = _allow_record(flow)
    rec["status"] = flow.response.status_code
    res_raw = flow.response.raw_content
    rec["bytes_in"] = len(res_raw) if res_raw else 0
    start, end = flow.request.timestamp_start, flow.response.timestamp_end
    if start and end:
        rec["duration_ms"] = int((end - start) * 1000)
    _log_once(flow, rec)


def error(flow: http.HTTPFlow) -> None:
    """Allowed request that never got a response (upstream refused, TLS failed, client went away)."""
    if flow.metadata.get("cc_effect") not in (None, "allow"):
        return
    if not getattr(flow, "request", None):
        return
    rec = _allow_record(flow)
    rec["error"] = str(getattr(flow.error, "msg", "") or "upstream error")[:200]
    start = flow.request.timestamp_start
    end = getattr(flow.error, "timestamp", None)
    if start and end:
        rec["duration_ms"] = int((end - start) * 1000)
    _log_once(flow, rec)
