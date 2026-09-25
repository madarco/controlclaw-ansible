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
  4. Inline AI review (docs: apps/saas/docs/features/ai-firewall-review.md): an `allow` rule
     with `ai_review` asks the mitm-agent's local judge (MITM_AI_JUDGE_URL) before the request
     leaves. The judge can let it through, block it, or turn it into a permission request. A
     `require_permission` rule with `ai_review` and an `ai_policy` asks it to approve on a
     person's behalf; an approval writes a normal grant (`by: "ai"`). A judge that is off, slow
     or failing never changes the rule's decision.
  5. Included AI tokens (apps/saas/docs/features/included-ai-tokens.md): a credential with
     `allowed_models` is the plan's AI Gateway key. It is only swapped into requests for one of
     those models (plus the model list); anything else is answered here and never reaches the
     gateway. A 402 from the gateway is rewritten into plain words and classified on the traffic
     record (`included`): `used_up` is the organisation's own budget, `no_credit` is ControlClaw's
     gateway account with nothing left, and `ok` is a call that went through. The agent reports
     the last two to the control plane, which is how the console knows to pause and to un-pause.
  6. Residential exit (apps/saas/docs/features/residential-exit.md): a rule may carry
     `exit: "residential"`, which sends that destination out through the org's own upstream
     residential proxy instead of this box's address. Such a flow is RELAYED, not inspected — the
     client's own TLS bytes reach the site, so its handshake is the browser's real one — and it
     gets host-level logging and byte counts, no credential swap and no AI review. It never falls
     back to this box's IP: every failure closes the connection and logs why.

This addon requires `connection_strategy=lazy` (the firewall's systemd unit sets it). With
mitmproxy's default, `eager`, the destination is connected BEFORE any layer decision is made,
which for a residential flow both leaks a connection from this box's address to the very site the
customer is reaching from elsewhere and leaves the relay running over the wrong socket. The
residential path refuses to run rather than do either, and says so in the log.

v1 loads rules/credentials from JSON files (hot-reloaded on mtime change). On real
boxes these come from the box-key-decrypted store (later parts). Tenant identity is
resolved by source for now; mTLS client-cert identity is a later part.

Dev-only escape hatches: any MITM_DEV_* flag makes the addon refuse to start unless
MITM_ALLOW_DEV_FLAGS=1 (set only by the smoke-test compose files). The production systemd
unit pins every MITM_DEV_* flag to 0.
"""

from __future__ import annotations

import asyncio
import base64
import collections
import hashlib
import hmac
import json
import os
import re
import time
import urllib.request
from typing import Any

import logging

from mitmproxy import connection
from mitmproxy import http

try:  # raw-TCP passthrough layer (used by next_layer); guarded so a version skew can't break import
    from mitmproxy.proxy import layers as _proxy_layers
except Exception:  # pragma: no cover
    _proxy_layers = None

# The residential exit (docs/plans/residential-exit.md) needs four more pieces of mitmproxy's proxy
# core. Each is guarded the same way `_proxy_layers` is: a version skew must not stop the proxy
# starting, because the proxy is the org's only way out. What it must not do either is silently send
# a residential flow out of THIS box's IP, so `_residential_ready()` refuses every residential rule
# when any of these is missing and the flow is closed with a logged reason (`_ExitUnavailable`).
#
# `_upstream_proxy` is private (leading underscore) and the only one of the four that is. It is
# worth it: `HttpUpstreamProxy` already speaks CONNECT, already handles a TLS-wrapped proxy, and
# already fires `http_connect_upstream` so the credential can be attached per flow. The smoke test
# asserts the import resolves, so a mitmproxy bump breaks CI rather than a customer's exit IP.
# Two blocks, not one, and the split is the whole point: the first holds public modules that a
# mitmproxy release is not going to move, and it is what builds the layer that CLOSES a connection
# the exit cannot carry. If the second (private) block were in with it, a version skew would take
# the fail-closed path down with the feature, `_use_residential` would raise NameError into
# `next_layer`'s catch-all, mitmproxy's own choice would stand, and the flow would leave from this
# box's address — the exact thing this feature exists to prevent.
try:
    from mitmproxy.proxy import commands as _commands
    from mitmproxy.proxy import layer as _layer
    from mitmproxy.proxy import tunnel as _tunnel
    from mitmproxy.proxy.layers.tls import parse_client_hello
except Exception as _exc:  # pragma: no cover
    _commands = _layer = _tunnel = None
    parse_client_hello = None
    _CORE_IMPORT_ERROR: str | None = str(_exc)
else:
    _CORE_IMPORT_ERROR = None

try:
    from mitmproxy.proxy.layers.http import _upstream_proxy
except Exception as _exc:  # pragma: no cover
    _upstream_proxy = None
    _UPSTREAM_IMPORT_ERROR: str | None = str(_exc)
else:
    _UPSTREAM_IMPORT_ERROR = None

_RESIDENTIAL_IMPORT_ERROR = _CORE_IMPORT_ERROR or _UPSTREAM_IMPORT_ERROR

# Where a residential flow is sent when this proxy cannot even build the layer that would close it
# (both import blocks failed). RFC 6598 space that no agent box routes: mitmproxy terminates the
# TLS, fails to connect, and answers the client with an error. Nothing reaches the real
# destination and nothing leaves from this box's address towards it — which is the promise. The
# record written alongside says what happened.
BLACKHOLE_ADDR = ("192.0.2.1", 9)

log = logging.getLogger("mitm")


# ----- config loading (hot-reloadable) --------------------------------------

RULES_PATH = os.environ.get("MITM_RULES_PATH", "/config/rules.json")
CREDS_PATH = os.environ.get("MITM_CREDENTIALS_PATH", "/config/credentials.json")
# Per-VM identity map [{private_ip, vm_id}] — synced from /api/vm-agent/identities (P8.1). Lets the
# proxy attribute a connection to a vm_id by source IP (redsocks connects from each box's private
# NIC), so VM-scoped rules/credentials apply and logs are attributed per VM.
IDENTITIES_PATH = os.environ.get("MITM_IDENTITIES_PATH", "/config/identities.json")
GRANTS_PATH = os.environ.get("MITM_GRANTS_PATH", "/config/grants.json")
# Residential exit (apps/saas/docs/features/residential-exit.md): the org's upstream proxy, written
# by the mitm-agent from its encrypted store into the same tmpfs as the credentials. `{}` / a
# missing file means the org has no exit, which is the normal case.
EXIT_PATH = os.environ.get("MITM_EXIT_PATH", "/config/exit.json")
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
# The backup object store's endpoint (e.g. s3.eu-west-1.amazonaws.com). Passed through uninspected,
# the same way and for much the same reason as the control plane: an agent box uploads its own
# already-encrypted archive there with a presigned URL, so there is nothing here to inspect (the body
# is ciphertext), nothing to credential-swap (the signature is in the URL), and multi-gigabyte bodies
# through mitmproxy's logging would be pure cost. Scoped to this one host, and a built-in of the same
# shape as CONTROL_PLANE_HOST rather than a `tunnel` rule — so an organisation cannot widen it and a
# compromised control plane cannot point it elsewhere without an Ansible change.
# See apps/saas/docs/features/backups.md.
BACKUP_HOST = os.environ.get("MITM_BACKUP_HOST", "").strip().lower()

# The built-in uninspected destinations. A connection whose SNI matches one of these is passed
# through without TLS termination; anything else needs a rule.
PASSTHROUGH_HOSTS = tuple(h for h in (CONTROL_PLANE_HOST, BACKUP_HOST) if h)

# Tailscale, for the agent boxes their owner has put on their own tailnet
# (apps/saas/docs/features/tailscale.md). `tailscaled` reaches the coordination server
# (`controlplane.tailscale.com`), the login service (`login.tailscale.com`) and the DERP relays
# (`derpN.tailscale.com`) over TLS on 443, and none of it can be inspected: the payload is a Noise
# session and, on DERP, WireGuard inside it. There is nothing here to read and no credential to
# swap, so the connection is passed through the way the control plane's and the backup store's are.
#
# Two differences from those two, both deliberate:
#   * it is NOT an env var. The hosts are Tailscale's own and there is nothing for a deployment to
#     configure, so this cannot be pointed somewhere else without a change to this file;
#   * it is PER BOX. A box only gets it once its owner has joined it, which the ORG FIREWALL
#     records (not the control plane) and publishes in the identity map as `tailscale: true`. An
#     agent whose owner never asked for this cannot reach tailscale.com at all.
#
# UDP is a separate matter and is not opened: the box's provider firewall allows outbound UDP only
# to the firewall box, so direct WireGuard (41641) and STUN never leave and Tailscale falls back to
# DERP over 443. See the doc for what that means for the owner.
TAILSCALE_HOSTS = ("*.tailscale.com",)

# Dev escape hatches. Every MITM_DEV_* flag is refused unless MITM_ALLOW_DEV_FLAGS=1, which only
# the smoke-test compose files set; the production systemd unit pins them all to 0. This makes
# "dev flags are off on secured boxes" a property of the proxy binary, not of a checklist.
_DEV_FLAGS = ("MITM_DEV_LOG_SECRETS", "MITM_DEV_ALLOW_PLAINTEXT_STORE",
              "MITM_DEV_INSECURE_UPSTREAM", "MITM_DEV_ALLOW_DIRECT_EGRESS")
_dev_set = [k for k in _DEV_FLAGS if os.environ.get(k, "") not in ("", "0")]
if _dev_set and os.environ.get("MITM_ALLOW_DEV_FLAGS") != "1":
    raise RuntimeError(f"refusing to start with dev flags set outside a smoke test: {_dev_set}")

# Inline AI review: the mitm-agent's loopback judge. Empty disables the call entirely. The timeout
# bounds the latency a reviewed request can gain; past it the rule's own decision stands.
AI_JUDGE_URL = os.environ.get("MITM_AI_JUDGE_URL", "http://127.0.0.1:3101/judge").strip()
AI_JUDGE_TIMEOUT = float(os.environ.get("MITM_AI_JUDGE_TIMEOUT", "3"))
# What the judge sees of a request body: the start of a text body only, never binary.
AI_BODY_CHARS = 300
AI_RECENT = 20

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
    """Like _Cache but for a JSON object (grants map), hot-reloaded on mtime.

    `missing_is_empty` decides what a file that has gone away means. For grants it means "keep
    what we have": a grant is permission the user already gave, and a vanished file is far more
    likely to be a transient read error than a revocation. For the residential exit it is the
    opposite — the file IS the credential, and the obvious way to revoke one is to delete it, so
    holding the last-loaded upstream host and password indefinitely would be exactly wrong.
    """

    def __init__(self, path: str, missing_is_empty: bool = False):
        self.path = path
        self.mtime = -1.0
        self.data: dict[str, Any] = {}
        self.missing_is_empty = missing_is_empty

    def get(self) -> dict[str, Any]:
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            if self.missing_is_empty:
                self.mtime = -1.0
                self.data = {}
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
_exit = _DictCache(EXIT_PATH, missing_is_empty=True)
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


def tailscale_allowed(vm_id: str | None) -> bool:
    """True when the org firewall says THIS box is on its owner's tailnet (identity map flag)."""
    if not vm_id:
        return False
    for ent in _identities.get():
        if ent.get("vm_id") == vm_id:
            return ent.get("tailscale") is True
    return False


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


# ----- residential exit -------------------------------------------------------
#
# A rule may say where its traffic leaves from: this box (`exit` absent or "firewall", the default)
# or the org's upstream residential proxy (`exit: "residential"`). A residential flow is NEVER
# inspected: the proxy opens a CONNECT through the upstream and relays the client's own TLS bytes,
# so the site sees the agent browser's real handshake. That is the whole point — a re-originated
# TLS session would carry mitmproxy's Python fingerprint, which on a residential IP reads worse
# than a datacenter IP with a real Chrome one. It also means no credential swap and no AI review
# on these flows, and the console says so before a rule can be marked.
#
# Residential NEVER falls back to this box's own IP. Every failure closes the connection and logs
# one record; see `_ExitUnavailable` and `tcp_error`.

# Emit an interim usage record every this many bytes, so a long-lived connection (a websocket, a
# large download) is accounted for before it ends. Without it the monthly cap could be blown by a
# single flow that never closes, and a stream still running when the proxy restarts would vanish.
RESIDENTIAL_INTERIM_BYTES = 64 * 1024 * 1024


def exit_config() -> dict[str, Any]:
    cfg = _exit.get()
    return cfg if isinstance(cfg, dict) else {}


# `exit: residential` turns a rule into an uninspected relay, so it is only honoured on the two
# effects that already let traffic out. On a `block` or `require_permission` rule it would quietly
# undo the decision the rule exists to make — the console refuses to set it, and so does this, so a
# control plane that sent one anyway cannot disable the firewall with a field.
RESIDENTIAL_EFFECTS = ("allow", "tunnel")


# One warning per misconfigured rule, not one per connection: this is reached from `next_layer`
# and `tls_clienthello` on every connection the box makes, and a single bad rule would otherwise
# write two lines a request for as long as it exists.
_warned_rules: set[str] = set()


def _warn_once(key: str, message: str) -> None:
    if key in _warned_rules:
        return
    _warned_rules.add(key)
    log.warning(message)


def _connection_matches(rule: dict[str, Any], host: str, port: int | None, vm_id: str | None) -> bool:
    """Could this rule apply to this destination, judged from what a connection alone tells us?

    `match_path` and `match_method` cannot be evaluated here — there is no request yet — so a rule
    carrying one is treated as "might apply". That is the safe direction: it can only make the
    decision below more conservative, never less.
    """
    if not _rule_applies_to_vm(rule, vm_id):
        return False
    pattern = rule.get("match_domain", "")
    if _is_ip(host) and (pattern == "*" or pattern.startswith("*.")):
        # An IP is what we are left with when the destination has no name we could read. A
        # wildcard domain matching it would send a connection out by IP — which the provider
        # cannot route on and which throws away the whole point of resolving at the exit. A rule
        # meant for a raw address says that address.
        return False
    if not host_matches(pattern, host):
        return False
    mp = rule.get("match_port")
    if mp is not None and port is not None and int(mp) != int(port):
        return False
    return True


def residential_rule(host: str, port: int | None, vm_id: str | None = None) -> dict[str, Any] | None:
    """The rule sending this destination out through the upstream, or None.

    Precedence is the whole engine's, not this feature's: the rule that wins is the one
    `match_rule` would pick for this destination, and residential happens only if THAT rule is the
    residential one. Picking the best *residential* rule on its own was a way to walk past a
    higher-priority `block` — an org with `block *.facebook.com` at priority 10 and
    `allow *.com exit=residential` at 500 would have had facebook relayed out uninspected, with
    the block never consulted.

    Anything we cannot judge yet counts against relaying. A rule with a `match_path` might or
    might not apply to the request that follows, so if it outranks the residential rule the
    connection is intercepted and the per-request matcher decides — inspection is the safe answer
    when the answer is not knowable here.
    """
    if not host:
        return None
    candidates = [r for r in _rules.get() if _connection_matches(r, host, port, vm_id)]
    if not candidates:
        return None
    winner = sorted(candidates, key=lambda r: r.get("priority", 1000))[0]
    if winner.get("exit") != "residential":
        return None
    if winner.get("effect", "allow") not in RESIDENTIAL_EFFECTS:
        _warn_once(
            f"{winner.get('name')}:{winner.get('effect')}",
            f"[mitm] ignoring exit=residential on a {winner.get('effect')} rule ({winner.get('name')})",
        )
        return None
    return winner


def _residential_ready() -> tuple[dict[str, Any] | None, str | None]:
    """The upstream to use, or (None, why not). Every "why not" is a closed connection, by design."""
    if _CORE_IMPORT_ERROR is not None:
        # The scheme-specific one is checked in `_residential_stack`, where the scheme is known:
        # a SOCKS5 exit uses our own tunnel layer and keeps working when the private HTTP upstream
        # module moves, which is the reason the imports are split at all.
        return None, f"this firewall's proxy cannot chain upstream ({_CORE_IMPORT_ERROR})"
    cfg = exit_config()
    if not cfg.get("enabled"):
        return None, "no residential exit is configured"
    up = cfg.get("upstream")
    if not isinstance(up, dict) or not up.get("host") or not up.get("port"):
        return None, "the residential exit is not configured"
    if up.get("scheme") not in ("http", "https", "socks5"):
        return None, f"unsupported residential exit scheme {up.get('scheme')!r}"
    if cfg.get("sticky") and len(str(cfg.get("sticky_salt") or "")) < 32:
        # The salt is what makes a box's exit IP underivable off-box. Without it the session is a
        # function of the vm id alone, which the control plane knows — so this fails closed rather
        # than hand out a sticky IP anyone can work out.
        return None, "this firewall's sticky-session salt is missing"
    cap = cfg.get("cap_bytes")
    used = cfg.get("used_bytes") or 0
    if cap and used >= cap:
        return None, "this month's residential data cap is used up"
    return up, None


COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_PLACEHOLDER_RE = re.compile(r"\{(username|password|session|country|country_lc)\}")


def normalize_country(value: Any) -> str | None:
    """ISO 3166-1 alpha-2, uppercase, or None. The one shape every part of the feature agrees on."""
    clean = value.strip().upper() if isinstance(value, str) else ""
    return clean if COUNTRY_RE.match(clean) else None


def render_template(template: str, username: str = "", password: str = "",
                    session: str | None = None, country: str | None = None) -> str:
    """Render a provider's username/password template.

    Providers put the knobs in different fields — Oxylabs and Bright Data in the username, IPRoyal
    in the password — so the shape is data, never code. `{username}`, `{password}`, `{session}`,
    `{country}` (uppercase) and `{country_lc}` (lowercase) substitute.

    A `[...]` segment is kept only when EVERY placeholder inside it has a value, and dropped whole
    otherwise. That is what lets one template serve sticky and rotating sessions and a chosen and
    an unchosen country at once (`customer-{username}[-cc-{country}][-sessid-{session}]` renders
    all four combinations) instead of a dangling `-cc-` the provider refuses the credential for. A
    segment with no placeholder in it keeps its old meaning and follows the session.

    `mitm-agent/src/exit.ts:renderTemplate` is the same function in TypeScript and the two MUST
    agree: the box authenticates the reachability check with it and this authenticates the
    customer's traffic with it.
    """
    values = {
        "username": username or "",
        "password": password or "",
        "session": session or "",
        "country": (country or "").upper(),
        "country_lc": (country or "").lower(),
    }

    def fill(m: "re.Match[str]") -> str:
        return values[m.group(1)]

    def segment(m: "re.Match[str]") -> str:
        inner = m.group(1)
        names = _PLACEHOLDER_RE.findall(inner)
        # A segment with nothing to fill keeps the rule it had before countries existed: it
        # follows the session. A hand-written `{username}[-sticky]` must not start appearing on
        # rotating connections it was never on.
        if not names:
            return inner if values["session"] else ""
        return inner if all(values[n] for n in names) else ""

    out = re.sub(r"\[([^\[\]]*)\]", segment, template or "")
    return _PLACEHOLDER_RE.sub(fill, out)


def session_for(vm_id: str | None) -> str | None:
    """The upstream session token for one agent box, or None when sticky IPs are off.

    Derived here, from a salt that was generated on this firewall and never leaves it, so neither
    the control plane nor an agent box can work out (or choose) which exit IP a box gets. Stable
    for the life of the credential: rotating the credential rotates the salt.
    """
    cfg = exit_config()
    if not cfg.get("sticky") or not vm_id:
        return None
    salt = str(cfg.get("sticky_salt") or "")
    return hmac.new(salt.encode("utf-8"), vm_id.encode("utf-8"), hashlib.sha256).hexdigest()[:12]


def _templates_take_country(up: dict[str, Any]) -> bool:
    """Whether this provider's templates have anywhere to put a country at all."""
    both = f"{up.get('username_template') or ''} {up.get('password_template') or ''}"
    return "{country}" in both or "{country_lc}" in both


def country_refusal(up: dict[str, Any], country: str | None) -> str | None:
    """Why this country cannot be asked of this upstream, or None if it can.

    A country the credential has nowhere to carry is the dangerous case: the rendered credential
    is byte-for-byte the one with no country, so the flow leaves from wherever the provider felt
    like and every part of the console reads as though the choice was honoured. Failing closed is
    the only outcome that does not lie.
    """
    if country and not _templates_take_country(up):
        return f"this exit's credential has no country field, so it cannot come out in {country}"
    return None


def exit_country_for(rule: dict[str, Any] | None) -> str | None:
    """Which country this flow should come out in: the rule's own choice, else the org default.

    A rule carries `exit_country` only when someone set one on it; anything else falls back to
    `exit.json`'s `country`, which is itself allowed to be absent ("wherever the provider puts
    us"). A malformed value on either is read as "no country" rather than passed on: a provider
    handed junk here refuses the whole credential, which would take a working exit down over a
    typo in a setting.
    """
    if rule:
        own = normalize_country(rule.get("exit_country"))
        if own:
            return own
    return normalize_country(exit_config().get("country"))


# `http_connect_upstream` fires from a flow mitmproxy fabricates for the CONNECT
# (`_upstream_proxy.HttpUpstreamProxy.start_handshake`), so nothing the real flow holds reaches it
# — and it must not re-derive the country from the connection alone. The two paths choose their
# rule differently: the TLS relay uses `residential_rule` (connection-level) and the plaintext
# path uses `match_rule` (path-aware), and a path-scoped rule that outranks the residential one
# makes them disagree. Re-deriving would then render the credential with the ORG default and send
# the flow out of a country nobody asked for, silently — the exact failure `country_refusal`
# exists to prevent. So the decision is tagged on the client connection, which is the one object
# both the decision and the hook can see, and the destination is carried with it so a tag can
# never be read for a request it was not made for.
def tag_exit_country(client, host: str, port: int | None, country: str | None) -> None:
    try:
        client.cc_exit_country = (host, int(port or 0), country)
    except Exception:  # noqa: BLE001
        pass


def tagged_exit_country(client, host: str, port: int | None) -> tuple[bool, str | None]:
    """(was this destination tagged, the country tagged for it)."""
    tag = getattr(client, "cc_exit_country", None)
    if not isinstance(tag, tuple) or len(tag) != 3:
        return False, None
    if tag[0] != host or tag[1] != int(port or 0):
        return False, None
    return True, tag[2]


def upstream_credentials(up: dict[str, Any], vm_id: str | None, country: str | None = None) -> tuple[str, str]:
    session = session_for(vm_id)
    user = render_template(str(up.get("username_template") or "{username}"),
                           username=str(up.get("username") or ""), session=session, country=country)
    pw = render_template(str(up.get("password_template") or "{password}"),
                         password=str(up.get("password") or ""), session=session, country=country)
    return user, pw


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


# ----- included AI tokens -----------------------------------------------------

INCLUDED_BLOCK_STATUS = 400
INCLUDED_HINT = "Pick one of your plan's models, or add your own provider key in ControlClaw under Model providers."
INCLUDED_EXHAUSTED = ("Your plan's included AI tokens are used up for this month. They reset on the 1st; "
                      "until then, add your own provider key in ControlClaw under Model providers.")
INCLUDED_NO_CREDIT = ("Included AI is paused: the AI provider refused this call over billing on ControlClaw's "
                      "side, not yours. ControlClaw has been told. Your own provider keys still work; see "
                      "Model providers in ControlClaw for where this stands.")


def _placeholder_in_request(flow: http.HTTPFlow, cred: dict[str, Any]) -> bool:
    placeholder = cred.get("placeholder") or ""
    if not placeholder:
        return False
    for loc in cred.get("locations") or DEFAULT_LOCATIONS:
        if loc.startswith("header:"):
            name = loc.split(":", 1)[1].lower()
            if any(k.lower() == name and placeholder in v for k, v in flow.request.headers.items()):
                return True
    return False


def included_model_check(method: str, path: str, body: bytes | None, allowed: list[str]) -> str | None:
    """Why a request on the included key is refused, or None to let it through.

    Only generation calls for an allowed model, and reading the model list. Everything else the
    gateway offers (credit balance, generation lookups, other models) stays out of reach: the key
    is ControlClaw's, shared by nobody but still billed to us."""
    bare = path.split("?", 1)[0]
    if method.upper() == "GET":
        return None if bare.rstrip("/").endswith("/models") or "/models/" in bare else "only generation requests are included"
    if method.upper() != "POST":
        return "only generation requests are included"
    try:
        model = json.loads(body or b"{}").get("model")
    except (ValueError, AttributeError):
        model = None
    if not isinstance(model, str) or not model:
        return "the request names no model"
    if model not in allowed:
        return f"{model} is not included in your plan"
    return None


def included_refusal(flow: http.HTTPFlow, vm_id: str | None) -> str | None:
    """The refusal reason when this request uses an included key the wrong way, else None.
    Marks the flow so a "budget exceeded" answer can be reworded (see `response`)."""
    for cred in credentials_for(flow.request.pretty_host, vm_id):
        allowed = cred.get("allowed_models")
        if not allowed or not _placeholder_in_request(flow, cred):
            continue
        flow.metadata["cc_included"] = True
        reason = included_model_check(flow.request.method, flow.request.path, flow.request.raw_content, list(allowed))
        if reason:
            return f"{reason}. Included models: {', '.join(allowed)}. {INCLUDED_HINT}"
    return None


def _error_body(message: str, code: str) -> str:
    """OpenAI-shaped, which is what OpenClaw's openai-completions transport reads."""
    return json.dumps({"error": {"message": message, "type": "invalid_request_error", "code": code}})


def classify_included_402(flow: http.HTTPFlow) -> str | None:
    """Which kind of billing refusal the gateway answered an included-tokens request with.

    `used_up`   the organisation's own key budget is spent — what the plan's allowance running out
                looks like, and the organisation's own business.
    `no_credit` anything else: the gateway refusing over billing for a reason that is not this
                key's budget, which in practice is our AI Gateway team running out of credit and
                every organisation on the included tokens going down at once.

    Generous on purpose. The refusal seen in production carried no type the gateway documents, so
    reading only a known list would have missed it again; being told about a 402 we can check
    against the balance in one call beats another silent outage. What follows from that is that
    the wording above must not tell the reader anything about their own allowance — only the
    console, which knows both numbers, says whose problem it is.
    """
    if not flow.metadata.get("cc_included") or not flow.response or flow.response.status_code != 402:
        return None
    try:
        kind = (json.loads(flow.response.get_text(strict=False) or "{}").get("error") or {}).get("type")
    except (ValueError, AttributeError):
        kind = None
    return "used_up" if kind == "quota_for_entity_exceeded" else "no_credit"


def reword_402(flow: http.HTTPFlow) -> str | None:
    """Rewrite the gateway's billing refusal into something a person can act on, and say which kind
    it was. The gateway's own message names our key id and a dollar amount and the agent passes it
    straight on to a person, so neither kind is ever forwarded as-is."""
    kind = classify_included_402(flow)
    if not kind:
        return None
    if kind == "used_up":
        flow.response.set_text(_error_body(INCLUDED_EXHAUSTED, "included_tokens_used_up"))
    else:
        flow.response.set_text(_error_body(INCLUDED_NO_CREDIT, "included_ai_no_credit"))
    flow.response.headers["content-type"] = "application/json"
    return kind


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
            elif loc == "path":
                # Some APIs carry the token in the URL itself (Telegram: /bot<token>/method).
                if placeholder in flow.request.path:
                    flow.request.path = flow.request.path.replace(placeholder, secret)
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


# The last few requests of each VM, for the inline judge: what the agent was doing just before.
_recent: dict[str | None, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=AI_RECENT))


def _remember(record: dict[str, Any]) -> None:
    if not record.get("host"):
        return
    keep = {k: record[k] for k in ("ts", "method", "host", "path", "effect", "status", "bytes_out") if record.get(k) is not None}
    keep["ts"] = int(keep.get("ts", 0))
    _recent[record.get("vm_id")].append(keep)


def _log(record: dict[str, Any]) -> None:
    """Append one traffic record (JSONL). Rotates the file by size first, see LOG_MAX_BYTES."""
    _remember(record)
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


# Telegram's Bot API carries the bot token in the URL path (`/bot<id>:<token>/method`). A traffic
# record must never store it: the console shows these paths and the control plane keeps them.
_TELEGRAM_TOKEN_RE = re.compile(r"/bot\d+:[A-Za-z0-9_-]{20,}(?=/|$)")


def redact_path(path: str) -> str:
    """The query-stripped path with any embedded credential replaced by a marker."""
    return _TELEGRAM_TOKEN_RE.sub("/bot<redacted>", path.split("?", 1)[0])


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
        "path": redact_path(flow.request.path), "effect": effect,
        "rule": flow.metadata.get("cc_rule"),
    })
    if flow.metadata.get("cc_ai"):
        rec["ai"] = flow.metadata["cc_ai"]
    return rec


def _log_once(flow: http.HTTPFlow, rec: dict[str, Any]) -> None:
    """mitmproxy can fire both `response` and `error` for one flow (e.g. the client goes away
    while the response is being written). Log each HTTP flow exactly once."""
    if flow.metadata.get("cc_logged"):
        return
    flow.metadata["cc_logged"] = True
    _log(rec)


# ----- inline AI review -------------------------------------------------------

_TEXT_TYPES = ("text/", "application/json", "application/x-www-form-urlencoded", "application/xml", "application/graphql")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _body_start(flow: http.HTTPFlow) -> str | None:
    """The first AI_BODY_CHARS characters of a text body, control characters stripped."""
    ctype = (flow.request.headers.get("content-type") or "").lower()
    if not flow.request.raw_content or not ctype.startswith(_TEXT_TYPES):
        return None
    try:
        text = flow.request.raw_content[: AI_BODY_CHARS * 4].decode("utf-8", errors="replace")
    except Exception:
        return None
    return _CONTROL_CHARS.sub(" ", text)[:AI_BODY_CHARS]


def _judge_sync(payload: dict[str, Any]) -> dict[str, Any]:
    # A proxy-less opener: the judge is on loopback and must never be sent through a proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(
        AI_JUDGE_URL, data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"}, method="POST",
    )
    with opener.open(req, timeout=AI_JUDGE_TIMEOUT) as res:
        return json.loads(res.read(64 * 1024))


async def ai_judge(flow: http.HTTPFlow, rule: dict[str, Any], vm_id: str | None,
                   approve: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Ask the local judge about one request. None means "no opinion": the rule's effect stands.
    Runs in a thread so a slow judge never stalls other flows."""
    if not AI_JUDGE_URL:
        return None
    raw_path = flow.request.path
    query = raw_path.split("?", 1)[1] if "?" in raw_path else ""
    payload = {
        "rule": rule.get("name") or rule.get("match_domain") or "",
        "vm_id": vm_id,
        "method": flow.request.method,
        "host": flow.request.pretty_host,
        "path": redact_path(raw_path)[:200],
        "query_keys": sorted({kv.split("=", 1)[0] for kv in query.split("&") if kv})[:20],
        "content_type": (flow.request.headers.get("content-type") or "")[:100] or None,
        "body_start": _body_start(flow),
        "recent": list(_recent[vm_id]),
        **({"mode": "approve", "policy": rule.get("ai_policy"), **approve} if approve else {"mode": "review"}),
    }
    try:
        out = await asyncio.to_thread(_judge_sync, payload)
    except Exception as exc:
        log.warning(f"[mitm] ai judge unavailable: {exc}")
        return None
    if not isinstance(out, dict) or out.get("decision") not in ("allow", "ask", "block"):
        return None
    return out


# ----- residential layers -----------------------------------------------------

if _layer is not None:

    class _ExitUnavailable(_layer.Layer):
        """Close a residential connection that cannot go out through the upstream.

        This is the fail-closed path and the reason it is a layer rather than an early return:
        letting the flow fall through to mitmproxy's defaults would send it out of THIS box's IP,
        which is exactly the correlation the customer bought a residential exit to avoid. They see
        a failed request and one Activity line saying why; they never see a job that quietly ran
        from a datacenter address.
        """

        def __init__(self, context, record: dict[str, Any]) -> None:
            super().__init__(context)
            self._record = record
            self._closed = False

        def _handle_event(self, event):
            if not self._closed:
                self._closed = True
                _log(self._record)
                yield _commands.CloseConnection(self.context.client)

    class _Socks5Upstream(_tunnel.TunnelLayer):
        """SOCKS5 with username/password auth (RFC 1928 + RFC 1929) to the upstream proxy.

        mitmproxy's own `Server.via` only knows http/https (`mitmproxy/net/server_spec.py`), so the
        SOCKS5 half of "HTTP CONNECT and SOCKS5" is ours. Two deliberate choices: the greeting
        offers method 0x02 ONLY, so a proxy that would have taken us unauthenticated cannot talk us
        out of sending credentials; and the request carries ATYP=domain, so the NAME is resolved at
        the exit rather than here (see `next_layer` — the whole point of CONNECTing by hostname).
        """

        def __init__(self, context, tunnel_conn, username: str, password: str) -> None:
            super().__init__(context, tunnel_connection=tunnel_conn, conn=context.server)
            self._user = username.encode("utf-8")[:255]
            self._pass = password.encode("utf-8")[:255]
            self._state = "greeting"
            self._buf = b""

        @classmethod
        def make(cls, ctx, address, username: str, password: str):
            stack = _tunnel.LayerStack()
            stack /= cls(ctx, connection.Server(address=address), username, password)
            return stack

        def start_handshake(self):
            yield _commands.SendData(self.tunnel_connection, b"\x05\x01\x02")

        def receive_handshake_data(self, data: bytes):
            self._buf += data
            if self._state == "greeting":
                if len(self._buf) < 2:
                    return False, None
                ver, method = self._buf[0], self._buf[1]
                self._buf = self._buf[2:]
                if ver != 0x05 or method != 0x02:
                    return False, f"socks5: upstream refused username/password auth (method {method:#04x})"
                self._state = "auth"
                yield _commands.SendData(
                    self.tunnel_connection,
                    bytes([0x01, len(self._user)]) + self._user + bytes([len(self._pass)]) + self._pass,
                )
                return False, None
            if self._state == "auth":
                if len(self._buf) < 2:
                    return False, None
                status = self._buf[1]
                self._buf = self._buf[2:]
                if status != 0x00:
                    return False, "socks5: upstream rejected the credential"
                self._state = "connect"
                host, port = self.conn.address
                raw = encode_host(host) or b""
                yield _commands.SendData(
                    self.tunnel_connection,
                    b"\x05\x01\x00\x03" + bytes([len(raw)]) + raw + int(port).to_bytes(2, "big"),
                )
                return False, None
            # connect reply: VER REP RSV ATYP ADDR PORT — length depends on ATYP.
            if len(self._buf) < 5:
                return False, None
            if self._buf[1] != 0x00:
                return False, f"socks5: upstream refused the connection (reply {self._buf[1]:#04x})"
            atyp = self._buf[3]
            need = {0x01: 10, 0x04: 22}.get(atyp, 7 + self._buf[4] if atyp == 0x03 else 0)
            if not need or len(self._buf) < need:
                return (False, None) if need else (False, f"socks5: bad address type {atyp:#04x}")
            rest = self._buf[need:]
            self._buf = b""
            if rest:
                yield from self.receive_data(rest)
            return True, None


def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"[0-9.]+", host or "")) or ":" in (host or "")


def encode_host(host: str) -> bytes | None:
    """The hostname as it goes on the wire, or None if it cannot go there at all.

    A browser will happily put things in an SNI that `idna` refuses: a label over 63 bytes, a
    trailing dot, an underscore. Finding that out inside a handshake generator raises through
    `TunnelLayer`, which does not guard it, and the flow dies as an unhandled proxy error instead
    of the logged fail-closed record. So it is decided before the stack is built.
    """
    if not host or len(host) > 253:
        return None
    if _is_ip(host):
        return host.encode("ascii", "ignore") or None
    try:
        # `idna` is the rule that actually applies: mitmproxy's own CONNECT does `encode("idna")`,
        # so anything it rejects would raise there instead of here. Checking ascii-ness instead
        # would let a 70-byte label through this gate and blow up inside the handshake.
        return host.encode("idna")
    except (UnicodeError, ValueError):
        return None


def _exit_record(ctx, rule: dict[str, Any] | None, host: str, port: int | None,
                 vm_id: str | None, error: str) -> dict[str, Any]:
    """The one record a refused residential connection leaves behind."""
    country = exit_country_for(rule)
    return {
        "flow_id": "res_" + hashlib.sha256(f"{time.time()}{host}{port}".encode()).hexdigest()[:24],
        "ts": time.time(), "tenant": TENANT, "vm_id": vm_id,
        "host": host, "port": port, "effect": "residential",
        "rule": (rule or {}).get("name"), "exit": "residential", "error": error[:200],
        **({"exit_country": country} if country else {}),
    }


def _residential_stack(ctx, host: str, port: int, rule: dict[str, Any], vm_id: str | None):
    """The layer stack for one residential flow, or None if it cannot be built (caller fails closed).

    CONNECT by NAME, not by the IP redsocks handed us: the destination is then resolved at the
    exit, which is what makes a geo-targeted exit reach the right edge of a CDN. (The agent box
    still resolved the name locally to get an IP to connect to at all — that DNS query leaks this
    datacenter even though the connection does not. Documented, not fixed.)
    """
    up, why = _residential_ready()
    if not up:
        return None, why
    if _upstream_proxy is None and str(up.get("scheme")) != "socks5":
        return None, f"this firewall's proxy cannot chain upstream ({_UPSTREAM_IMPORT_ERROR})"
    if encode_host(host) is None:
        return None, f"{host[:60]!r} cannot be put in a CONNECT request"
    if ctx.server.connected:
        # mitmproxy opened the destination before we were asked. That is `connection_strategy=eager`
        # (its default), which for a residential flow has already leaked a TCP connection from this
        # box's own IP to the very site we are trying to reach from somewhere else — and would then
        # relay over that socket instead of the tunnel. The firewall's unit sets `lazy`; if it did
        # not, say so plainly instead of quietly exiting from the wrong address.
        return None, "this firewall's proxy is running with connection_strategy=eager"
    country = exit_country_for(rule)
    refused = country_refusal(up, country)
    if refused:
        return None, refused
    tag_exit_country(ctx.client, host, port, country)
    user, pw = upstream_credentials(up, vm_id, country)
    session = session_for(vm_id)
    scheme = str(up.get("scheme"))
    ctx.server.address = (host, int(port))
    if scheme == "socks5":
        # No `via` here: mitmproxy's ServerSpec has no socks5 scheme, and setting a made-up one
        # would be read by any other code path that trusts it. The address goes straight in.
        stack = _Socks5Upstream.make(ctx, (str(up["host"]), int(up["port"])), user, pw)
    else:
        ctx.server.via = (scheme, (str(up["host"]), int(up["port"])))
        stack = _upstream_proxy.HttpUpstreamProxy.make(ctx, True)
    relay = _proxy_layers.TCPLayer(ctx)  # ignore=False: a real TCPFlow, so we get bytes and hooks
    relay.flow.metadata["cc_exit"] = {
        "rule": rule.get("name") or rule.get("match_domain"),
        "host": host, "port": int(port), "vm_id": vm_id, "country": country,
        "session": session, "in": 0, "out": 0, "billed_in": 0, "billed_out": 0, "seq": 0,
    }
    stack /= relay
    return stack[0], None


# ----- hooks ----------------------------------------------------------------

def tls_clienthello(data) -> None:
    """Pass a connection through untouched (no TLS interception), matched by SNI: a built-in host
    (the control plane, so the JWT channel is never MITM'd, and the backup object store, whose bodies
    are already encrypted end to end), Tailscale for a box whose owner joined it to their tailnet,
    OR an opt-in `tunnel` rule (uninspected egress).

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
        vm_id = ctx_vm_id(ctx)
        if residential_rule(sni, port, vm_id) is not None:
            # Residential is decided in `next_layer`, which runs first and has the ClientHello.
            # Reaching here means that decision was missed, and `ignore_connection` would send the
            # flow out of THIS box's IP — the one outcome a residential rule must never produce.
            log.error(f"[mitm] residential rule reached tls_clienthello for {sni}; refusing to pass through")
            return
        if (
            any(host_matches(h, sni) for h in PASSTHROUGH_HOSTS)
            or (tailscale_allowed(vm_id) and any(host_matches(h, sni) for h in TAILSCALE_HOSTS))
            or tunnel_match(sni, port, vm_id)
        ):
            data.ignore_connection = True
    except Exception as exc:  # noqa: BLE001 — never break interception over a match error
        log.warning(f"[mitm] tls_clienthello passthrough check failed: {exc}")


def next_layer(data) -> None:
    """Where a connection's fate is decided before any layer exists. Three jobs:

    - A raw connection to a `tunnel` destination (by IP:port) is passed through uninspected.
    - A connection matching a **residential** rule is relayed through the org's upstream proxy,
      untouched, so the site sees the agent browser's own TLS handshake. For TLS that means
      reading the SNI out of the ClientHello HERE, because the hook that normally does it
      (`tls_clienthello`) can only pass a connection through DIRECT, which is the one thing a
      residential rule must not do.
    - Everything else falls through to mitmproxy's defaults: HTTP/TLS are intercepted as usual,
      and any other raw TCP becomes a flow that `tcp_start` drops.

    This addon's hook runs after mitmproxy's own, so `data.layer` already holds its choice: an
    override assigns, and a *deferral* must clear it back to None (which makes mitmproxy buffer and
    ask again when more bytes arrive). Chrome's ClientHello with post-quantum key shares is ~2 KB
    and arrives in two TCP segments, so that deferral is the normal path, not an edge case.

    Fully guarded: any error leaves mitmproxy's default layer selection untouched.
    """
    if _proxy_layers is None:
        return
    try:
        ctx = getattr(data, "context", None)
        host, port = _server_addr(ctx)
        vm_id = ctx_vm_id(ctx)
        peeked = b""
        try:
            peeked = bytes(data.data_client())
        except Exception:
            peeked = b""
        if not peeked:
            # Nothing to judge by yet. mitmproxy calls this hook again on the first bytes; acting
            # now would mean treating every connection as raw TCP and matching it by IP.
            return
        is_tls = peeked[0] == 0x16  # TLS handshake record
        sni = ""  # set below for TLS; stays empty for raw TCP, which matches by IP and port

        if is_tls and parse_client_hello is not None:
            readable = True
            try:
                hello = parse_client_hello(peeked)
            except ValueError:
                hello, readable = None, False  # not a ClientHello we can read; leave it to mitmproxy
            if hello is None and readable and residential_configured():
                # Incomplete ClientHello. Clear mitmproxy's choice and wait for the rest; this is
                # the normal path for Chrome, whose hello spans two segments.
                data.layer = None
                return
            if hello is not None:
                sni = (hello.sni or "").lower()
            if sni:
                rule = residential_rule(sni, port, vm_id)
                if rule is not None:
                    _use_residential(data, ctx, sni, port or 443, rule, vm_id)
                    return
            elif residential_configured():
                # No SNI, or a ClientHello we could not read. The destination cannot be named, so
                # a rule written against a domain cannot be matched and this flow is about to be
                # intercepted and sent from this box's own address. That may be right — most such
                # connections are not residential at all — but it is the one case where the
                # customer could believe otherwise, so it goes in the log rather than nowhere. A
                # residential rule pinned to this IP and port still matches, below.
                log.info(f"[mitm] no readable SNI for {host}:{port}; residential rules by domain cannot apply")

        # Raw TCP, and TLS we could not name: both can still match a rule pinned to this exact
        # IP and port, which is how a residential rule for something without an SNI is written.
        if not is_tls or not sni:
            rule = residential_rule(host, port, vm_id)
            if rule is not None:
                _use_residential(data, ctx, host, port or 0, rule, vm_id)
                return
        if not is_tls:
            if tunnel_match(host, port, vm_id) is not None:
                data.layer = _proxy_layers.TCPLayer(ctx, ignore=True)
    except Exception as exc:  # noqa: BLE001
        log.warning(f"[mitm] next_layer passthrough check failed: {exc}")


def residential_configured() -> bool:
    """Whether ANY residential rule exists — the cheap test that decides if deferring for a full
    ClientHello is worth the wait. An org with no residential rules never pays for this."""
    return any(r.get("exit") == "residential" for r in _rules.get())


def _use_residential(data, ctx, host: str, port: int, rule: dict[str, Any], vm_id: str | None) -> None:
    """Install the residential stack, or the layer that closes the connection and says why."""
    stack, why = _residential_stack(ctx, host, port, rule, vm_id)
    if stack is not None:
        data.layer = stack
        log.info(f"[mitm] residential exit for {host}:{port} (rule={rule.get('name')}, tenant={TENANT})")
        return
    reason = f"residential exit unavailable: {why}"
    log.warning(f"[mitm] {reason} ({host}:{port})")
    record = _exit_record(ctx, rule, host, port, vm_id, reason)
    if _layer is None:
        # We cannot even build a layer (the core import failed). Point the connection at a
        # black hole so mitmproxy's own machinery ends it: the client gets an error and nothing
        # goes to the real destination from this box.
        _log(record)
        try:
            ctx.server.address = BLACKHOLE_ADDR
        except Exception as exc:  # noqa: BLE001
            log.error(f"[mitm] could not fail a residential flow closed: {exc}")
        return
    data.layer = _ExitUnavailable(ctx, record)


def tcp_start(flow) -> None:
    """Central drop: any RAW TCP flow that reaches interception is non-HTTP/TLS and not an
    allowlisted tunnel (those are passed through in next_layer/tls_clienthello and never become a
    TCP flow). Since the box redirects ALL TCP here, this is the "drop everything not allowed" point.

    The one exception is a residential relay, which IS a raw TCP flow on purpose: it is how the
    client's own TLS bytes reach the site unmodified, and it is a flow rather than an ignored
    connection so that its bytes can be counted. `next_layer` marks it when it builds the stack.
    """
    try:
        if flow.metadata.get("cc_exit"):
            return
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


def tcp_message(flow) -> None:
    """Count a residential relay's bytes, then drop the message from the flow.

    `TCPLayer` appends every chunk to `flow.messages` and only then sends it (`layers/tcp.py`), so
    a flow left alone would hold an entire multi-gigabyte transfer in this process's memory. The
    send reads the message object the layer already holds, so trimming the list here is safe — and
    it is also what keeps the promise that a relayed flow's *contents* are never stored anywhere.
    """
    meta = flow.metadata.get("cc_exit")
    if not meta:
        return
    try:
        msg = flow.messages[-1]
        size = len(msg.content or b"")
        meta["out" if msg.from_client else "in"] += size
        del flow.messages[:-1]
        unbilled = (meta["in"] - meta["billed_in"]) + (meta["out"] - meta["billed_out"])
        if unbilled >= RESIDENTIAL_INTERIM_BYTES:
            _log(_residential_record(flow, meta, interim=True))
    except Exception as exc:  # noqa: BLE001
        log.warning(f"[mitm] tcp_message accounting failed: {exc}")


def tcp_end(flow) -> None:
    """One record per residential relay: host, port, bytes and how long it was open. Never a path
    (there is none to have) and never a byte of content."""
    if flow.metadata.get("cc_exit"):
        _log(_residential_record(flow, flow.metadata["cc_exit"]))


def tcp_error(flow) -> None:
    """A residential relay that never opened: the upstream refused the CONNECT, rejected the
    credential, or was unreachable. This is the fail-closed outcome the customer sees in Activity."""
    meta = flow.metadata.get("cc_exit")
    if not meta:
        return
    rec = _residential_record(flow, meta)
    rec["error"] = f"residential exit unreachable: {str(getattr(flow, 'error', '') or 'upstream error')}"[:200]
    _log(rec)


def _residential_record(flow, meta: dict[str, Any], interim: bool = False) -> dict[str, Any]:
    """A usage record for one relay. Interim records carry only the bytes since the last one and a
    suffixed flow id, so the shipper's at-least-once upload still dedupes and nothing double-counts.
    """
    moved_in = meta["in"] - meta["billed_in"]
    moved_out = meta["out"] - meta["billed_out"]
    meta["billed_in"], meta["billed_out"] = meta["in"], meta["out"]
    seq = meta["seq"]
    meta["seq"] = seq + 1
    rec = {
        "flow_id": flow.id if seq == 0 else f"{flow.id}#{seq}",
        "ts": time.time(), "tenant": TENANT, "vm_id": meta.get("vm_id"),
        "host": meta.get("host") or "", "port": meta.get("port"),
        "effect": "residential", "rule": meta.get("rule"), "exit": "residential",
        "bytes_in": moved_in, "bytes_out": moved_out,
        # On every record, not only on a refusal: "which country did this come out in" is a
        # question about the flows that WORKED, and the console cannot answer it from a rule
        # (a rule's country can change after the fact).
        **({"exit_country": meta["country"]} if meta.get("country") else {}),
    }
    start = getattr(getattr(flow, "client_conn", None), "timestamp_start", None)
    if start and not interim:
        rec["duration_ms"] = int((time.time() - start) * 1000)
    return rec


def http_connect_upstream(flow: http.HTTPFlow) -> None:
    """Authenticate this firewall to the org's upstream residential proxy.

    mitmproxy fires this just before it writes the CONNECT, which is the only place a per-flow
    credential can go: the username carries the agent's sticky session, so two agent boxes get two
    exit IPs from one account. The credential is never logged, never put in a traffic record, and
    never sent anywhere but the proxy named in the org's own exit configuration.
    """
    try:
        up, why = _residential_ready()
        if not up:
            log.warning(f"[mitm] upstream CONNECT without a usable exit: {why}")
            return
        vm_id = vm_id_for_ip(_peer_ip(flow.client_conn.peername))
        host = flow.request.host or ""
        # The country the path that built this stack actually decided on (see `tag_exit_country`).
        # The fallback is for a stack nothing tagged, which can only be a mitmproxy path we do not
        # own; the connection-level answer is right for every rule that has no `match_path`.
        tagged, country = tagged_exit_country(flow.client_conn, host, flow.request.port)
        if not tagged:
            country = exit_country_for(residential_rule(host, flow.request.port, vm_id))
        user, pw = upstream_credentials(up, vm_id, country)
        if user or pw:
            token = base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")
            flow.request.headers["Proxy-Authorization"] = f"Basic {token}"
    except Exception as exc:  # noqa: BLE001
        log.warning(f"[mitm] upstream auth failed: {exc}")


def _residential_http_record(flow: http.HTTPFlow) -> dict[str, Any]:
    """A plaintext residential request's record: host and port, like every other relayed flow.

    Port 80 carries no handshake to protect and the request line was readable to anyone on the
    path — but the promise made to the customer is that a residential flow is logged at host level
    and no finer, and a promise with an exception in it is not one. So `method` and `path` come
    back out of the record `_http_record` built.
    """
    rec = _http_record(flow, "residential")
    rec.pop("method", None)
    rec.pop("path", None)
    rec.update({"port": flow.request.port, "exit": "residential"})
    _, country = tagged_exit_country(flow.client_conn, flow.request.host or "", flow.request.port)
    if country:
        rec["exit_country"] = country
    return rec


def _refuse_residential_http(flow: http.HTTPFlow, host: str, why: str) -> None:
    """Answer a plaintext residential request the exit cannot carry, and say why in one record."""
    flow.response = http.Response.make(
        BLOCK_STATUS,
        json.dumps({"error": "residential_exit_unavailable", "host": host, "tenant": TENANT}),
        {"Content-Type": "application/json"},
    )
    flow.metadata["cc_effect"] = "residential"
    rec = _residential_http_record(flow)
    rec.update({"status": BLOCK_STATUS, "error": f"residential exit unavailable: {why}"[:200]})
    _log_once(flow, rec)


async def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    method = flow.request.method
    path = flow.request.path
    vm_id = flow_vm_id(flow)  # which VM (by source IP) this request belongs to; None if unknown
    flow.metadata["cc_vm_id"] = vm_id

    rule = match_rule(host, method, path, vm_id)
    effect = (rule or {}).get("effect", "allow")
    flow.metadata["cc_effect"] = effect
    flow.metadata["cc_rule"] = (rule or {}).get("name") or (rule or {}).get("match_domain")

    if rule is not None and rule.get("exit") == "residential" and effect in RESIDENTIAL_EFFECTS:
        # Plaintext HTTP to a residential destination. A TLS flow never gets here (next_layer
        # relays it whole); this is port 80, where there is no handshake to preserve and the
        # bytes were readable to anyone on the path anyway. It still goes out through the upstream
        # and it still gets residential's terms: no credential swap, no AI review, host-level
        # logging only. `via` is mitmproxy's own per-flow upstream mechanism, honoured by the HTTP
        # layer, so nothing needs to be built here.
        up, why = _residential_ready()
        if not up:
            _refuse_residential_http(flow, host, why or "no residential exit is configured")
            return
        if str(up.get("scheme")) == "socks5":
            # mitmproxy's `via` cannot express SOCKS5, and a plaintext HTTP request is not worth a
            # second tunnel implementation. Fail closed rather than leaving from this box's IP.
            _refuse_residential_http(flow, host, "plain HTTP needs an HTTP upstream, not SOCKS5")
            return
        if encode_host(host) is None:
            _refuse_residential_http(flow, host, f"{host[:60]!r} cannot be put in a CONNECT request")
            return
        http_country = exit_country_for(rule)
        refused = country_refusal(up, http_country)
        if refused:
            _refuse_residential_http(flow, host, refused)
            return
        tag_exit_country(flow.client_conn, host, flow.request.port, http_country)
        # A FRESH Server, not `flow.server_conn.via = ...`. `Context.fork()` hands every stream on
        # one client connection the SAME Server object, so setting `via` on it is not per-request:
        # the next request on that connection — to any host, residential or not — would inherit
        # the upstream and be billed to the customer's provider account. The HTTP layer reads
        # `via` and `transport_protocol` off `flow.server_conn` when it makes the connection, so
        # replacing the object routes this request and only this request.
        flow.server_conn = connection.Server(
            address=(host, flow.request.port),
            via=(str(up.get("scheme")), (str(up["host"]), int(up["port"]))),
        )
        # `make_server_connection` takes the CONNECT authority from `request.host`, which behind
        # redsocks is the IP the agent box resolved. Put the name back: resolving at the exit is
        # what makes a geo-targeted exit reach the right edge, and it is the only way the provider
        # can route at all. The `Host` header is a separate field and is left exactly as it was.
        if flow.request.host != host:
            flow.request.host = host
        flow.metadata["cc_effect"] = "residential"
        flow.metadata["cc_exit_http"] = True
        return

    if effect == "allow" and rule and rule.get("ai_review"):
        # A human grant for this exact request (after an earlier AI "ask") wins over asking again.
        pid = permission_id_for(permission_scope(method, host, redact_path(path)))
        if not grant_active(pid):
            verdict = await ai_judge(flow, rule, vm_id)
            if verdict:
                flow.metadata["cc_ai"] = {
                    "verdict": verdict["decision"],
                    "category": verdict.get("category"),
                    "cached": bool(verdict.get("cached")),
                }
                if verdict["decision"] == "block":
                    effect = "block"
                elif verdict["decision"] == "ask":
                    effect = "require_permission"
                flow.metadata["cc_effect"] = effect

    if effect == "tunnel":
        # A tunnel destination should have been passed through *before* the HTTP layer
        # (tls_clienthello / next_layer). If we somehow reach here, let it through but NEVER swap
        # credentials into an uninspected-intent flow.
        _log_once(flow, _http_record(flow, "tunnel"))
        return

    if effect == "block":
        flow.response = http.Response.make(
            BLOCK_STATUS,
            json.dumps({"error": "blocked_by_ai_review" if flow.metadata.get("cc_ai") else "blocked_by_policy",
                        "host": host, "tenant": TENANT,
                        **({"category": flow.metadata["cc_ai"].get("category")} if flow.metadata.get("cc_ai") else {})}),
            {"Content-Type": "application/json"},
        )
        rec = _http_record(flow, "block")
        rec["status"] = BLOCK_STATUS
        _log_once(flow, rec)
        return

    if effect == "require_permission":
        scope = permission_scope(method, host, redact_path(path))
        pid = permission_id_for(scope)
        approved = None
        if (not grant_active(pid) and not flow.metadata.get("cc_ai") and rule
                and rule.get("ai_review") and rule.get("ai_policy")):
            # Ask rule with a policy: the AI may approve on the person's behalf. It never blocks;
            # "no" or no answer is the usual 451.
            approved = await ai_judge(flow, rule, vm_id, {"permission_id": pid, "scope": scope})
            if approved:
                flow.metadata["cc_ai"] = {
                    "verdict": "allow" if approved["decision"] == "allow" else "ask",
                    "category": approved.get("category"),
                    "cached": bool(approved.get("cached")),
                    **({"by": "ai"} if approved["decision"] == "allow" else {}),
                }
        if grant_active(pid) or (approved and approved["decision"] == "allow"):
            # Approved for this exact scope (by a person, or just now by the AI under the rule's
            # policy) and not expired: let it through (and swap).
            effect = "allow"
            flow.metadata["cc_effect"] = "allow"
            flow.metadata["cc_granted"] = pid
        else:
            record_pending(pid, {
                "ts": time.time(), "tenant": TENANT, "vm_id": vm_id, "permission_id": pid,
                "scope": scope, "host": host, "method": method, "path": redact_path(path),
                **({"ai_category": flow.metadata["cc_ai"].get("category")} if flow.metadata.get("cc_ai") else {}),
            })
            flow.response = http.Response.make(
                PERMISSION_STATUS,
                json.dumps({
                    "permission_id": pid,
                    "reason": "ai_review" if flow.metadata.get("cc_ai") else "require_permission",
                    "summary": scope, "expires_at": int(time.time()) + PERMISSION_TTL,
                }),
                {"Content-Type": "application/json"},
            )
            rec = _http_record(flow, "require_permission")
            rec.update({"permission_id": pid, "status": PERMISSION_STATUS})
            _log_once(flow, rec)
            return

    refusal = included_refusal(flow, vm_id)
    if refusal:
        flow.response = http.Response.make(INCLUDED_BLOCK_STATUS, _error_body(refusal, "model_not_included"), {"Content-Type": "application/json"})
        flow.metadata["cc_effect"] = "block"
        flow.metadata["cc_rule"] = "included_ai"
        rec = _http_record(flow, "block")
        rec["status"] = INCLUDED_BLOCK_STATUS
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
    if flow.metadata.get("cc_exit_http"):
        rec = _residential_http_record(flow)
        rec.update({"status": flow.response.status_code,
                    "bytes_out": len(flow.request.raw_content or b""),
                    "bytes_in": len(flow.response.raw_content or b"")})
        _log_once(flow, rec)
        return
    if flow.metadata.get("cc_effect") not in (None, "allow"):
        return
    # `included` on the record is what the console turns into a plain reason, and what the agent
    # reads off the traffic log to tell the control plane about our gateway. `ok` matters as much
    # as the refusals: one call getting through is what says the outage is over.
    kind = reword_402(flow)
    if not kind and flow.metadata.get("cc_included") and flow.response.status_code < 400:
        kind = "ok"
    rec_extra = {"included": kind} if kind else {}
    rec = _allow_record(flow)
    rec.update(rec_extra)
    rec["status"] = flow.response.status_code
    res_raw = flow.response.raw_content
    rec["bytes_in"] = len(res_raw) if res_raw else 0
    start, end = flow.request.timestamp_start, flow.response.timestamp_end
    if start and end:
        rec["duration_ms"] = int((end - start) * 1000)
    _log_once(flow, rec)


def error(flow: http.HTTPFlow) -> None:
    """Allowed request that never got a response (upstream refused, TLS failed, client went away)."""
    if flow.metadata.get("cc_exit_http"):
        rec = _residential_http_record(flow)
        rec["error"] = f"residential exit unreachable: {getattr(flow.error, 'msg', '') or 'upstream error'}"[:200]
        _log_once(flow, rec)
        return
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
