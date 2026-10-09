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
     leaves (with the rule's `ai_policy`, if any, as a note for the AI). The judge can let it
     through, block it, or turn it into a permission request. A
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
  7. Non-routable targets (T-61): no connection ever goes to a link-local, loopback, unspecified
     or multicast address, whatever a rule, the Host header or the CONNECT target says. Names are
     resolved first and the connection is pinned to the checked address (`server_connect`), so a
     name pointing at the metadata service is refused too. Each refusal is a `block` record.

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
import secrets
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import time
import urllib.request
from typing import Any

import logging

from mitmproxy import connection
from mitmproxy import http
from mitmproxy import ctx as _mitm_ctx
# Enforcement cannot be optional: refuse to load on an incompatible proxy version.
from mitmproxy.proxy import commands as _media_commands, events as _media_events
from mitmproxy.proxy.commands import CloseConnection as _CloseConnection
from mitmproxy.proxy.layer import Layer as _EnforcementLayer
from mitmproxy.proxy.layers.tcp import TCPLayer as _TCPLayer, TcpStartHook as _TcpStartHook

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

# The package hosts an agent box's own Ansible role downloads from (apt mirrors, NodeSource, npm,
# pkgs.tailscale.com, downloads.rclone.org, ...), allowed for a box only while it runs a confirmed
# update (apps/saas/docs/features/agent-updates.md). An update re-runs the role on a box that is
# already confined to this proxy, so under a deny-by-default policy it would fail at its first
# download without this.
#
#   * The list comes from the role, which writes it into this unit's environment. The control plane
#     does not send it and no org rule can change it.
#   * Exact host names only. A wildcard entry is dropped, so a typo in the role cannot turn into
#     "everything under .com". `*.tailscale.com` in particular stays with TAILSCALE_HOSTS above.
#   * The window is per box and has a deadline: the mitm-agent writes `update_until` (epoch seconds)
#     into that box's identity entry when the person confirms the update, and clears it when the run
#     finishes. The proxy checks the deadline itself, so a window cannot outlive it.
#   * The request goes to the name it asked for (see `request`), not to whatever IP the box
#     connected to, and it gets no credential swap and no AI review. It is logged like any other
#     request, with rule UPDATE_RULE, so the owner sees it in Activity as update traffic.
UPDATE_RULE = "agent_update"
# What a refusal under the emergency stop is called in the traffic log, so Activity can say why a
# box went quiet rather than showing a wall of ordinary policy blocks.
KILL_RULE = "kill_switch"

# The one thing a stopped box may still do (apps/saas/docs/features/kill-switch.md).
#
# Lifting the emergency stop needs a six-digit code, and the only way the firewall can put text in
# front of a person is to ask an agent to send it on one of its own channels — which the stop has
# just turned off and cut off. Without this the switch is one-way: proven on a real pair, where a
# release answered "Could not reach you on any connected channel" and the owner had no way back.
#
# So the firewall opens a window on ONE agent (`code_until` in its identity entry, epoch seconds,
# exactly like `update_until`) and these hosts, and nothing else, are allowed for it while the code
# is alive. It is ten minutes, one agent, the channel providers' own APIs: enough to carry six
# digits, not enough to reach a model or the web, so the agent still cannot DO anything.
#
# A built-in like TAILSCALE_HOSTS rather than an env var: the hosts are the providers' own and
# there is nothing here for a deployment to configure, so this cannot be pointed somewhere else
# without a change to this file. Exact names and one wildcard per provider, from the channel types
# the product supports (telegram, slack, whatsapp).
CODE_RULE = "kill_switch_code"
CHANNEL_HOSTS = (
    "api.telegram.org",
    "slack.com",
    "*.slack.com",
    "graph.facebook.com",
    "*.whatsapp.net",
    "web.whatsapp.com",
)
UPDATE_HOSTS = tuple(
    h for h in (p.strip().lower() for p in os.environ.get("MITM_UPDATE_HOSTS", "").split(","))
    if h and "*" not in h and "." in h
)

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
# The `rule` on a record for a target no rule can allow (link-local, loopback — see check_target).
NON_ROUTABLE_RULE = "non_routable_target"
# Prefix of the `server.error` a refused connection carries; the HTTP flow's error repeats it.
NON_ROUTABLE_REFUSAL = "refused by the firewall:"
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


def kill_switched(vm_id: str | None) -> bool:
    """True when this box is under an emergency stop (`apps/saas/docs/features/kill-switch.md`).

    The flag rides the identity map, like `tailscale`, and is written by the mitm-agent out of its
    OWN encrypted store — never from the control plane's answer, which has its `locked` stripped on
    every sync. So a compromised control plane can neither cut an agent off nor, far more
    importantly, let one back out.

    A connection whose source IP is not in the map resolves to `vm_id = None`. That is deliberately
    NOT treated as locked: an org-wide stop locks every entry the map has, and a connection from
    outside it is something the ordinary rules already have to judge. Making it lock instead would
    mean a stop on one agent broke the firewall box's own traffic.
    """
    if not vm_id:
        return False
    for ent in _identities.get():
        if ent.get("vm_id") == vm_id:
            return ent.get("locked") is True
    return False


def code_window_open(vm_id: str | None) -> bool:
    """True while THIS box is carrying a confirmation code out of a locked organisation: its
    identity entry has a `code_until` deadline (epoch seconds) that has not passed. Written by the
    mitm-agent when a release asks for a code, and cleared the moment the code is used, refused or
    runs out. See CHANNEL_HOSTS."""
    if not vm_id:
        return False
    for ent in _identities.get():
        if ent.get("vm_id") == vm_id:
            try:
                return float(ent.get("code_until") or 0) > time.time()
            except (TypeError, ValueError):
                return False
    return False


def code_traffic(host: str, vm_id: str | None) -> bool:
    """A request the code window allows: a channel provider's own host, from the one box the
    firewall opened the window for."""
    return code_window_open(vm_id) and any(host_matches(h, (host or "").lower()) for h in CHANNEL_HOSTS)


def update_window_open(vm_id: str | None) -> bool:
    """True while THIS box runs a confirmed update: its identity entry carries an `update_until`
    deadline (epoch seconds, written by the mitm-agent) that has not passed."""
    if not vm_id:
        return False
    for ent in _identities.get():
        if ent.get("vm_id") == vm_id:
            try:
                return float(ent.get("update_until") or 0) > time.time()
            except (TypeError, ValueError):
                return False
    return False


def update_traffic(host: str, vm_id: str | None) -> bool:
    """A request the update window allows: an exact UPDATE_HOSTS name, from a box that is updating."""
    return bool(UPDATE_HOSTS) and (host or "").lower() in UPDATE_HOSTS and update_window_open(vm_id)


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


def running() -> None:
    # mitmdump's built-in dumper otherwise prints the rewritten query string.
    # Activity is emitted separately below, with named swaps and no values.
    if hasattr(_mitm_ctx.options, "flow_detail"):
        _mitm_ctx.options.update(flow_detail=0)


def secret_host_matches(pattern: str, host: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower()
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host != pattern[2:]
    return "*" not in pattern and host == pattern


def credentials_for(host: str, vm_id: str | None = None) -> list[dict[str, Any]]:
    """Credentials matching `host`, vm-scoped with ORG FALLBACK: a credential with no `vm_id` is
    org-wide; one with a `vm_id` applies only to that VM and OVERRIDES the org-wide credential for
    the same placeholder. So per-VM secrets take precedence, and VMs without a specific override
    still get the org credential."""
    by_placeholder: dict[str, dict[str, Any]] = {}
    for c in _creds.get():
        if c.get("secret_name") or c.get("login_id"):
            # Custom secrets and website logins never inherit org fallback or legacy broad swap
            # locations: one agent, the hosts they were given, and nothing else.
            if not c.get("vm_id") or c["vm_id"] != vm_id:
                continue
            if not any(secret_host_matches(pattern, host) for pattern in c.get("allowed_hosts", [])):
                continue
        elif not host_matches(c.get("match_domain", ""), host):
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
    # An emergency stop outranks every rule the organisation wrote, and a tunnel is the one effect
    # that would otherwise leave the box without ever consulting a rule again.
    if kill_switched(vm_id):
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
    # Same as `tunnel_match`: a relayed flow never reaches the HTTP hook, so the stop has to be
    # applied before the stack is built or a locked box would keep its residential exit.
    if kill_switched(vm_id):
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

# Twilio v1: one assigned VM per account; narrow REST operations and TwiML verbs.
def phone_hook_url(value: str, hook: str) -> bool:
    from urllib.parse import urlsplit, parse_qsl
    try:
        u, h = urlsplit(value), urlsplit(hook)
        if (u.scheme, u.netloc, u.path) != (h.scheme, h.netloc, h.path) or u.fragment or len(u.query) > 2048:
            return False
        pairs = parse_qsl(u.query, keep_blank_values=True, strict_parsing=True)
        if len({k for k, _ in pairs}) != len(pairs):
            return False
        return all(v == "status" if k == "type" else k in ("callId", "turnToken", "ccCall") and re.fullmatch(r"[a-zA-Z0-9_-]{1,160}", v) for k, v in pairs)
    except ValueError:
        return False


def phone_twiml_allowed(xml: str, hook: str) -> bool:
    import xml.etree.ElementTree as ET
    if len(xml.encode()) > 65536 or "<!" in xml or re.search(r"&(?!amp;|lt;|gt;|quot;|apos;)", xml):
        return False
    xml = re.sub(r'^\s*<\?xml version="1\.0"(?: encoding="UTF-8")?\?>', '', xml)
    if "<?" in xml:
        return False
    attrs = {"Response": set(), "Say": {"voice", "language", "loop"},
             "Gather": {"input", "speechTimeout", "timeout", "language", "action", "method", "numDigits", "finishOnKey", "actionOnEmptyResult"},
             "Pause": {"length"}, "Hangup": set(), "Reject": {"reason"}, "Play": {"digits"}, "Redirect": {"method"}}
    try:
        root = ET.fromstring(xml)
        if root.tag != "Response":
            return False
        nodes = list(root.iter())
        if len(nodes) > 128:
            return False
        for node in nodes:
            if node.tag not in attrs or set(node.attrib) - attrs[node.tag] or (node is not root and node.tag == "Response"):
                return False
            if node.attrib.get("method", "POST") != "POST":
                return False
            if node.tag == "Gather" and not phone_hook_url(node.attrib.get("action", ""), hook):
                return False
            if node.tag == "Redirect" and not phone_hook_url((node.text or "").strip(), hook):
                return False
            if node.tag == "Play" and (not re.fullmatch(r"[0-9*#wW]{1,100}", node.attrib.get("digits", "")) or (node.text or "").strip()):
                return False
            if node.tag in ("Say", "Play", "Redirect") and len(node):
                return False
        return True
    except (ET.ParseError, ValueError):
        return False


# ----- email rules (docs/plans/email-rules.md) --------------------------------------------------
#
# The proxy holds no email rule. For every AgentMail or Gmail send it works out WHAT is being sent
# where (metadata only: recipients, ids, the RFC 822 header block, never a body) and asks the
# firewall agent on 127.0.0.1:8792, which allows and counts, blocks, or asks the owner. For every
# AgentMail message or thread it is about to show an agent, it asks the same listener whether to
# keep it, blank its preview, or hide it. Anything that fails, fails closed.

EMAIL_ADMISSION_URL = os.environ.get("MITM_EMAIL_ADMISSION_URL", "http://127.0.0.1:8792/")
AGENTMAIL_API = "api.agentmail.to"
AGENTMAIL_WS = "ws.agentmail.to"
_EMAIL_REASONS = {
    "sending_off": "Email sending is turned off for this mailbox.",
    "not_allowed": "This recipient is not on the allowed list for this mailbox.",
    "hourly_limit": "This mailbox has reached its hourly sending limit.",
    "daily_limit": "This mailbox has reached its daily sending limit.",
    "too_many_recipients": "Too many recipients in one message.",
    "no_recipients": "The message has no recipients.",
    "unreadable_recipients": "The firewall could not read the recipients of this message.",
    "lookup_failed": "The firewall could not check this message. Try again.",
    "headers_refused": "Custom headers may only be X-* headers, In-Reply-To or References.",
    "unknown_write": "This AgentMail operation is not allowed from an agent.",
    "forwarding_refused": "Agents may not set up forwarding, delegates or send-as addresses.",
    "unsupported_upload": "Send the message with a plain or multipart upload.",
    "held_back": "This message was held back by your organization's email rules.",
    "draft_busy": "This draft is being sent. Wait for that to finish before changing it.",
    "scheduled_send": "Scheduled sending is not allowed from an agent. Send the message when it should go.",
    "thread_attachment": "Read attachments through the message they belong to.",
    "email_rules_unavailable": "Email rules are unavailable on the firewall, so email is refused.",
}
_AM_SEND = re.compile(r"^/v0/inboxes/([^/]+)/messages/send$")
_AM_MSG_OP = re.compile(r"^/v0/inboxes/([^/]+)/messages/([^/]+)/(reply|reply-all|forward)$")
_AM_DRAFT_SEND = re.compile(r"^/v0/inboxes/([^/]+)/drafts/([^/]+)/send$")
_AM_DRAFT_WRITE = [("POST", re.compile(r"^/v0/inboxes/[^/]+/drafts$")),
                   ("PATCH", re.compile(r"^/v0/inboxes/[^/]+/drafts/[^/]+$")),
                   ("PUT", re.compile(r"^/v0/inboxes/[^/]+/drafts/[^/]+$"))]
_AM_SAFE_WRITES = [("DELETE", re.compile(r"^/v0/inboxes/[^/]+/drafts/[^/]+$")),
                   ("PATCH", re.compile(r"^/v0/inboxes/[^/]+/messages/[^/]+$")),
                   ("PATCH", re.compile(r"^/v0/inboxes/[^/]+/threads/[^/]+$"))]
_AM_ATTACHMENT = re.compile(r"^/v0/inboxes/([^/]+)/messages/([^/]+)/(?:attachments/[^/]+|raw)$")
_AM_THREAD_ATTACHMENT = re.compile(r"^/v0/(?:inboxes/[^/]+/)?threads/[^/]+/attachments(?:/|$)")
_AM_HEADER_OK = re.compile(r"^(?:X-[A-Za-z0-9-]{1,64}|In-Reply-To|References)$", re.I)
_GM_SEND = re.compile(r"^/(upload/)?gmail/v1/users/[^/]+/(messages|drafts)/send$")
_GM_IMPORT = re.compile(r"^/(?:upload/)?gmail/v1/users/[^/]+/messages/(?:import|insert)$")
_GM_SETTINGS = re.compile(r"^/gmail/v1/users/[^/]+/settings/(forwardingAddresses|autoForwarding|delegates|sendAs|filters)(?:/|$)")
_HIDDEN_FIELDS = ("text", "html", "extracted_text", "extracted_html", "preview", "subject")


def email_admission(payload: dict[str, Any], timeout: float = 20) -> dict[str, Any]:
    request = urllib.request.Request(EMAIL_ADMISSION_URL, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
    # Never use environment proxies for the firewall-local admission service.
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=timeout) as response:
        result = json.load(response)
    if result.get("ok") is not True:
        raise ValueError("email admission refused")
    return result


def is_googleapis(host: str) -> bool:
    host = host.lower()
    return host == "googleapis.com" or host.endswith(".googleapis.com")


def _json_body(flow: http.HTTPFlow) -> dict[str, Any] | None:
    raw = flow.request.raw_content or b""
    if len(raw) > 40 * 1024 * 1024:
        return None
    try:
        body = json.loads(flow.request.get_content() or b"{}")
    except (ValueError, UnicodeError):
        return None
    return body if isinstance(body, dict) else None


_HEADER_LIMIT = 262144


def _header_block(message: bytes) -> str | None:
    """The header block of an RFC 822 message, without its body. Never the body. None when the
    headers do not end within the limit: a recipient past it would go unchecked."""
    end = re.search(rb"\r?\n\r?\n", message[:_HEADER_LIMIT])
    if end:
        head = message[:end.start()]
    elif len(message) <= _HEADER_LIMIT:
        head = message  # headers only, no body
    else:
        return None
    return head.decode("utf-8", errors="replace")


def _b64url(value: Any) -> bytes | None:
    if not isinstance(value, str) or len(value) > 50 * 1024 * 1024:
        return None
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError):
        return None


def _multipart_message(flow: http.HTTPFlow) -> bytes | None:
    """The message/rfc822 part of a Gmail multipart upload."""
    import email.parser
    import email.policy
    ctype = flow.request.headers.get("content-type", "")
    if not ctype.lower().startswith("multipart/"):
        return None
    try:
        parsed = email.parser.BytesParser(policy=email.policy.compat32).parsebytes(
            b"Content-Type: " + ctype.encode("latin-1") + b"\r\n\r\n" + (flow.request.get_content() or b""))
    except (ValueError, UnicodeError):
        return None
    if not parsed.is_multipart():
        return None
    parts = [p for p in parsed.get_payload() if p.get_content_type() == "message/rfc822"]
    if len(parts) != 1:
        return None
    payload = parts[0].get_payload(decode=False)
    if isinstance(payload, list):  # compat32 parses an rfc822 part into a nested message
        return payload[0].as_bytes() if payload else None
    return payload.encode("latin-1", errors="replace") if isinstance(payload, str) else None


def email_send_request(flow: http.HTTPFlow, vm_id: str | None) -> dict[str, Any] | str | None:
    """
    What a send looks like to the email rules: a reserve payload, a refusal reason (str), or None
    when the request is not an email send at all.
    """
    from urllib.parse import unquote
    host = flow.request.pretty_host.lower()
    method = flow.request.method.upper()
    path = flow.request.path.split("?", 1)[0]
    if host == AGENTMAIL_API and method in ("POST", "PUT", "PATCH", "DELETE"):
        m_send, m_op, m_draft = _AM_SEND.match(path), _AM_MSG_OP.match(path), _AM_DRAFT_SEND.match(path)
        drafting = any(m == method and r.match(path) for m, r in _AM_DRAFT_WRITE)
        if not (m_send or m_op or m_draft):
            if any(m == method and r.match(path) for m, r in _AM_SAFE_WRITES):
                return None
            if not drafting:
                return "unknown_write"
        body = _json_body(flow) if method != "DELETE" else {}
        if body is None:
            return "unreadable_recipients"
        headers = body.get("headers")
        if headers is not None and (not isinstance(headers, dict) or not all(isinstance(k, str) and _AM_HEADER_OK.match(k) for k in headers)):
            return "headers_refused"
        if drafting:
            # A draft that sends itself later would skip every check made at send time.
            if any("send_at" in k.lower() or "sendat" in k.lower() or "schedul" in k.lower() for k in body):
                return "scheduled_send"
            m_edit = re.match(r"^/v0/inboxes/([^/]+)/drafts/([^/]+)$", path)
            if m_edit:
                return {"action": "email.draft_write", "provider": "agentmail", "inboxId": unquote(m_edit.group(1)), "draftId": unquote(m_edit.group(2))}
            return None  # Recipients are checked when the draft is sent, from the draft itself.
        payload: dict[str, Any] = {"action": "email.reserve", "vmId": vm_id or "", "provider": "agentmail",
                                   "to": body.get("to"), "cc": body.get("cc"), "bcc": body.get("bcc")}
        if m_send:
            payload.update(inboxId=unquote(m_send.group(1)), op="send")
        elif m_op:
            payload.update(inboxId=unquote(m_op.group(1)), messageId=unquote(m_op.group(2)),
                           op={"reply": "reply", "reply-all": "reply_all", "forward": "forward"}[m_op.group(3)])
            if m_op.group(3) == "reply" and body.get("reply_all") is True:
                payload["op"] = "reply_all"
        else:
            payload.update(inboxId=unquote(m_draft.group(1)), draftId=unquote(m_draft.group(2)), op="draft_send")
        return payload
    if not is_googleapis(host):
        return None
    # Match on the path Google acts on: decoded, slashes collapsed, no trailing slash.
    path = re.sub(r"/+", "/", unquote(path))
    if len(path) > 1:
        path = path.rstrip("/")
    if path.startswith("/batch/gmail/") or (path.startswith("/batch") and b"/gmail/v1/" in (flow.request.get_content() or b"")):
        return "unsupported_upload"
    if method != "GET" and _GM_IMPORT.match(path):
        return "unknown_write"
    settings = _GM_SETTINGS.match(path)
    if settings and method != "GET":
        if settings.group(1) != "filters":
            return "forwarding_refused"
        body = _json_body(flow)
        if method == "POST" and (body is None or (body.get("action") or {}).get("forward")):
            return "forwarding_refused"
        return None
    m_gdraft = re.match(r"^/(?:upload/)?gmail/v1/users/[^/]+/drafts/([^/]+)$", path)
    if m_gdraft and method in ("PUT", "PATCH", "DELETE"):
        return {"action": "email.draft_write", "provider": "gmail", "draftId": m_gdraft.group(1)}
    m = _GM_SEND.match(path)
    if not m or method != "POST":
        return None
    upload, kind = bool(m.group(1)), m.group(2)
    payload = {"action": "email.reserve", "vmId": vm_id or "", "provider": "gmail",
               "op": "send" if kind == "messages" else "draft_send"}
    if upload:
        if kind == "drafts":
            return "unsupported_upload"
        upload_type = flow.request.query.get("uploadType", "")
        if upload_type == "media":
            message = flow.request.get_content() or b""
        elif upload_type == "multipart":
            message = _multipart_message(flow)
        else:
            return "unsupported_upload"
        if not message:
            return "unreadable_recipients"
        payload["head"] = _header_block(message)
        return payload if payload["head"] is not None else "unreadable_recipients"
    body = _json_body(flow)
    if body is None:
        return "unreadable_recipients"
    if kind == "messages":
        message = _b64url(body.get("raw"))
        if not message:
            return "unreadable_recipients"
        payload["head"] = _header_block(message)
        return payload if payload["head"] is not None else "unreadable_recipients"
    inner = body.get("message") if isinstance(body.get("message"), dict) else {}
    if inner.get("raw") is not None:
        message = _b64url(inner.get("raw"))
        if not message:
            return "unreadable_recipients"
        payload["head"] = _header_block(message)
        if payload["head"] is None:
            return "unreadable_recipients"
    elif isinstance(body.get("id"), str):
        payload["draftId"] = body["id"]
    else:
        return "unreadable_recipients"
    return payload


def _email_refuse(flow: http.HTTPFlow, reason: str) -> None:
    flow.response = http.Response.make(
        403, json.dumps({"error": "email_refused", "reason": reason, "message": _EMAIL_REASONS.get(reason, "Email refused by the firewall.")}),
        {"Content-Type": "application/json"})
    flow.metadata["cc_effect"] = "block"
    flow.metadata["cc_rule"] = "email"
    rec = _http_record(flow, "block")
    rec.update({"status": 403, "email_reason": reason})
    _log_once(flow, rec)


async def email_outbound(flow: http.HTTPFlow, vm_id: str | None) -> bool:
    """True when the request may go on (counted if it is a send); False when a response was set."""
    try:
        request = email_send_request(flow, vm_id)
    except Exception:  # noqa: BLE001 — anything unexpected about a send refuses it
        request = "unreadable_recipients"
    if request is None:
        return True
    if isinstance(request, str):
        _email_refuse(flow, request)
        return False
    try:
        result = await asyncio.to_thread(email_admission, request)
    except (OSError, ValueError):
        _email_refuse(flow, "email_rules_unavailable")
        return False
    if request.get("action") == "email.draft_write":
        if result.get("draftOk") is True:
            return True
        _email_refuse(flow, "draft_busy")
        return False
    decision = result.get("decision")
    if decision == "allow" and isinstance(result.get("id"), str) and re.fullmatch(r"[a-f0-9]{48}", result["id"]):
        flow.metadata["cc_email_reservation"] = result["id"]
        return True
    if decision == "ask" and isinstance(result.get("asks"), list) and result["asks"]:
        asks = [a for a in result["asks"] if isinstance(a, dict) and isinstance(a.get("scope"), str) and isinstance(a.get("summary"), str)]
        pids = []
        for ask in asks[:20]:
            pid = permission_id_for(ask["scope"])
            pids.append(pid)
            record_pending(pid, {"permission_id": pid, "scope": ask["scope"], "summary": ask["summary"][:300],
                                 "kind": "email_recipient", "host": flow.request.pretty_host, "method": flow.request.method,
                                 "path": redact_path(flow.request.path, flow.request.pretty_host)})
        flow.response = http.Response.make(
            PERMISSION_STATUS,
            json.dumps({"permission_id": pids[0] if pids else None, "permission_ids": pids, "reason": "email_recipient_needs_approval",
                        "summary": "; ".join(a["summary"] for a in asks[:20]),
                        "message": "The owner has been asked to approve this recipient. Tell the person, and send again once it is approved.",
                        "expires_at": int(time.time()) + PERMISSION_TTL}),
            {"Content-Type": "application/json"})
        flow.metadata["cc_effect"] = "require_permission"
        flow.metadata["cc_rule"] = "email"
        rec = _http_record(flow, "require_permission")
        rec.update({"permission_id": pids[0] if pids else None, "status": PERMISSION_STATUS})
        _log_once(flow, rec)
        return False
    _email_refuse(flow, str(result.get("reason") or "not_allowed"))
    return False


def email_settle(flow: http.HTTPFlow) -> None:
    reservation = flow.metadata.get("cc_email_reservation")
    if not reservation:
        return
    try:
        response = flow.response
        rejected = response is not None and 400 <= response.status_code < 500
        email_admission({"action": "email.settle", "id": reservation, "rejected": rejected}, timeout=5)
    except (OSError, ValueError):
        pass  # An unsettled reservation counts after ten minutes (EmailRulesFirewall.sweep).


async def agentmail_attachment_allowed(flow: http.HTTPFlow) -> bool:
    """Attachment and raw reads carry no message, so the firewall checks the message they belong to."""
    from urllib.parse import unquote
    if flow.request.pretty_host.lower() != AGENTMAIL_API or flow.request.method.upper() != "GET":
        return True
    path = flow.request.path.split("?", 1)[0]
    if _AM_THREAD_ATTACHMENT.match(path):
        return False  # Read attachments through their message, which the firewall can check.
    m = _AM_ATTACHMENT.match(path)
    if not m:
        return True
    try:
        result = await asyncio.to_thread(email_admission, {"action": "email.inbound", "provider": "agentmail", "inboxId": unquote(m.group(1)),
                                                           "items": [{"kind": "ref", "message_id": unquote(m.group(2))}]})
        return (result.get("actions") or [{}])[0].get("action") == "keep"
    except (OSError, ValueError, IndexError, AttributeError):
        return False


def _is_message(d: Any) -> bool:
    return isinstance(d, dict) and isinstance(d.get("message_id"), str) and isinstance(d.get("inbox_id"), str) and "thread_id" in d


def _is_thread(d: Any) -> bool:
    return isinstance(d, dict) and isinstance(d.get("thread_id"), str) and isinstance(d.get("inbox_id"), str) and "message_id" not in d


def _hide_message(m: dict[str, Any]) -> None:
    """Mark a message the agent asked for by id as blocked, and empty everything it says."""
    labels = m.get("labels") if isinstance(m.get("labels"), list) else []
    m["labels"] = labels + (["blocked"] if "blocked" not in labels else [])
    for field in _HIDDEN_FIELDS:
        if field in m:
            m[field] = ""
    for field in ("attachments", "headers", "authentication_results"):
        if field in m:
            m[field] = [] if field == "attachments" else {}


def agentmail_filter(doc: Any, decide) -> Any:
    """
    Apply the firewall's keep/strip/hide answer to an AgentMail JSON response. `decide(items)`
    takes [(inbox_id, item)] and returns one action per item. A message asked for by id is kept
    but marked blocked and emptied (the channel then settles it for good); list and thread
    members are dropped.
    """
    targets: list[tuple[str, dict[str, Any], dict[str, Any]]] = []  # (inbox, item, original)

    def message_item(m: dict[str, Any]) -> dict[str, Any]:
        return {"kind": "message", **{k: v for k, v in m.items() if k in ("message_id", "from", "labels", "authentication_results", "headers", "text", "html", "extracted_text", "extracted_html")}}

    def collect(container: list[Any]) -> None:
        for item in container:
            if _is_message(item):
                targets.append((item["inbox_id"], message_item(item), item))
            elif _is_thread(item):
                if isinstance(item.get("messages"), list):
                    collect(item["messages"])
                targets.append((item["inbox_id"], {"kind": "thread", "senders": item.get("senders"), "labels": item.get("labels")}, item))

    if _is_message(doc) or _is_thread(doc):
        collect([doc])
    elif isinstance(doc, dict):
        for key in ("messages", "threads"):
            if isinstance(doc.get(key), list):
                collect(doc[key])
    if not targets:
        return doc
    actions = decide([(inbox, item) for inbox, item, _ in targets])
    verdict = {id(orig): (a.get("action") if isinstance(a, dict) else "hide") for (_, _, orig), a in zip(targets, actions)}

    def prune(container: list[Any]) -> list[Any]:
        kept = []
        for item in container:
            act = verdict.get(id(item), "keep")
            if _is_thread(item) and isinstance(item.get("messages"), list):
                item["messages"] = prune(item["messages"])
                if not item["messages"] and act != "hide":
                    item["subject"] = ""
            if act == "hide":
                continue
            if act == "strip" or _is_thread(item):
                if "preview" in item:
                    item["preview"] = ""
            kept.append(item)
        return kept

    if _is_message(doc):
        if verdict.get(id(doc)) == "hide":
            _hide_message(doc)
        elif verdict.get(id(doc)) == "strip" and "preview" in doc:
            doc["preview"] = ""
        return doc
    if _is_thread(doc):
        pruned = prune([doc])
        if not pruned:
            doc["messages"] = []
            for field in ("preview", "subject"):
                if field in doc:
                    doc[field] = ""
        return doc
    for key in ("messages", "threads"):
        if isinstance(doc.get(key), list):
            before = len(doc[key])
            doc[key] = prune(doc[key])
            if isinstance(doc.get("count"), int):
                doc["count"] = max(0, doc["count"] - (before - len(doc[key])))
    return doc


def _decide_via_admission(items: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    """One admission call per inbox. Fails closed: no answer hides everything."""
    by_inbox: dict[str, list[int]] = {}
    for i, (inbox, _) in enumerate(items):
        by_inbox.setdefault(inbox, []).append(i)
    out: list[dict[str, Any]] = [{"action": "hide"}] * len(items)
    for inbox, idx in by_inbox.items():
        for chunk in (idx[i:i + 200] for i in range(0, len(idx), 200)):
            try:
                result = email_admission({"action": "email.inbound", "provider": "agentmail", "inboxId": inbox,
                                          "items": [items[i][1] for i in chunk]}, timeout=5)
                acts = result.get("actions")
                if isinstance(acts, list) and len(acts) == len(chunk):
                    for i, a in zip(chunk, acts):
                        out[i] = a if isinstance(a, dict) else {"action": "hide"}
            except (OSError, ValueError):
                pass
    return out


def agentmail_response(flow: http.HTTPFlow) -> None:
    """Filter what an AgentMail API response shows the agent, before it leaves the firewall."""
    if flow.request.pretty_host.lower() != AGENTMAIL_API or flow.response is None or not (200 <= flow.response.status_code < 300):
        return
    if "json" not in flow.response.headers.get("content-type", "").lower():
        return
    try:
        doc = json.loads(flow.response.get_content() or b"null")
    except (ValueError, UnicodeError):
        flow.response = http.Response.make(502, '{"error":"unreadable_response"}', {"Content-Type": "application/json"})
        return
    filtered = agentmail_filter(doc, _decide_via_admission)
    flow.response.set_content(json.dumps(filtered).encode())


def _agentmail_ws_decide(message) -> bool:
    """Whether one server-to-client frame may reach the agent. Blocking: run it off the event loop."""
    if message.from_client:
        return True
    try:
        event = json.loads(message.content)
    except (ValueError, TypeError, UnicodeError):
        return False
    if not isinstance(event, dict) or event.get("type") != "event":
        return True
    kind = str(event.get("event_type") or event.get("eventType") or "")
    if not kind.startswith("message.received"):
        return True
    msg = event.get("message")
    if kind != "message.received" or not _is_message(msg):
        return False
    return _decide_via_admission([(msg["inbox_id"], {"kind": "message", **msg})])[0].get("action") == "keep"


_email_tasks: set = set()


def _off_loop(flow, work) -> bool:
    """
    Pause `flow`, run the blocking `work()` in a thread, resume. Returns False when there is no
    running event loop (a direct call from a test), so the caller runs `work()` itself. The admission
    answer can take a moment; holding the event loop for it would stall every agent's traffic.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return False
    flow.intercept()

    async def run():
        try:
            await asyncio.to_thread(work)
        finally:
            flow.resume()

    task = loop.create_task(run())
    _email_tasks.add(task)
    task.add_done_callback(_email_tasks.discard)
    return True


def agentmail_ws_message(flow) -> None:
    """A received-mail event over AgentMail's WebSocket reaches the agent only if the rules keep it."""
    if not flow.websocket or not flow.websocket.messages:
        return
    message = flow.websocket.messages[-1]

    def work():
        try:
            if not _agentmail_ws_decide(message):
                message.drop()
        except Exception:  # noqa: BLE001 — anything unexpected drops the frame
            message.drop()
        finally:
            # Never keep mail content on the flow.
            flow.websocket.messages.clear()

    if not _off_loop(flow, work):
        work()


def phone_credential(flow, vm_id):
    if flow.request.pretty_host.lower() != "api.twilio.com":
        return None
    for c in credentials_for("api.twilio.com", vm_id):
        if c.get("phone") and c.get("vm_id") == vm_id and vm_id:
            return c
    return None


def phone_authorized(flow, cred) -> bool:
    import base64
    from urllib.parse import parse_qsl, urlencode
    if not cred or flow.request.pretty_host.lower() != "api.twilio.com" or (getattr(flow.client_conn, "sni", None) or "").lower() != "api.twilio.com" or flow.request.scheme != "https" or flow.request.port != 443:
        return False
    # Transparent requests carry a destination IP. Pin routing to the verified
    # TLS/Host name before any secret can be inserted, never to that client IP.
    flow.request.host = "api.twilio.com"
    config = cred["phone"]
    headers = flow.request.headers.get_all("authorization")
    if len(headers) != 1 or not headers[0].startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(headers[0][6:], validate=True).decode("ascii")
        if decoded != config["account_sid"] + ":" + cred["placeholder"]:
            return False
        prefix = "/2010-04-01/Accounts/" + config["account_sid"] + "/Calls"
        path = flow.request.path
        create = path == prefix + ".json"
        item = re.fullmatch(re.escape(prefix) + r"/CA[0-9a-fA-F]{32}\.json", path)
        if flow.request.method == "GET":
            return bool(item)
        if flow.request.method != "POST" or not (create or item):
            return False
        if not flow.request.headers.get("content-type", "").lower().startswith("application/x-www-form-urlencoded"):
            return False
        body = (flow.request.raw_content or b"").decode("utf-8", errors="strict")
        if len(body) > 65536 or re.search(r"%(?![0-9a-fA-F]{2})", body):
            return False
        pairs = parse_qsl(body, keep_blank_values=True, strict_parsing=True, errors="strict", max_num_fields=128)
        # Twilio's plugin repeats StatusCallbackEvent, all other fields are scalar.
        fields = {}
        for k, v in pairs:
            if k in fields and k != "StatusCallbackEvent":
                return False
            fields[k] = v
        if create:
            if set(fields) - {"To", "From", "Url", "Method", "StatusCallback", "StatusCallbackMethod", "StatusCallbackEvent", "Timeout", "TimeLimit"}:
                return False
            if fields.get("From") != config["from_number"] or not re.fullmatch(r"\+[1-9]\d{6,14}", fields.get("To", "")):
                return False
            if not phone_hook_url(fields.get("Url", ""), config["hook_url"]) or not phone_hook_url(fields.get("StatusCallback", ""), config["hook_url"]):
                return False
            if fields.get("Method", "POST") != "POST" or fields.get("StatusCallbackMethod", "POST") != "POST":
                return False
            if any(v not in ("initiated", "ringing", "answered", "completed") for k, v in pairs if k == "StatusCallbackEvent"):
                return False
            if fields.get("Timeout") and not re.fullmatch(r"[1-9]|[12][0-9]|30", fields["Timeout"]):
                return False
            # Always set the provider's hard duration for outbound calls.
            limit = config.get("max_duration", 300)
            if type(limit) is not int:
                return False
            limit = max(60, min(3600, limit))
            if not 60 <= limit <= 3600:
                return False
            pairs = [(k, v) for k, v in pairs if k != "TimeLimit"] + [("TimeLimit", str(limit))]
            flow.request.set_text(urlencode(pairs))
        else:
            if fields == {"Status": "completed"}:
                return True
            if set(fields) != {"Twiml"} or not phone_twiml_allowed(fields["Twiml"], config["hook_url"]):
                return False
        return True
    except (ValueError, UnicodeError, KeyError):
        return False


def phone_admission(payload):
    import urllib.request
    request = urllib.request.Request("http://127.0.0.1:8791/", data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
    # Never use environment proxies for the firewall-local admission service.
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=2) as response:
        result = json.load(response)
    if result.get("ok") is not True:
        raise ValueError("phone admission refused")
    return result


async def phone_reserve(flow, cred):
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
    if flow.request.method != "POST" or not flow.request.path.endswith("/Calls.json"):
        return True
    try:
        result = await asyncio.to_thread(phone_admission, {"action": "reserve", "vmId": cred["vm_id"], "placeholder": cred["placeholder"]})
        reservation = result["id"]
        if not isinstance(reservation, str) or not re.fullmatch(r"[a-f0-9]{48}", reservation):
            return False
        flow.metadata["cc_phone_reservation"] = reservation
        pairs = list(flow.request.urlencoded_form.items(multi=True))
        updated = []
        for key, value in pairs:
            if key in ("Url", "StatusCallback"):
                u = urlsplit(value)
                query = [(k, v) for k, v in parse_qsl(u.query) if k != "ccCall"]
                value = urlunsplit((u.scheme, u.netloc, u.path, urlencode(query + [("ccCall", reservation)]), ""))
            updated.append((key, value))
        flow.request.set_text(urlencode(updated))
        return True
    except (OSError, ValueError, KeyError):
        return False


def phone_settle(flow):
    reservation = flow.metadata.get("cc_phone_reservation")
    if not reservation:
        return
    try:
        # An uncertain transport result retains its slot until the maximum call lifetime.
        response = flow.response
        if response is None:
            return
        rejected = 400 <= response.status_code < 500
        sid = None
        if 200 <= response.status_code < 300:
            sid = json.loads(response.content).get("sid")
        phone_admission({"action": "settle", "id": reservation, "sid": sid, "rejected": rejected})
    except (OSError, ValueError, TypeError):
        pass


# ----- website logins (docs/plans/website-credentials.md) ----------------------
#
# An agent types a login's placeholder into a sign-in form; the real password goes in here, on the
# way out, only to the login's own sites (`allowed_hosts`) and only for that agent. The placeholder
# is made of letters, digits and `-_.` (packages/mitm-agent/src/logins-placeholder.ts), so it reads
# the same in a form, a query string, JSON, or JSON inside a form: finding it is a search for the
# literal text, and only the replacement has to be escaped for where it sits.

LOGIN_TRIPWIRE_RULE = "login_tripwire"
# Responses larger than this are not searched for an echoed password.
LOGIN_REDACT_MAX = 2 * 1024 * 1024
# A placeholder shorter than this (a PIN, a short password) is found only standing alone.
LOGIN_SHORT = 8
# After a swap, responses to that agent from the login's sites are searched for the password for
# this long, so an echo on a later response (the redirect target, an error page) is taken out too.
LOGIN_ECHO_WINDOW_S = 600
# How many recent swaps are remembered per agent, and for how many agents.
LOGIN_ECHO_MAX = 16
LOGIN_ECHO_AGENTS_MAX = 256
# Request headers the browser fills in by itself from the page it is on. A sign-in form sent with
# GET puts the placeholder in the page's URL, and from there into these on every request the page
# makes, to any host: they say where the browser is, not what the agent sent.
_NAVIGATION_HEADERS = frozenset({"referer", "origin", "ping-from", "ping-to"})
_PLACEHOLDER_NEIGHBOUR = r"A-Za-z0-9_.\-"

# vm_id -> [(expires_at, secret, placeholder, allowed_hosts)], newest last.
_login_echoes: dict[str | None, list[tuple[float, str, str, tuple[str, ...]]]] = {}


def _json_levels(text: str, at: int) -> int:
    """How many JSON strings the text at `at` sits inside, read off the quote that opens it.

    `"PH"` is one string, `\\"PH\\"` (a JSON string inside a JSON string, as Google's sign-in
    sends it inside a form field) two, and so on: the quote of a string k levels deep has
    2^(k-1) - 1 backslashes in front of it. The search stops at a line break, which a JSON string
    cannot hold, so a multipart part or a plain form value counts as no string at all. It reads the
    nearest quote, so a password typed after an escaped quote in the same string is escaped once too
    often; sign-in forms send the password as a value of its own."""
    i = at - 1
    while i >= 0 and text[i] not in "\"\r\n":
        i -= 1
    if i < 0 or text[i] != '"':
        return 0
    n = 0
    j = i - 1
    while j >= 0 and text[j] == "\\":
        n += 1
        j -= 1
    return (n + 1).bit_length()


def _json_escape(value: str, levels: int) -> str:
    for _ in range(levels):
        value = json.dumps(value, ensure_ascii=False)[1:-1]
    return value


def _xml_escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")


def _in_cdata(text: str, at: int) -> bool:
    return text.rfind("<![CDATA[", 0, at) > text.rfind("]]>", 0, at)


def _is_json(text: str) -> bool:
    s = text.strip()
    if not s or s[0] not in "[{\"":
        return False
    try:
        json.loads(s)
    except ValueError:
        return False
    return True


def _body_kind(ctype: str, body: str) -> str:
    """How the password has to be written into this body: `json`, `xml`, `form` or `raw`.

    A JSON body sent as `text/plain` (a common way to skip a CORS preflight) is still JSON."""
    c = ctype.lower()
    if "json" in c:
        return "json"
    if "xml" in c:
        return "xml"
    if c.startswith("application/x-www-form-urlencoded"):
        return "form"
    if c.startswith("multipart/"):
        return "raw"
    if body.lstrip().startswith("<?xml"):
        return "xml"
    return "json" if _is_json(body) else "raw"


def swap_login_text(text: str, placeholder: str, secret: str, kind: str = "raw") -> str:
    """Every occurrence of `placeholder` in `text`, replaced by `secret` escaped for where it sits:
    for `json`, as many times as the JSON strings around it; for `xml`, as an XML entity (or split
    out of a CDATA section); otherwise as it is."""
    out: list[str] = []
    start = 0
    for m in _placeholder_re(placeholder).finditer(text):
        out.append(text[start:m.start()])
        if kind == "json":
            out.append(_json_escape(secret, _json_levels(text, m.start())))
        elif kind == "xml":
            out.append(secret.replace("]]>", "]]]]><![CDATA[>") if _in_cdata(text, m.start()) else _xml_escape(secret))
        else:
            out.append(secret)
        start = m.end()
    out.append(text[start:])
    return "".join(out)


def _value_kind(value: str) -> str:
    """A form field or query value: JSON when it parses as JSON (Google's `f.req`), else as it is."""
    return "json" if _is_json(value) else "raw"


def swap_login_form(body: str, placeholder: str, secret: str) -> str:
    """A form body: only the fields that hold the placeholder are decoded, swapped and re-encoded,
    so every other byte stays exactly as the page sent it."""
    from urllib.parse import quote_plus, unquote_plus
    parts = body.split("&")
    for i, part in enumerate(parts):
        key, eq, value = part.partition("=")
        if not eq:
            continue
        decoded = unquote_plus(value)
        if _placeholder_re(placeholder).search(decoded):
            parts[i] = f"{key}={quote_plus(swap_login_text(decoded, placeholder, secret, _value_kind(decoded)), safe='*')}"
    return "&".join(parts)


def _login_entries() -> list[dict[str, Any]]:
    return [c for c in _creds.get() if c.get("login_id") and c.get("placeholder")]


def _placeholder_re(placeholder: str) -> "re.Pattern[str]":
    """How a placeholder is found. A long one with letters is unmistakable anywhere. An all-digit
    one (for an all-digit password) would also match inside any longer number, so it has to stand
    alone among digits. A short one (a PIN, a 4-7 character password) has to stand alone as a
    value: no letter, digit or `-_.` on either side, so it is not found inside a longer word, a
    longer number or a decimal."""
    if len(placeholder) < LOGIN_SHORT:
        n = _PLACEHOLDER_NEIGHBOUR
        return re.compile(f"(?<![{n}])" + re.escape(placeholder) + f"(?![{n}])")
    if placeholder.isdigit():
        return re.compile(r"(?<![0-9])" + placeholder + r"(?![0-9])")
    return re.compile(re.escape(placeholder))


def _basic_credentials(value: str) -> str | None:
    """The `user:password` of an HTTP Basic `Authorization` value, or None."""
    if value[:6].lower() != "basic ":
        return None
    try:
        return base64.b64decode(value[6:].strip(), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def _integration_host(host: str, vm_id: str | None) -> bool:
    """A host the firewall swaps one of this agent's OWN integration credentials into: its model
    provider, its chat channels, its mail. The agent's conversation travels there, and a placeholder
    it was handed is part of that conversation (a tool result, a message it writes), so the tripwire
    must not fire on it. The placeholder carries no secret, so nothing is lost by letting it pass.

    Only the entries the firewall's integration modules write count (they name the host they serve
    in `match_domain`). A custom secret (`secret_name`) can carry whatever pattern the owner typed,
    `*.amazonaws.com` say, and is not a conversation channel: it does not switch the alarm off."""
    return any(
        not c.get("login_id") and not c.get("secret_name") and c.get("match_domain") not in (None, "", "*")
        for c in credentials_for(host, vm_id)
    )


def login_tripwire(flow: http.HTTPFlow, vm_id: str | None = None) -> dict[str, Any] | None:
    """A login whose placeholder this request carries to a host that is not one of its sites.

    The swap is what keeps a password where it belongs; this is the alarm. A placeholder going
    anywhere else means the agent was talked into it (prompt injection, a look-alike domain), and the
    people running it should hear about it. The request is refused so the attempt is visible.

    It reads the URL, the body (both as sent and URL-decoded) and every header that can carry a
    credential. Not the navigation headers (`Referer`, `Origin`): the browser copies the page's URL
    into those by itself."""
    entries = _login_entries()
    if not entries:
        return None
    host = flow.request.pretty_host
    if CONTROL_PLANE_HOST and host_matches(CONTROL_PLANE_HOST, host):
        return None
    if _integration_host(host, vm_id):
        return None
    from urllib.parse import unquote, unquote_plus
    try:
        body = flow.request.get_text(strict=False) or ""
    except ValueError:
        body = ""
    url = flow.request.path
    texts = [url, body]
    if "%" in url:
        texts.append(unquote(url))
    if "%" in body or "+" in body:
        texts.append(unquote_plus(body))
    for name, value in flow.request.headers.items(multi=True):
        if name.lower() in _NAVIGATION_HEADERS:
            continue
        texts.append(value)
        if name.lower() in ("authorization", "proxy-authorization"):
            decoded = _basic_credentials(value)
            if decoded is not None:
                texts.append(decoded)
    for c in entries:
        found = _placeholder_re(c["placeholder"])
        if not any(found.search(t) for t in texts):
            continue
        if any(secret_host_matches(pattern, host) for pattern in c.get("allowed_hosts", [])):
            continue
        return c
    return None


def _login_destination_ok(flow: http.HTTPFlow, host: str) -> bool:
    """The swap may only go to the name the client asked for (same rule as custom secrets): the TLS
    names must match the host, and behind redsocks an IP authority is re-pointed at that name."""
    authority = flow.request.host.lower().rstrip(".")
    destination = host.lower().rstrip(".")
    client_sni = getattr(flow.client_conn, "sni", None)
    server_sni = getattr(flow.server_conn, "sni", None)
    if any(sni and sni.lower().rstrip(".") != destination for sni in (client_sni, server_sni)):
        return False
    if authority != destination:
        try:
            ipaddress.ip_address(authority)
        except ValueError:
            return False
        if flow.request.scheme != "https" or not client_sni:
            return False
        flow.request.host = host
        flow.server_conn = connection.Server(address=(host, flow.request.port), sni=host)
    return True


def _login_header_names(flow: http.HTTPFlow) -> list[str]:
    """The request headers a password may be swapped into: `Authorization` (HTTP Basic decoded and
    encoded again, any other scheme as it is) and custom `X-*` headers. Never `Cookie` or the
    navigation headers, which the browser fills in by itself."""
    return sorted({k.lower() for k in flow.request.headers.keys() if k.lower() == "authorization" or k.lower().startswith("x-")})


def _swap_login_header(name: str, value: str, placeholder: str, secret: str) -> str:
    found = _placeholder_re(placeholder)
    if name == "authorization":
        decoded = _basic_credentials(value)
        if decoded is not None:
            if not found.search(decoded):
                return value
            swapped = found.sub(lambda _: secret, decoded)
            return value[:6] + base64.b64encode(swapped.encode("utf-8")).decode("ascii")
    return found.sub(lambda _: secret, value)


def apply_login_swap(flow: http.HTTPFlow, cred: dict[str, Any], host: str) -> bool:
    from urllib.parse import quote
    placeholder = cred.get("placeholder") or ""
    secret = _secret_value(cred) or ""
    if not placeholder or not secret:
        return False
    try:
        body = flow.request.get_text(strict=False) or ""
    except ValueError:
        body = ""
    found = _placeholder_re(placeholder)
    path_only, sep, query_text = flow.request.path.partition("?")
    in_path = bool(found.search(path_only))
    in_query = any(found.search(v) for v in flow.request.query.values())
    in_body = bool(found.search(body))
    header_hits = [
        name for name in _login_header_names(flow)
        if any(_swap_login_header(name, v, placeholder, secret) != v for v in flow.request.headers.get_all(name))
    ]
    if not (in_body or in_query or in_path or header_hits):
        return False
    if not _login_destination_ok(flow, host):
        return False
    if in_path:
        # The placeholder's characters need no escaping in a path; the password does.
        flow.request.path = found.sub(lambda _: quote(secret, safe=""), path_only) + sep + query_text
    if in_query:
        for k in list(flow.request.query.keys()):
            values = flow.request.query.get_all(k)
            if any(found.search(v) for v in values):
                flow.request.query.set_all(k, [swap_login_text(v, placeholder, secret, _value_kind(v)) for v in values])
    for name in header_hits:
        # Per name, all values at once, so a repeated header keeps every value.
        flow.request.headers.set_all(name, [_swap_login_header(name, v, placeholder, secret) for v in flow.request.headers.get_all(name)])
    if in_body:
        kind = _body_kind(flow.request.headers.get("content-type") or "", body)
        if kind == "form":
            flow.request.set_text(swap_login_form(body, placeholder, secret))
        else:
            flow.request.set_text(swap_login_text(body, placeholder, secret, kind))
    return True


def _remember_login_echo(vm_id: str | None, cred: dict[str, Any], secret: str, placeholder: str) -> None:
    """Keep this swap for LOGIN_ECHO_WINDOW_S, so later responses to the agent from the login's
    sites are searched for the password too. Bounded per agent and in agents."""
    now = time.time()
    hosts = tuple(str(h) for h in cred.get("allowed_hosts", []))
    kept = [e for e in _login_echoes.get(vm_id, []) if e[0] > now and (e[1], e[2]) != (secret, placeholder)]
    kept.append((now + LOGIN_ECHO_WINDOW_S, secret, placeholder, hosts))
    _login_echoes.pop(vm_id, None)
    _login_echoes[vm_id] = kept[-LOGIN_ECHO_MAX:]
    while len(_login_echoes) > LOGIN_ECHO_AGENTS_MAX:
        _login_echoes.pop(next(iter(_login_echoes)))


def _recent_login_pairs(vm_id: str | None, host: str) -> list[tuple[str, str]]:
    now = time.time()
    entries = [e for e in _login_echoes.get(vm_id, []) if e[0] > now]
    if not entries:
        _login_echoes.pop(vm_id, None)
        return []
    _login_echoes[vm_id] = entries
    return [(secret, placeholder) for _, secret, placeholder, hosts in entries if any(secret_host_matches(p, host) for p in hosts)]


_TEXT_TYPES = ("text/", "json", "xml", "javascript", "x-www-form-urlencoded")


def _redact_text(text: str, pairs: list[tuple[str, str]]) -> str:
    from urllib.parse import quote, quote_plus
    for secret, placeholder in pairs:
        forms = {secret, quote(secret, safe=""), quote_plus(secret), _json_escape(secret, 1), _json_escape(secret, 2), json.dumps(secret)[1:-1], _xml_escape(secret)}
        # Longest first, so a JSON spelling is replaced whole before the plain value inside it.
        for form in sorted(forms, key=len, reverse=True):
            if not form or form not in text:
                continue
            # A form that starts or ends with a letter or digit is only replaced where it is not
            # part of a longer word or number: a short password must not eat into the page.
            left = r"(?<![A-Za-z0-9])" if form[0].isalnum() else ""
            right = r"(?![A-Za-z0-9])" if form[-1].isalnum() else ""
            text = re.sub(left + re.escape(form) + right, lambda _: placeholder, text)
    return text


def redact_login_response(flow: http.HTTPFlow) -> None:
    """A site that echoes the password back (rare, but it happens on error pages) must not hand the
    agent what the swap kept from it: the real value goes back to the placeholder. On the response
    to the request that carried the password, and for LOGIN_ECHO_WINDOW_S after it on every
    response to the same agent from that login's sites (a redirect target, the next page)."""
    if not flow.response:
        return
    pairs = list(flow.metadata.get("cc_login_pairs") or [])
    recent = _recent_login_pairs(flow.metadata.get("cc_vm_id"), flow.request.pretty_host) if _login_echoes else []
    pairs += [p for p in recent if p not in pairs]
    if not pairs:
        return
    # Per name, all values at once: assigning one would collapse repeated headers (Set-Cookie).
    for name in {k.lower() for k in flow.response.headers.keys()}:
        values = flow.response.headers.get_all(name)
        cleaned = [_redact_text(v, pairs) for v in values]
        if cleaned != values:
            flow.response.headers.set_all(name, cleaned)
    if not flow.response.raw_content or len(flow.response.raw_content) > LOGIN_REDACT_MAX:
        return
    ctype = (flow.response.headers.get("content-type") or "").lower()
    if not flow.metadata.get("cc_login_pairs") and not any(t in ctype for t in _TEXT_TYPES):
        # A later response is only searched when it is text: an image or a download is left whole.
        return
    try:
        text = flow.response.get_text(strict=False)
    except ValueError:
        return
    if text is None:
        return
    changed = _redact_text(text, pairs)
    if changed != text:
        flow.response.set_text(changed)


def apply_swaps(flow: http.HTTPFlow, vm_id: str | None = None) -> list[tuple[str, str]]:
    """Replace placeholders with real secrets, domain-scoped (+ vm-scoped with org fallback).
    Returns [(secret, placeholder)] pairs applied, for later log redaction."""
    host = flow.request.pretty_host
    applied: list[tuple[str, str]] = []

    for cred in credentials_for(host, vm_id):
        # Speech credentials may only be substituted after voice_request has
        # admitted this exact request. Do not let alternate header spellings or
        # additional placeholder occurrences reach the general swapper.
        if cred.get("speech") and flow.metadata.get("voice_credential") != cred.get("placeholder"):
            continue
        placeholder = cred.get("placeholder")
        secret = _secret_value(cred)
        if not placeholder or not secret:
            continue
        if cred.get("speech"):
            authorization = flow.request.headers.get("authorization", "")
            if authorization[:7].lower() == "bearer " and authorization[7:] == placeholder:
                flow.request.headers["authorization"] = "Bearer " + secret
                applied.append((secret, placeholder))
            continue
        if cred.get("login_id"):
            if apply_login_swap(flow, cred, host):
                applied.append((secret, placeholder))
                flow.metadata.setdefault("cc_login_swaps", []).append(str(cred.get("login_name") or "login"))
                flow.metadata.setdefault("cc_login_pairs", []).append((secret, placeholder))
                _remember_login_echo(vm_id, cred, secret, placeholder)
                log.info("[mitm] login=%s host=%s verdict=swapped", cred.get("login_id"), host)
            continue
        if cred.get("secret_name"):
            # Behind redsocks the routing authority is an IP. Require the client's
            # TLS name to match Host, then route to that approved name, never to the
            # caller's IP. Ordinary named authorities must also match Host exactly.
            authority = flow.request.host.lower().rstrip(".")
            destination = host.lower().rstrip(".")
            client_sni = getattr(flow.client_conn, "sni", None)
            server_sni = getattr(flow.server_conn, "sni", None)
            if any(sni and sni.lower().rstrip(".") != destination for sni in (client_sni, server_sni)):
                continue
            if authority != destination:
                try:
                    ipaddress.ip_address(authority)
                except ValueError:
                    continue
                if flow.request.scheme != "https" or not client_sni:
                    continue
                flow.request.host = host
                flow.server_conn = connection.Server(address=(host, flow.request.port), sni=host)
            hit = False
            for loc in cred.get("secret_locations", []):
                name = loc.get("name", "")
                if loc.get("kind") == "header":
                    prefix = loc.get("prefix", "")
                    # Compare the whole field, including prefix; never substitute a substring.
                    values = flow.request.headers.get_all(name)
                    changed = [prefix + secret if v == prefix + placeholder else v for v in values]
                    if values != changed:
                        flow.request.headers.set_all(name, changed)
                        hit = True
                elif loc.get("kind") == "query":
                    values = flow.request.query.get_all(name)
                    changed = [secret if v == placeholder else v for v in values]
                    if values != changed:
                        flow.request.query.set_all(name, changed)
                        hit = True
            if hit:
                applied.append((secret, placeholder))
                flow.metadata.setdefault("cc_secret_swaps", []).append(cred["secret_name"])
                log.info("[mitm] secret=%s host=%s verdict=swapped", cred["secret_name"], host)
            continue
        locations = cred.get("locations") or DEFAULT_LOCATIONS
        hit = False

        for loc in locations:
            if loc == "basic:authorization" and cred.get("phone"):
                if phone_authorized(flow, cred):
                    import base64
                    sid = cred["phone"]["account_sid"]
                    flow.request.headers["Authorization"] = "Basic " + base64.b64encode((sid + ":" + secret).encode()).decode()
                    hit = True
            elif loc.startswith("header:"):
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
            log.info(f"[mitm] credential swap for host={host} (tenant={TENANT})")

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


def redact_path(path: str, host: str = "") -> str:
    """The query-stripped path with any embedded credential replaced by a marker."""
    if host.lower() == "api.twilio.com":
        return "/".join(p if p in ("", "2010-04-01", "Accounts", "Calls", "Calls.json") else "{id}" for p in path.split("?", 1)[0].split("/"))
    if host.lower() in ("api.agentmail.to", "ws.agentmail.to"):
        # Only fixed resource names survive. IDs, addresses, search terms and arbitrary segments
        # must never reach activity storage or an AI review prompt.
        resources = {"v0", "inboxes", "messages", "threads", "drafts", "attachments", "send", "reply", "reply-all", "forward", "raw", "api-keys", "organizations"}
        return "/".join(part if part in resources or not part else "{id}" for part in path.split("?", 1)[0].split("/"))
    clean = _TELEGRAM_TOKEN_RE.sub("/bot<redacted>", path.split("?", 1)[0])
    # Meeting codes are secrets, including when embedded in a resource path.
    return re.sub(r"(?<![a-z])[a-z]{3}-[a-z]{4}-[a-z]{3}(?![a-z])", "<meeting>", clean)


def _base_record(flow, vm_id: str | None) -> dict[str, Any]:
    """Fields every traffic record carries. `flow_id` is mitmproxy's per-flow uuid: the shipper's
    dedupe key, so an at-least-once upload never double-counts a request."""
    return {"flow_id": flow.id, "ts": time.time(), "tenant": TENANT, "vm_id": vm_id}


def permission_path(path: str, host: str) -> str:
    redacted = redact_path(path, host)
    if host.lower() in ("api.agentmail.to", "ws.agentmail.to"):
        # Keep grants specific to the original resource without storing its address or ID.
        return redacted + "#" + hashlib.sha256(path.split("?", 1)[0].encode()).hexdigest()[:24]
    return redacted


def _http_record(flow: http.HTTPFlow, effect: str) -> dict[str, Any]:
    """One record per HTTP request. `path` is query-stripped so a credential swapped into a query
    string can never end up in a log line."""
    rec = _base_record(flow, flow.metadata.get("cc_vm_id"))
    rec.update({
        "host": flow.request.pretty_host, "method": flow.request.method,
        "path": redact_path(flow.request.path, flow.request.pretty_host), "effect": effect,
        "rule": flow.metadata.get("cc_rule"),
    })
    if flow.request.pretty_host.lower() == "api.twilio.com":
        try:
            destination = flow.request.urlencoded_form.get("To", "")
            rec["rule"] = "phone: outbound ****" + destination[-4:] if re.fullmatch(r"\+[1-9]\d{6,14}", destination) else "phone"
        except (ValueError, KeyError):
            rec["rule"] = "phone"
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
    if flow.request.pretty_host.lower() in ("api.agentmail.to", "ws.agentmail.to", "api.twilio.com"):
        return None  # Mail content never goes to the judge or its remote model provider.
    if not AI_JUDGE_URL:
        return None
    raw_path = flow.request.path
    query = raw_path.split("?", 1)[1] if "?" in raw_path else ""
    payload = {
        "rule": rule.get("name") or rule.get("match_domain") or "",
        "vm_id": vm_id,
        "method": flow.request.method,
        "host": flow.request.pretty_host,
        "path": redact_path(raw_path, flow.request.pretty_host)[:200],
        "query_keys": sorted({kv.split("=", 1)[0] for kv in query.split("&") if kv})[:20],
        "content_type": (flow.request.headers.get("content-type") or "")[:100] or None,
        "body_start": _body_start(flow),
        "recent": list(_recent[vm_id]),
        # The rule's note for the AI: the approval policy on an Ask rule, extra instructions on an
        # Allow rule. Written by the org admin; the judge puts it in its questions, not the state.
        "policy": rule.get("ai_policy"),
        **({"mode": "approve", **approve} if approve else {"mode": "review"}),
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


# Meet media grants are written only by mitm-agent, never copied from SaaS rules.
# Reviewed Google network policy, 2026-10-02. No IPv6, UDP or ICE TCP/19305.
MEETING_MEDIA_PATH = os.environ.get("MITM_MEETING_MEDIA_PATH", os.path.join(os.path.dirname(RULES_PATH), "meeting-media.json"))
MEETING_MEDIA_RANGES = {
    "meet.turns.goog": tuple(map(ipaddress.ip_network, ("142.250.82.0/24",))),
    "workspace.turns.goog": tuple(map(ipaddress.ip_network, ("74.125.250.0/24", "74.125.247.128/32"))),
}
MEETING_MAX_BYTES = 512 * 1024 * 1024
MEETING_MAX_SECONDS = 4 * 60 * 60
MEETING_MAX_CONNECTIONS = 8
MEETING_PROXY_STARTED = time.time()
_media_usage: dict[str, dict[str, Any]] = {}


def meeting_leases() -> dict[str, Any]:
    # Re-read even when mtime is unchanged. Missing, truncated or unreadable revokes all.
    try:
        with open(MEETING_MEDIA_PATH, encoding="utf-8") as f:
            value = json.load(f)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def meeting_lease(vm_id, lease_id=None):
    if not vm_id or kill_switched(vm_id):
        return None
    lease = meeting_leases().get(vm_id)
    if not isinstance(lease, dict):
        return None
    now = time.time()
    try:
        start, expiry, deadline = lease["started"], lease["expires"], lease["deadline"]
        budget = lease["max_bytes"]
        if not all(type(v) in (int, float) for v in (start, expiry, deadline, budget)):
            return None
        if not (MEETING_PROXY_STARTED <= start <= now < expiry <= min(deadline, now + 60)
                and start < deadline <= start + MEETING_MAX_SECONDS
                and 0 < budget <= MEETING_MAX_BYTES):
            return None
        if not isinstance(lease["id"], str) or not re.fullmatch(r"[a-f0-9]{32}", lease["id"]):
            return None
        if lease_id is not None and lease["id"] != lease_id:
            return None
    except (KeyError, TypeError, ValueError):
        return None
    return lease


def meeting_destination(sni, host, port):
    if port != 443 or sni not in MEETING_MEDIA_RANGES:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # CONNECT-by-name is resolved once and pinned before the connection opens.
        # The transparent production path already supplies the destination IP.
        return False
    return ip.version == 4 and any(ip in net for net in MEETING_MEDIA_RANGES[sni])


class _MeetingMedia(_EnforcementLayer):
    """TLS bytes relayed unchanged; every send and a one-second timer recheck the grant."""
    def __init__(self, context, vm_id, sni, lease):
        super().__init__(context)
        self.relay = _TCPLayer(context, ignore=True)
        self.vm_id, self.sni, self.lease_id = vm_id, sni, lease["id"]
        self.started = time.time()
        self.in_bytes = self.out_bytes = 0
        self.closed = False
        self.wakeup = None
        # Keep exhausted budgets until the absolute deadline, across reconnects and renewals.
        for key in list(_media_usage):
            if _media_usage[key]["deadline"] < self.started and not _media_usage[key]["connections"]:
                del _media_usage[key]
        self.usage = _media_usage.setdefault(self.lease_id, {"bytes": 0, "connections": 0, "deadline": lease["deadline"]})
        self.usage["connections"] += 1

    def close(self, reason):
        if self.closed:
            return
        self.closed = True
        self.usage["connections"] -= 1
        # Transport closure must happen even when the logger fails.
        yield _CloseConnection(self.context.client)
        yield _CloseConnection(self.context.server)
        try:
            _log({"flow_id": "meet_" + hashlib.sha256(f"{self.started}{id(self)}".encode()).hexdigest()[:24],
                  "ts": time.time(), "tenant": TENANT, "vm_id": self.vm_id,
                  "host": self.sni, "port": 443, "effect": "tunnel", "rule": "meet-media-v1",
                  "bytes_in": self.in_bytes, "bytes_out": self.out_bytes,
                  "duration_ms": int((time.time() - self.started) * 1000), "reason": reason})
        except Exception:
            log.warning("[mitm] meeting media metadata log unavailable")

    def _handle_event(self, event):
        if self.closed:
            return
        lease = meeting_lease(self.vm_id, self.lease_id)
        if (not lease or self.usage["connections"] > MEETING_MAX_CONNECTIONS
                or self.usage["bytes"] >= lease["max_bytes"]):
            yield from self.close("revoked_or_limit")
            return
        if isinstance(event, _media_events.ConnectionClosed):
            yield from self.close("closed")
            return
        if isinstance(event, (_media_events.Start, _media_events.Wakeup)):
            self.wakeup = _media_commands.RequestWakeup(1)
            yield self.wakeup
            if isinstance(event, _media_events.Wakeup):
                return
        for command in self.relay.handle_event(event):
            if isinstance(command, _media_commands.SendData):
                size = len(command.data)
                # Shared per-call budget, charged BEFORE forwarding, including TLS handshakes.
                if self.usage["bytes"] + size > lease["max_bytes"]:
                    yield from self.close("byte_limit")
                    return
                self.usage["bytes"] += size
                if command.connection is self.context.server:
                    self.out_bytes += size
                else:
                    self.in_bytes += size
            yield command


# ----- hooks ----------------------------------------------------------------

class _DeniedTCP(_EnforcementLayer):
    """Consume all events and close both sides without opening or forwarding anything.

    mitmproxy 12.2.2's TCPLayer ignores Flow.kill(), including after TLS interception.
    Keep the tcp_start hook for the drop record, but enforce denial with transport commands.
    Hook/logging failures cannot turn this layer into a relay.
    """

    def __init__(self, selected: _TCPLayer) -> None:
        super().__init__(selected.context)
        self.flow = selected.flow
        self._closed = False

    def _handle_event(self, event):
        if not self._closed:
            self._closed = True
            yield _TcpStartHook(self.flow)
            yield _CloseConnection(self.context.client)
            yield _CloseConnection(self.context.server)
            self.flow.live = False


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
        if sni in MEETING_MEDIA_RANGES:
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
        if kill_switched(vm_id):
            # Under an emergency stop the ONLY destination that still passes through is the
            # control plane: the vm-agent's own channel rides it, and so does the relay an owner
            # uses to unlock a box's disk. Everything else — the backup store, Tailscale, every
            # `tunnel` rule the organisation wrote — is intercepted and refused below, because a
            # passed-through connection is one this proxy never sees again.
            if CONTROL_PLANE_HOST and host_matches(CONTROL_PLANE_HOST, sni):
                data.ignore_connection = True
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

    Script hooks run BEFORE the built-in selector in mitmproxy 12.2.2. Ask it for its choice
    first so the enforcement step can replace raw TCP, including decrypted non-HTTP traffic.
    A deferral clears the choice back to None so mitmproxy buffers more bytes.

    A final enforcement step replaces every unapproved TCP relay, even if matching fails.
    """
    try:
        if data.layer is None:
            _mitm_ctx.master.addons.get("nextlayer").next_layer(data)
    except Exception as exc:
        log.error(f"[mitm] protocol selection failed; closing connection: {exc}")
        data.layer = _DeniedTCP(_TCPLayer(data.context))
        return
    try:
        if _proxy_layers is None:
            return
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
            if hello is None and readable and (residential_configured() or meeting_lease(vm_id)):
                # Incomplete ClientHello. Clear mitmproxy's choice and wait for the rest; this is
                # the normal path for Chrome, whose hello spans two segments.
                data.layer = None
                return
            if hello is not None:
                sni = (hello.sni or "").lower()
            if sni in MEETING_MEDIA_RANGES:
                lease = meeting_lease(vm_id)
                usage = _media_usage.get(lease["id"], {}) if lease else {}
                if (lease and usage.get("connections", 0) < MEETING_MAX_CONNECTIONS
                        and meeting_destination(sni, host, port) and not ctx.server.connected):
                    data.layer = _MeetingMedia(ctx, vm_id, sni, lease)
                else:
                    data.layer = _DeniedTCP(_TCPLayer(ctx))
                return
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
    finally:
        selected = data.layer
        if (isinstance(selected, _TCPLayer) and selected.flow is not None
                and not selected.flow.metadata.get("cc_exit")):
            data.layer = _DeniedTCP(selected)


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
    TCP flow). `_DeniedTCP` closes the transport; this hook records the decision.

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
        # Defense in depth for an unexpected TCP layer: never forward a denied payload,
        # even when Flow.kill() is ineffective. The normal path closes in _DeniedTCP.
        for msg in flow.messages:
            msg.content = b""
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


# ---- Targets the firewall never connects to (T-61) ----
# An agent box sends everything to this proxy, so a request for 169.254.169.254 (the cloud metadata
# service) used to be fetched by the FIREWALL box, from its own metadata: the agent got the
# firewall's user-data. Link-local, loopback, unspecified and multicast addresses mean "this
# machine" or "this link" — on this box they are the firewall's own services and metadata, never
# something an agent may reach. No rule can allow them. Private ranges (10/8, 172.16/12,
# 192.168/16) are not in this list: they are real, if internal, destinations.
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def non_routable_kind(ip: str) -> str | None:
    """Why `ip` is a target the firewall refuses, or None if it may be connected to. Also looks
    through the IPv6 forms that carry an IPv4 address (`::ffff:169.254.169.254`, NAT64)."""
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        elif addr in _NAT64:
            addr = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    if addr.is_link_local:
        return "link-local"
    if addr.is_loopback:
        return "loopback"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_multicast:
        return "multicast"
    return None


async def _resolve(host: str, port: int | None) -> list[str]:
    """Every address `host` resolves to; an IP literal is its own answer."""
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
        return [host]
    except ValueError:
        pass
    infos = await asyncio.get_running_loop().getaddrinfo(host, port or 0, type=socket.SOCK_STREAM)
    out: list[str] = []
    for info in infos:
        ip = str(info[4][0])
        if ip not in out:
            out.append(ip)
    return out


async def check_target(host: str, port: int | None, strict: bool) -> tuple[str | None, str | None]:
    """Resolve `host` and refuse it if ANY address is non-routable, so a name that points at the
    metadata address is refused like the address itself. Returns (address to connect to, refusal).
    With `strict`, a name that does not resolve is refused too: the caller is about to connect, and
    connecting would resolve again — the answer we checked must be the one that is used."""
    host = (host or "").strip().strip("[]")
    if not host:
        return None, None
    try:
        ips = await _resolve(host, port)
    except (OSError, UnicodeError) as exc:
        if strict:
            return None, f"could not resolve {host[:60]}: {exc}"[:200]
        return None, None
    for ip in ips:
        kind = non_routable_kind(ip)
        if kind:
            shown = host if host == ip else f"{host} ({ip})"
            return None, f"{shown[:120]} is a {kind} address; the firewall never connects there"
    if not ips:
        return None, (f"could not resolve {host[:60]}" if strict else None)
    # Prefer IPv4, as most of these boxes route it; any address in the list passed the check.
    return next((ip for ip in ips if ":" not in ip), ips[0]), None


def _non_routable_record(vm_id: str | None, host: str, port: int | None, why: str, flow_id: str | None = None) -> dict[str, Any]:
    return {
        "flow_id": flow_id or "nr_" + hashlib.sha256(f"{time.time()}{host}{port}".encode()).hexdigest()[:24],
        "ts": time.time(), "tenant": TENANT, "vm_id": vm_id,
        "host": host, "port": port, "effect": "block", "rule": NON_ROUTABLE_RULE, "error": why[:200],
    }


async def _refuse_non_routable_http(flow: http.HTTPFlow) -> bool:
    """Refuse an HTTP request whose connection would go to a non-routable address, before any rule
    runs. Checks where the connection actually goes (the CONNECT target, or the request's own
    authority), never the Host header, which decides nothing about the socket."""
    server = getattr(flow, "server_conn", None)
    if server is not None and getattr(server, "connected", False):
        return False  # an open connection was checked when it was made
    targets: list[tuple[str, int | None]] = []
    addr = getattr(server, "address", None)
    if addr and not getattr(server, "via", None):
        targets.append((str(addr[0]), addr[1]))
    targets.append((flow.request.host, flow.request.port))
    for host, port in targets:
        _, why = await check_target(host, port, strict=False)
        if why:
            flow.response = http.Response.make(
                BLOCK_STATUS,
                json.dumps({"error": "non_routable_target", "host": host, "reason": why, "tenant": TENANT}),
                {"Content-Type": "application/json"},
            )
            flow.metadata["cc_effect"] = "block"
            flow.metadata["cc_rule"] = NON_ROUTABLE_RULE
            rec = _http_record(flow, "block")
            rec.update({"status": BLOCK_STATUS, "port": port, "error": why[:200]})
            _log_once(flow, rec)
            log.warning(f"[mitm] refused {host}:{port}: {why}")
            return True
    return False


async def server_connect(data) -> None:
    """The last word before ANY upstream socket opens — intercepted HTTP(S), passed-through TLS,
    tunnels, residential upstreams. Resolves the destination, refuses it when any address is
    non-routable, and pins the connection to the address that was checked, so a name cannot answer
    differently the second time (DNS rebinding). Setting `server.error` is mitmproxy's own way to
    kill a connection before it is made."""
    server = getattr(data, "server", None)
    addr = getattr(server, "address", None)
    if not addr:
        return
    host, port = str(addr[0]), addr[1]
    try:
        ip, why = await check_target(host, port, strict=True)
    except Exception as exc:  # noqa: BLE001 — a failed check refuses; it never lets through
        ip, why = None, f"could not check {host[:60]}: {exc}"[:200]
    if why:
        server.error = f"{NON_ROUTABLE_REFUSAL} {why}"
        client = getattr(data, "client", None)
        vm_id = vm_id_for_ip(_peer_ip(getattr(client, "peername", None)))
        sni = getattr(client, "sni", None) or host
        _log(_non_routable_record(vm_id, sni, port, why))
        log.warning(f"[mitm] refused connection to {host}:{port}: {why}")
        return
    if ip and ip != host:
        # Keep the name for TLS: this is what mitmproxy's tls_start_server would pick itself.
        if getattr(server, "sni", None) is None:
            server.sni = getattr(getattr(data, "client", None), "sni", None) or host
        # Pinned only for the connect. `server_connected` puts the name back, because mitmproxy
        # reuses an open upstream connection only when its address equals the next request's
        # (name, port): left as an IP, every request would open a new connection.
        _pinned[server.id] = addr
        server.address = (ip, port)


# server.id -> the (name, port) a connection had before `server_connect` pinned it to an IP.
_pinned: dict[str, Any] = {}


def _unpin(data) -> None:
    server = getattr(data, "server", None)
    original = _pinned.pop(getattr(server, "id", None), None)
    if original is not None:
        # `Server.__setattr__` refuses an address change once the connection is open, to stop an
        # addon moving a live connection somewhere else. This one does not move it: the socket is
        # already connected to the checked IP, and only the label used for reuse changes back.
        # Pinned mitmproxy (12.2.2); test_non_routable.py fails if this stops working.
        object.__setattr__(server, "address", original)


def server_connected(data) -> None:
    """The socket is open to the checked IP; give the connection its name back (see server_connect)."""
    _unpin(data)


def server_connect_error(data) -> None:
    _unpin(data)


# Realtime is a call-scoped capability, separate from ordinary text credentials.
# No audio, transcripts or tool arguments are retained here. Upstream ephemeral
# credentials remain in firewall RAM until their one-time use or 60-second expiry.
_voice_tokens = {}
_voice_usage = {}
_voice_tasks = {}
VOICE_MAX_BYTES = 512 * 1024 * 1024
VOICE_MAX_FRAMES = 250000
VOICE_PATHS = {"ai-gateway.vercel.sh": {"/v1/realtime/client-secrets", "/v4/ai/realtime-model", "/v1/live/sessions"},
               "api.openai.com": {"/v1/realtime", "/v1/live", "/v1/live/sessions", "/v1/realtime/calls"}}
# Speech models by protocol family (docs/plans/gpt-live-and-wake-word.md D10/D14), mirroring
# @controlclaw/meetings speechFamily. The firewall allows whatever model the lease binds, as long
# as it belongs to a family it knows how to police; the family decides paths and frames.
# Transcription and translation models share the gpt-realtime prefix and are not voice models.
_REALTIME_SUFFIX = r"(?:-(?![a-z0-9.-]*(?:whisper|translate|transcribe))[a-z0-9][a-z0-9.-]{0,23})?"
_SPEECH_FAMILIES = {
    "gateway": {"realtime": re.compile(r"openai/gpt-realtime" + _REALTIME_SUFFIX), "live": re.compile(r"openai/gpt-live-[0-9]{1,3}(?:\.[0-9]{1,3})?")},
    "openai": {"realtime": re.compile(r"gpt-realtime" + _REALTIME_SUFFIX), "live": re.compile(r"gpt-live-[0-9]{1,3}(?:\.[0-9]{1,3})?")},
    "codex": {"realtime": re.compile(r"gpt-realtime")},
}
LIVE_VOICES = {"marin", "cedar", "alloy", "ash", "ballad", "coral", "echo", "sage", "shimmer", "verse"}
LIVE_MAX_APPENDS = 400
# Meetings in wake mode (controlclaw docs/plans/gpt-live-and-wake-word.md, D7/D10): the agent opens a
# gpt-live session per request, and the mitm-agent marks such a meeting lease with `wake_sessions`
# (at most 40). Then: still one socket at a time; at most `wake_sessions` sockets that carry audio;
# up to six token mints per session, since a session opened early on a half-heard name and never
# given audio costs a mint but is not billed; and one start per 2 s.
WAKE_MAX_SESSIONS = 40
WAKE_OPENS_PER_SESSION = 6
WAKE_START_GAP = 2


def wake_sessions(lease, family, purpose):
    n = lease.get("wake_sessions")
    return n if purpose == "meeting" and family == "live" and type(n) is int and 1 < n <= WAKE_MAX_SESSIONS else 0


def speech_family(provider, model):
    families = _SPEECH_FAMILIES.get(provider) if isinstance(provider, str) else None
    if not families or not isinstance(model, str):
        return None
    return next((name for name, pattern in families.items() if pattern.fullmatch(model)), None)


PHONE_MEDIA_PATH = os.environ.get("MITM_PHONE_MEDIA_PATH", os.path.join(os.path.dirname(RULES_PATH), "phone-media.json"))


def phone_lease(vm_id, lease_id=None):
    if not vm_id or kill_switched(vm_id):
        return None
    try:
        with open(PHONE_MEDIA_PATH, encoding="utf-8") as f:
            leases = json.load(f).get(vm_id)
        if not isinstance(leases, list):
            leases = [leases]
        lease = next((v for v in leases if isinstance(v, dict) and
                      (v.get("id") == lease_id if lease_id is not None else
                       _voice_usage.get(v.get("id"), {}).get("reserved_until", 0) <= time.time() and
                       not _voice_usage.get(v.get("id"), {}).get("active", False))), None)
        now = time.time()
        if (not isinstance(lease, dict) or lease.get("purpose") != "phone"
            or not re.fullmatch(r"[a-f0-9]{64}", lease.get("id", ""))
            or not all(type(lease.get(k)) in (int, float) for k in ("started", "expires", "deadline"))
            or not MEETING_PROXY_STARTED <= lease["started"] <= now < lease["expires"] <= min(lease["deadline"], now + 5)
            or not lease["started"] < lease["deadline"] <= lease["started"] + 3600
            or lease_id is not None and lease["id"] != lease_id):
            return None
        return lease
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def voice_request(flow, vm_id):
    host, path = flow.request.pretty_host, flow.request.path.split("?", 1)[0]
    credentials = credentials_for(host, vm_id)
    authorization = flow.request.headers.get("authorization", "")
    speech_cred = next((c for c in credentials if c.get("speech") and c.get("placeholder") and
                       c["placeholder"] in authorization), None)
    if speech_cred and (authorization[:7].lower() != "bearer " or authorization[7:] != speech_cred["placeholder"]):
        return "Invalid speech authorization"
    realtime = path in VOICE_PATHS.get(host, set())
    if not realtime and not speech_cred:
        return None
    purpose = "phone" if speech_cred and speech_cred.get("phone_speech") else "meeting"
    bound = None
    if not speech_cred:
        tokens = [p.strip()[len("ai-gateway-auth."):] for p in flow.request.headers.get("sec-websocket-protocol", "").split(",") if p.strip().startswith("ai-gateway-auth.")]
        if len(tokens) == 1:
            bound = _voice_tokens.get(hashlib.sha256(tokens[0].encode()).hexdigest())
            if bound and len(bound) > 5:
                purpose = bound[5]
    lease = phone_lease(vm_id, bound[1] if bound else None) if purpose == "phone" else meeting_lease(vm_id)
    speech = lease.get("speech") if lease else None
    if not realtime or not isinstance(speech, dict):
        return "Voice needs an active approved call"
    provider, model = speech.get("provider"), speech.get("model")
    if speech_cred and speech_cred["placeholder"] != lease.get("voice_placeholder"):
        return "Speech credential does not match this call"
    expected_host = "ai-gateway.vercel.sh" if provider == "gateway" else "api.openai.com"
    # pretty_host trusts Host; credential translation also requires the actual
    # HTTPS target, port and (when present) client TLS name to agree.
    sni = (getattr(flow.client_conn, "sni", None) or "").lower()
    if (flow.request.scheme != "https" or flow.request.port != 443
            or sni and sni != expected_host):
        return "Voice requires the verified provider HTTPS destination"
    if flow.request.host != expected_host:
        # Redsocks CONNECT names the original IP. Require the provider TLS name,
        # then route by the pinned provider hostname, never the supplied IP/Host.
        try:
            ipaddress.ip_address(flow.request.host)
        except ValueError:
            return "Voice requires the verified provider HTTPS destination"
        if sni != expected_host:
            return "Voice requires the verified provider HTTPS destination"
        flow.request.host = expected_host
    family = speech_family(provider, model)
    if host != expected_host or not family:
        return "Speech provider does not match this call"
    now = time.time()
    for key, entry in list(_voice_tokens.items()):
        if entry[3] < now:
            del _voice_tokens[key]
    for key, entry in list(_voice_usage.items()):
        if entry["deadline"] < now:
            del _voice_usage[key]
    usage = _voice_usage.setdefault(lease["id"], {"deadline": lease["deadline"], "bytes": 0, "frames": 0, "attempts": 0, "active": False, "responses": 0})
    if usage["bytes"] >= VOICE_MAX_BYTES or usage["responses"] >= 120 or usage["active"]:
        return "Voice call limit reached"
    mint = provider == "gateway" and path == "/v1/realtime/client-secrets"
    wake = wake_sessions(lease, family, purpose)
    if (mint or provider != "gateway") and usage["attempts"] >= (wake * WAKE_OPENS_PER_SESSION if wake else 4):
        return "Voice call limit reached"
    if wake and (mint or provider != "gateway") and now - usage.get("last_start", 0) < WAKE_START_GAP:
        return "Voice sessions are starting too fast"
    if mint:
        try:
            body = json.loads(flow.request.content)
            expected = {"model": model, "routeKind": "live"} if family == "live" else {"model": model, "expiresIn": 60}
            if flow.request.method != "POST" or not speech_cred or body != expected:
                return "Invalid realtime token request"
        except (ValueError, TypeError):
            return "Invalid realtime token request"
        usage["attempts"] += 1
        usage["last_start"] = now
    else:
        if flow.request.method != "GET" or flow.request.headers.get("upgrade", "").lower() != "websocket":
            return "Only the approved voice WebSocket is allowed"
        query = dict(flow.request.query)
        if provider == "gateway":
            # gpt-live names its model in the first frame (session.start), checked frame by frame.
            if (family == "live" and (path != "/v1/live/sessions" or query)) or \
                    (family == "realtime" and (path != "/v4/ai/realtime-model" or query != {"ai-model-id": model})):
                return "Realtime model does not match this call"
            protocols = [p.strip() for p in flow.request.headers.get("sec-websocket-protocol", "").split(",")]
            tokens = [p[len("ai-gateway-auth."):] for p in protocols if p.startswith("ai-gateway-auth.")]
            if len(tokens) != 1:
                return "Missing call token"
            digest = hashlib.sha256(tokens[0].encode()).hexdigest()
            bound = _voice_tokens.pop(digest, None)
            if not bound or bound[:3] != (vm_id, lease["id"], model) or bound[3] <= now or (bound[5] if len(bound) > 5 else "meeting") != purpose:
                return "Call token expired or belongs to another call"
            flow.request.headers["sec-websocket-protocol"] = ", ".join(
                "ai-gateway-auth." + bound[4] if p.startswith("ai-gateway-auth.") else p for p in protocols)
        else:
            if not speech_cred or (family == "live" and (path != "/v1/live/sessions" or query)) or \
                    (family == "realtime" and (path != "/v1/realtime" or query != {"model": model})):
                return "Invalid provider voice request"
            usage["attempts"] += 1
            usage["last_start"] = now
            if provider == "codex" and speech_cred.get("speech_account_id"):
                flow.request.headers["chatgpt-account-id"] = speech_cred["speech_account_id"]
    if purpose == "phone":
        usage["reserved_until"] = now + 60
    flow.metadata["cc_voice"] = {"vm_id": vm_id, "lease_id": lease["id"], "model": model, "provider": provider, "mint": mint, "purpose": purpose, "family": family, "wake": wake}
    if speech_cred:
        flow.metadata["voice_credential"] = speech_cred["placeholder"]
    return None


def voice_response(flow):
    voice = flow.metadata.get("cc_voice")
    if not voice or not voice["mint"]:
        return
    if flow.response.status_code != 200:
        usage = _voice_usage.get(voice["lease_id"])
        if usage: usage["reserved_until"] = 0
        return
    try:
        value = json.loads(flow.response.content)
        token = value["token"]
        if not isinstance(token, str) or len(token) > 8192:
            raise ValueError()
        opaque = "cc-voice-" + secrets.token_hex(32)
        digest = hashlib.sha256(opaque.encode()).hexdigest()
        _voice_tokens[digest] = (voice["vm_id"], voice["lease_id"], voice["model"], time.time() + 60, token, voice.get("purpose", "meeting"))
        flow.response.content = json.dumps({"token": opaque}).encode()
    except (ValueError, KeyError, TypeError):
        flow.response = http.Response.make(502, b'{"error":"Voice token unavailable"}')


def live_client_event(event, model, state):
    """gpt-live client frames (D10). `state` is per socket: whether session.start was seen, appends."""
    kind = event.get("type")
    if not state.get("started"):
        # The first frame starts the session, once, with settings we can vouch for: the bound model,
        # nothing stored, client delegation only (Responses delegation would run a backend model
        # with arbitrary tools on this credential), 24 kHz PCM and a known voice.
        session = event.get("session")
        if kind != "session.start" or set(event) - {"type", "session", "event_id"} or not isinstance(session, dict):
            return False
        if set(session) - {"model", "store", "delegation", "audio", "instructions"} or session.get("model") != model:
            return False
        if session.get("store") is not False or session.get("delegation") != {"type": "client"}:
            return False
        instructions = session.get("instructions", "")
        if not isinstance(instructions, str) or len(instructions) > 32000:
            return False
        audio = session.get("audio", {})
        if not isinstance(audio, dict) or set(audio) - {"format", "output"} or audio.get("format", {"type": "audio/pcm", "rate": 24000}) != {"type": "audio/pcm", "rate": 24000}:
            return False
        output = audio.get("output", {})
        if not isinstance(output, dict) or set(output) - {"voice"} or output.get("voice", "marin") not in LIVE_VOICES:
            return False
        state["started"] = True
        return True
    if kind == "session.input_audio.append":
        return not set(event) - {"type", "audio", "event_id"} and isinstance(event.get("audio"), str)
    if kind in ("session.input_audio.mute", "session.input_audio.unmute", "session.close"):
        return not set(event) - {"type", "event_id"}
    if kind in ("session.thinking.append", "session.commentary.append"):
        state["appends"] = state.get("appends", 0) + 1
        delegation = event.get("delegation_id")
        return (not set(event) - {"type", "content", "delegation_id", "event_id"}
                and isinstance(event.get("content"), str) and len(event["content"]) <= 4000
                and (delegation is None or isinstance(delegation, str) and len(delegation) <= 200)
                and state["appends"] <= LIVE_MAX_APPENDS)
    # session.update, session.instructions.append, response.* and anything new are refused.
    return False


def voice_client_event(event, provider, model, family="realtime", state=None):
    if not isinstance(event, dict):
        return False
    if family == "live":
        return live_client_event(event, model, state if state is not None else {})
    kind = event.get("type")
    allowed = {"session-update", "input-audio-append", "input-audio-commit", "input-audio-clear",
               "conversation-item-create", "conversation-item-truncate", "response-create", "response-cancel"}
    if provider in ("openai", "codex"):
        allowed = {"session.update", "input_audio_buffer.append", "input_audio_buffer.commit", "input_audio_buffer.clear", "conversation.item.create", "conversation.item.truncate", "response.create", "response.cancel"}
    if kind not in allowed:
        return False
    if kind in ("response.create", "response-create"):
        # Session policy cannot be overridden on an individual response.
        if set(event) != {"type"}:
            return False
    config = event.get("config", {}) if provider == "gateway" else event.get("session", {})
    if kind in ("session-update", "session.update"):
        if not isinstance(config, dict) or config.get("model", model) != model:
            return False
        if provider == "gateway" and "model" in config:
            return False
        if provider in ("openai", "codex") and config.get("max_output_tokens") != 512:
            return False
        options = config.get("providerOptions", {})
        if not isinstance(options, dict) or set(options) - {"audio", "max_output_tokens"}:
            return False
        if provider == "gateway" and (not model.startswith("openai/") or options.get("max_output_tokens") != 512):
            return False
        tools = config.get("tools", [])
        if not isinstance(tools, list) or len(tools) > 1 or any(t.get("type") != "function" or t.get("name") != "ask_agent" for t in tools if isinstance(t, dict)) or any(not isinstance(t, dict) for t in tools):
            return False
    return True


def voice_lease(voice):
    lease = phone_lease(voice["vm_id"], voice["lease_id"]) if voice.get("purpose") == "phone" else meeting_lease(voice["vm_id"], voice["lease_id"])
    speech = lease.get("speech") if lease else None
    return lease if isinstance(speech, dict) and speech.get("provider") == voice["provider"] and speech.get("model") == voice["model"] else None


def _voice_close(flow):
    if getattr(flow, "live", False):
        flow.kill()


async def _voice_watch(flow):
    voice = flow.metadata["cc_voice"]
    try:
        while True:
            await asyncio.sleep(0.25 if voice.get("purpose") == "phone" else 1)
            if not voice_lease(voice):
                _voice_close(flow)
                return
    except asyncio.CancelledError:
        pass


def websocket_start(flow):
    voice = flow.metadata.get("cc_voice")
    if not voice:
        return
    usage = _voice_usage.get(voice["lease_id"])
    if not usage or usage["active"] or not voice_lease(voice):
        _voice_close(flow)
        return
    usage["active"] = flow.id
    _voice_tasks[flow.id] = asyncio.create_task(_voice_watch(flow))


def websocket_message(flow):
    if flow.request.pretty_host.lower() == AGENTMAIL_WS:
        agentmail_ws_message(flow)
        return
    voice = flow.metadata.get("cc_voice")
    if not voice or not flow.websocket.messages:
        return
    message = flow.websocket.messages[-1]
    usage = _voice_usage.get(voice["lease_id"])
    reject = not usage or not voice_lease(voice)
    if usage:
        usage["bytes"] += len(message.content)
        usage["frames"] += 1
        reject |= usage["bytes"] > VOICE_MAX_BYTES or usage["frames"] > VOICE_MAX_FRAMES or len(message.content) > 512 * 1024
    try:
        event = json.loads(message.content)
        if message.from_client:
            state = voice.setdefault("live", {})
            reject |= not voice_client_event(event, voice["provider"], voice["model"], voice.get("family", "realtime"), state)
            if voice.get("wake") and usage and event.get("type") == "session.input_audio.append" and not state.get("audio"):
                # This session is being given meeting audio: it counts against the meeting's sessions.
                state["audio"] = True
                usage["audio_sockets"] = usage.get("audio_sockets", 0) + 1
                reject |= usage["audio_sockets"] > voice["wake"]
        elif isinstance(event, dict) and event.get("type") in ("session.usage.updated", "session.closed"):
            # Billed seconds of a gpt-live session (cumulative): kept for its Activity record.
            seconds = (event.get("usage") or {}).get("seconds") if isinstance(event.get("usage"), dict) else None
            if isinstance(seconds, (int, float)) and 0 <= seconds <= 86400:
                voice["seconds"] = max(voice.get("seconds", 0), int(seconds))
        elif isinstance(event, dict) and event.get("type") in ("response-created", "response.created") and usage:
            usage["responses"] += 1
            reject |= usage["responses"] > 120
    except (ValueError, TypeError):
        reject = True
    if reject:
        message.drop()
        _voice_close(flow)
    # mitmproxy relays its local message reference after this hook. The flow must not retain it.
    flow.websocket.messages.clear()


def websocket_end(flow):
    voice = flow.metadata.get("cc_voice")
    if not voice:
        return
    task = _voice_tasks.pop(flow.id, None)
    if task:
        task.cancel()
    usage = _voice_usage.get(voice["lease_id"])
    if usage and usage["active"] == flow.id:
        usage["active"] = False
        usage["reserved_until"] = 0
    flow.websocket.messages.clear()
    # Ordinary HTTP activity records the upgrade; never emit provider payloads or close reasons.
    if voice.get("family") == "live" and "seconds" in voice:
        # gpt-live bills per connected second; the provider's own count, as metadata only.
        rec = _base_record(flow, voice["vm_id"])
        rec.update({"flow_id": flow.id + ":end", "host": flow.request.pretty_host, "method": "GET",
                    "path": redact_path(flow.request.path, flow.request.pretty_host), "effect": "allow",
                    "rule": f"{voice.get('purpose', 'meeting')}_voice: {voice['model']} {voice['seconds']} s billed"})
        _log(rec)


async def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    method = flow.request.method
    path = flow.request.path
    vm_id = flow_vm_id(flow)  # which VM (by source IP) this request belongs to; None if unknown
    flow.metadata["cc_vm_id"] = vm_id

    if await _refuse_non_routable_http(flow):
        return

    # The emergency stop, before anything that could let a request past
    # (`apps/saas/docs/features/kill-switch.md`). It sits above the update window on purpose: a box
    # that was mid-update when somebody pressed Stop must not keep its allowance to fetch packages.
    # The control plane is the single exception, for the vm-agent's own channel and the disk-unlock
    # relay — and it is matched by name here as well as by SNI in `tls_clienthello`, so a `Host:`
    # header cannot borrow it for somewhere else.
    # Read once, here, because three of the checks below compare it with the `Host:` header: the
    # code window, the emergency stop's control-plane exception and the update window.
    sni = (getattr(flow.client_conn, "sni", None) or "").lower()

    # The code window, checked before the refusal below and nowhere else: over TLS the name the
    # client handshook with has to be the same host, so a `Host:` header cannot borrow it, and the
    # request is sent to that name rather than to whatever address the box connected to.
    if kill_switched(vm_id) and code_traffic(host, vm_id) and (not sni or sni == host.lower()):
        if flow.request.host != host:
            flow.request.host = host
        flow.metadata["cc_effect"] = "allow"
        flow.metadata["cc_rule"] = CODE_RULE
        return

    if kill_switched(vm_id) and not (CONTROL_PLANE_HOST and host_matches(CONTROL_PLANE_HOST, host)):
        flow.metadata["cc_effect"] = "block"
        flow.metadata["cc_rule"] = KILL_RULE
        flow.response = http.Response.make(
            BLOCK_STATUS,
            json.dumps({"error": "blocked_by_kill_switch", "host": host, "tenant": TENANT}),
            {"Content-Type": "application/json"},
        )
        rec = _http_record(flow, "block")
        rec["status"] = BLOCK_STATUS
        _log_once(flow, rec)
        return

    # A box running a confirmed update may fetch from the role's package hosts, whatever the org's
    # rules say (see UPDATE_HOSTS). Over TLS the name the client handshook with must be the same
    # host, and the request is sent to that name rather than to the address the box connected to,
    # so a `Host:` header cannot borrow the allowance for some other server. No swap, no AI review.
    if update_traffic(host, vm_id) and (not sni or sni == host.lower()):
        if flow.request.host != host:
            flow.request.host = host
        flow.metadata["cc_effect"] = "allow"
        flow.metadata["cc_rule"] = UPDATE_RULE
        return

    tripped = login_tripwire(flow, vm_id)
    if tripped is not None:
        flow.metadata["cc_effect"] = "block"
        flow.metadata["cc_rule"] = LOGIN_TRIPWIRE_RULE
        flow.response = http.Response.make(
            BLOCK_STATUS,
            json.dumps({"error": "login_sent_to_another_site", "host": host,
                        "message": "This password placeholder only works on the login's own sites. The firewall blocked it and recorded the attempt."}),
            {"Content-Type": "application/json"},
        )
        rec = _http_record(flow, "block")
        rec.update({"status": BLOCK_STATUS, "login": str(tripped.get("login_name") or "login")[:64]})
        _log_once(flow, rec)
        log.warning("[mitm] login=%s host=%s verdict=tripwire", tripped.get("login_id"), host)
        return

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
        pid = permission_id_for(permission_scope(method, host, permission_path(path, host)))
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
        scope = permission_scope(method, host, permission_path(path, host))
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
                "scope": scope, "host": host, "method": method, "path": redact_path(path, host),
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

    if host.lower() in (AGENTMAIL_API, AGENTMAIL_WS) or is_googleapis(host):
        if not await agentmail_attachment_allowed(flow):
            _email_refuse(flow, "thread_attachment" if _AM_THREAD_ATTACHMENT.match(flow.request.path.split("?", 1)[0]) else "held_back")
            return
        if not await email_outbound(flow, vm_id):
            return

    if host.lower() == "api.twilio.com" and (not phone_authorized(flow, phone_credential(flow, vm_id)) or not await phone_reserve(flow, phone_credential(flow, vm_id))):
        flow.response = http.Response.make(403, '{"error":"phone_assignment_required_or_operation_refused"}', {"Content-Type": "application/json"})
        flow.metadata["cc_effect"] = "block"
        flow.metadata["cc_rule"] = "phone"
        rec = _http_record(flow, "block")
        rec["status"] = 403
        _log_once(flow, rec)
        return

    voice_refusal = voice_request(flow, vm_id)
    if voice_refusal:
        flow.response = http.Response.make(403, json.dumps({"error": voice_refusal}), {"Content-Type": "application/json"})
        flow.metadata["cc_effect"] = "block"
        flow.metadata["cc_rule"] = "meeting_voice"
        rec = _http_record(flow, "block")
        rec["status"] = 403
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
    login_pairs = {p for _, p in flow.metadata.get("cc_login_pairs", [])}
    rec["swapped"] = [p for _, p in flow.metadata.get("cc_applied", []) if not p.startswith("CC-SEC-") and p not in login_pairs] + flow.metadata.get("cc_secret_swaps", [])
    if flow.metadata.get("cc_login_swaps"):
        rec["login"] = flow.metadata["cc_login_swaps"][0][:64]
    if flow.metadata.get("cc_granted"):
        rec["permission_id"] = flow.metadata["cc_granted"]
    req_raw = flow.request.raw_content
    rec["bytes_out"] = len(req_raw) if req_raw else 0
    return rec


_phone_settle_tasks = set()


def response(flow: http.HTTPFlow) -> None:
    if flow.metadata.get("cc_email_reservation"):
        task = asyncio.create_task(asyncio.to_thread(email_settle, flow))
        _phone_settle_tasks.add(task)
        task.add_done_callback(_phone_settle_tasks.discard)
    if flow.request.pretty_host.lower() == AGENTMAIL_API and not _off_loop(flow, lambda: agentmail_response(flow)):
        agentmail_response(flow)
    if flow.metadata.get("cc_phone_reservation"):
        # A slow admission listener must not stall other calls' audio forwarding.
        task = asyncio.create_task(asyncio.to_thread(phone_settle, flow))
        _phone_settle_tasks.add(task)
        task.add_done_callback(_phone_settle_tasks.discard)
    voice_response(flow)
    redact_login_response(flow)
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
    if NON_ROUTABLE_REFUSAL in str(getattr(flow.error, "msg", "") or ""):
        return  # `server_connect` refused the connection and already wrote the block record
    rec = _allow_record(flow)
    rec["error"] = "Secret request failed" if flow.metadata.get("cc_secret_swaps") else "Integration request failed" if flow.request.pretty_host in ("api.agentmail.to", "ws.agentmail.to", "api.twilio.com") else str(getattr(flow.error, "msg", "") or "upstream error")[:200]
    start = flow.request.timestamp_start
    end = getattr(flow.error, "timestamp", None)
    if start and end:
        rec["duration_ms"] = int((end - start) * 1000)
    _log_once(flow, rec)
