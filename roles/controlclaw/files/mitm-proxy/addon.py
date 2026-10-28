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
     or multicast address, nor to any address of the firewall itself (T-sni), whatever a rule, the
     Host header or the CONNECT target says. Names are resolved first and the connection is pinned to the checked address (`server_connect`), so a
     name pointing at the metadata service is refused too. Each refusal is a `block` record.
  8. One destination per connection (docs/ops/t-sni-passthrough.md): rules and swaps are decided
     for one name, and the connection goes to that name. A passthrough matched by SNI is sent to
     the SNI, never to the IP the box asked for, and only to a public address. Over TLS the SNI must
     be the `Host:` header, and a CONNECT target that is an IP is replaced by that name. A mismatch
     is refused with a `destination_mismatch` record, and so is a request that names a second host
     (two Host headers, an HTTP/2 host header other than :authority). Credentials are only swapped
     into https requests. mitmproxy's own `ignore_hosts` is cleared at
     start: it matches the SNI and the Host header and then connects to the dialled address.

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
import concurrent.futures
import base64
import collections
import secrets
import hashlib
import hmac
import ipaddress
import json
import os
import re
from html import unescape as html_unescape
import socket
import threading
import time
import urllib.request
import uuid
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
              "MITM_DEV_INSECURE_UPSTREAM", "MITM_DEV_ALLOW_DIRECT_EGRESS",
              "MITM_DEV_PRIVATE_PASSTHROUGH")
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
# The `rule` on a record for a connection whose names disagree: a TLS name (SNI) that is not the
# `Host:` header, or a name that is not the one the box asked to connect to. Every rule and every
# swap is decided by one name, so the connection may only go to that name (see `request` and
# `tls_clienthello`).
DESTINATION_RULE = "destination_mismatch"
# The one port the built-in passthroughs (the control plane, the backup store, Tailscale) are used
# on. A connection to any other port with one of their names is intercepted like any other.
PASSTHROUGH_PORT = 443
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
    # Once per agent: an id is per scope, so two agents may ask for the same one, and each may
    # read only the requests raised for it.
    seen = f"{permission_id}|{record.get('vm_id') or ''}"
    if seen in _pending_seen:
        return
    _pending_seen.add(seen)
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


def _no_ignore_hosts() -> None:
    """Clear mitmproxy's own `ignore_hosts` / `allow_hosts`. They pass a connection through when the
    CONNECT target, the SNI OR a plain-HTTP `Host:` header matches, and then connect to the address
    the box asked for: a forged SNI or Host is an uninspected tunnel to any IP (T-sni). The firewall's
    unit set `--ignore-hosts <control plane>` until 2026-10-28; the control plane is passed through
    by `tls_clienthello` instead, to its own name only."""
    opts = _mitm_ctx.options
    for name in ("ignore_hosts", "allow_hosts"):
        if getattr(opts, name, None):
            # A warning, not an error: mitmdump exits when an error is logged during startup.
            log.warning(f"[mitm] {name} is set ({getattr(opts, name)}); clearing it, see docs/ops/t-sni-passthrough.md")
            opts.update(**{name: []})


def configure(updated) -> None:
    if "ignore_hosts" in updated or "allow_hosts" in updated:
        _no_ignore_hosts()


def running() -> None:
    _no_ignore_hosts()
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
            # mitmproxy hands over an international host name decoded; a login's sites are kept in
            # punycode, so that form is tried too.
            if not any(secret_host_matches(pattern, host) for pattern in c.get("allowed_hosts", [])) and not (
                c.get("login_id") and not host.isascii() and any(secret_host_matches(pattern, _ascii_host(host) or host) for pattern in c.get("allowed_hosts", []))
            ):
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
    if is_ip_literal(host) and (pattern == "*" or pattern.startswith("*.")):
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


# Provider wording that means "no money left" whatever the status: OpenAI answers 429
# `insufficient_quota`, Anthropic 400 "credit balance is too low", OpenRouter 402.
_MODEL_CREDIT_MARKERS = (
    "insufficient_quota", "billing_hard_limit", "billing_not_active", "credit balance", "insufficient credits",
    "insufficient_credits", "exceeded your current quota", "payment required", "out of credits",
)
# The first bytes of an error body read for those words; error bodies are small.
MODEL_ERROR_READ_MAX = 4096


def _swapped_model_credential(flow: http.HTTPFlow, vm_id: str | None) -> bool:
    """The firewall put one of the organization's model credentials into this request."""
    applied = {p for _, p in flow.metadata.get("cc_applied", [])}
    return any(c.get("model") and c.get("placeholder") in applied for c in credentials_for(flow.request.pretty_host, vm_id))


def classify_model_error(flow: http.HTTPFlow, vm_id: str | None) -> str | None:
    """Why a model provider refused an agent's call: `auth`, `credit` or `rate_limit`, else None.

    Only a POST (a model call; listing the models with a restricted key is not one) that carried a
    model credential the firewall swapped in, and only for a 4xx. That leaves out the agent's own
    browser on chatgpt.com, which signs in with a bearer of its own, and the included tokens, whose
    refusals have their own field (`included`). The body is read for the provider's error code and
    nothing of it is kept: only the code goes on the record (docs/features/problems.md).
    """
    if not flow.response or flow.metadata.get("cc_included"):
        return None
    status = flow.response.status_code
    if status < 400 or status >= 500 or flow.request.method.upper() != "POST":
        return None
    if not _swapped_model_credential(flow, vm_id):
        return None
    try:
        text = (flow.response.get_text(strict=False) or "")[:MODEL_ERROR_READ_MAX].lower()
    except (ValueError, AttributeError):
        text = ""
    if status == 402 or any(m in text for m in _MODEL_CREDIT_MARKERS):
        return "credit"
    if status == 401 or (status == 403 and ("authentication" in text or "permission" in text or "api key" in text or "api_key" in text)):
        return "auth"
    if status == 429:
        return "rate_limit"
    return None


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


def email_approval_doc(pids: list[str], recipients: list[str], summary: str) -> dict[str, Any]:
    """What an agent is told when a send waits for the owner: who, which request, and what to do."""
    who = ", ".join(recipients) if recipients else "a new recipient"
    ids = ", ".join(pids)
    wait = " and ".join(f"`cc-perm {p}`" for p in pids)
    message = (f"Approval needed: nothing was sent. The owner has been asked to approve emailing {who} "
               f"(request {ids}). The whole message is held, every recipient included, and it does not send itself "
               f"once approved: send it again after approval. Wait for the answer with {wait}, or check it with "
               f"`cc-perm status {pids[0] if pids else '<id>'}`. Tell the person you are waiting for the owner. Do not retry in a loop.")
    return {"permission_id": pids[0] if pids else None, "permission_ids": pids, "reason": "email_recipient_needs_approval",
            "recipients": recipients, "summary": summary, "resend": "manual", "message": message,
            "expires_at": int(time.time()) + PERMISSION_TTL}


def _email_answer(flow: http.HTTPFlow, status: int, doc: dict[str, Any]) -> None:
    """
    A refused or held send, as the agent's mail client shows it. Google's clients (gog included)
    read only Google's own `{"error": {...}}` object and print an empty error for anything else, so
    on googleapis.com the reason and the message also go in that shape.
    """
    if is_googleapis(flow.request.pretty_host):
        doc = {**doc, "error": {"code": status, "message": doc["message"],
                                "status": "FAILED_PRECONDITION" if status == PERMISSION_STATUS else "PERMISSION_DENIED",
                                # gog prints the first reason: the word the skills name (email_refused, or
                                # email_recipient_needs_approval), not the detail, which is in the message.
                                "errors": [{"domain": "controlclaw.firewall", "reason": doc["error"] if isinstance(doc.get("error"), str) else doc["reason"],
                                            "message": doc["message"]}]}}
    flow.response = http.Response.make(status, json.dumps(doc), {"Content-Type": "application/json"})


def _email_refuse(flow: http.HTTPFlow, reason: str, message: str | None = None, rule: str | None = None) -> None:
    _email_answer(flow, 403, {"error": "email_refused", "reason": reason,
                              "message": message or _EMAIL_REASONS.get(reason, "Email refused by the firewall.")})
    flow.metadata["cc_effect"] = "block"
    flow.metadata["cc_rule"] = rule or "email"
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
        # A send the email rules let through: its record says so, for the console's counts
        # (docs/plans/rule-metrics.md). Whether the mail service took it is the record's status.
        flow.metadata["cc_email_sent"] = True
        return True
    if decision == "ask" and isinstance(result.get("asks"), list) and result["asks"]:
        asks = [a for a in result["asks"] if isinstance(a, dict) and isinstance(a.get("scope"), str) and isinstance(a.get("summary"), str)][:20]
        pids, recipients = [], []
        for ask in asks:
            pid = permission_id_for(ask["scope"])
            pids.append(pid)
            recipient = ask.get("recipient") if isinstance(ask.get("recipient"), str) else None
            mailbox = ask.get("mailbox") if isinstance(ask.get("mailbox"), str) else None
            if recipient:
                recipients.append(recipient)
            record_pending(pid, {"permission_id": pid, "vm_id": vm_id, "scope": ask["scope"], "summary": ask["summary"][:300],
                                 "kind": "email_recipient", "host": flow.request.pretty_host, "method": flow.request.method,
                                 "path": redact_path(flow.request.path, flow.request.pretty_host),
                                 **({"recipient": recipient[:254], "mailbox": mailbox[:300]} if recipient and mailbox else {})})
        _email_answer(flow, PERMISSION_STATUS, email_approval_doc(pids, recipients, "; ".join(a["summary"] for a in asks)))
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


def agentmail_filter(doc: Any, decide, blocked=None) -> Any:
    """
    Apply the firewall's keep/strip/hide answer to an AgentMail JSON response. `decide(items)`
    takes [(inbox_id, item)] and returns one action per item. A message asked for by id is kept
    but marked blocked and emptied (the channel then settles it for good); list and thread
    members are dropped. `blocked(original)`, when given, is the content rules' word on an item the
    email rules kept: True hides it as well.
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
    if blocked is not None:
        for _, _, orig in targets:
            if verdict.get(id(orig)) != "hide" and blocked(orig):
                verdict[id(orig)] = "hide"

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
    try:
        # A write read the rules before it went (`content_rules_agentmail_before`): its answer is not
        # turned into "try again" after the mail was sent, which the agent would send again.
        rules = flow.metadata["cc_content_rules"] if "cc_content_rules" in flow.metadata else content_rules()
    except ContentRulesUnreadable:
        # Asked again in a moment, once the rules are known. Hiding would be for good: the agent's
        # channel settles a message it was shown as blocked.
        flow.response = http.Response.make(503, '{"error":"rules_loading","message":"The firewall is loading its rules. Try again in a few seconds."}', {"Content-Type": "application/json"})
        return
    try:
        filtered = agentmail_filter(doc, _decide_via_admission, _agentmail_blocked(flow, rules))
    except Exception as exc:
        if "cc_content_rules" in flow.metadata:
            # A write that already went: its ids, and nothing it carried back, rather than "try again".
            log.warning(f"[content-rules] the answer to an email write could not be checked, ids only: {exc!r}")
            _content_audit(flow, "error", "email", "in", "block")
            kept = {k: doc[k] for k in ("message_id", "thread_id", "draft_id", "inbox_id") if isinstance(doc, dict) and isinstance(doc.get(k), str)}
            flow.response.set_content(json.dumps(kept).encode())
            return
        log.warning(f"[content-rules] incoming email check failed, asked to try again: {exc!r}")
        _content_audit(flow, "error", "email", "in", "wait")
        flow.response = http.Response.make(503, '{"error":"check_failed","message":"The firewall could not check this mail. Try again."}', {"Content-Type": "application/json"})
        return
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
    if _decide_via_admission([(msg["inbox_id"], {"kind": "message", **msg})])[0].get("action") != "keep":
        return False
    # Off the event loop: while the rules are not known yet (a firewall starting), wait for them.
    return not _agentmail_blocked(None, content_rules_wait())(msg)


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

# Where a password may be put in (docs/plans/login-swap-scope.md). The proxy keeps what it learned
# from sign-in pages here; the firewall agent reads the file, keeps the targets in its own store
# and hands them back in `sign_in_targets`, so they outlive a restart of this box.
LOGIN_TARGETS_PATH = os.environ.get("MITM_LOGIN_TARGETS_PATH", os.path.join(os.path.dirname(CREDS_PATH), "login-targets.json"))
LOGIN_TARGETS_MAX = 5
LOGIN_TARGET_TTL_S = 30 * 86400
# A sign-in page larger than this is not read for its forms.
LOGIN_PAGE_MAX = 1024 * 1024
# Sign-in pages built in JavaScript have no form to read. The one everybody uses is listed here, so
# a Google login works without its owner typing a path. host -> path prefixes.
LOGIN_KNOWN_SIGN_IN = {"accounts.google.com": ("/v3/signin/",)}
# A request that carries a stand-in is read only when it is small and flat. A sign-in is.
LOGIN_BODY_MAX = 64 * 1024
LOGIN_FIELDS_MAX = 200
LOGIN_JSON_DEPTH_MAX = 8

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
        if _login_host(c, host) or (not host.isascii() and _login_host(c, _ascii_host(host) or host)):
            continue
        return c
    return None


def _login_destination_ok(flow: http.HTTPFlow, host: str) -> bool:
    """The swap may only go to the name the client asked for (same rule as custom secrets): the TLS
    names must match the host, and behind redsocks an IP authority is re-pointed at that name."""
    wire = lambda name: _ascii_host(name) or name.lower().rstrip(".")
    authority = wire(flow.request.host)
    destination = wire(host)
    client_sni = getattr(flow.client_conn, "sni", None)
    server_sni = getattr(flow.server_conn, "sni", None)
    if any(sni and wire(sni) != destination for sni in (client_sni, server_sni)):
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


def _without_stand_in(path: Any, cred: dict[str, Any]) -> Any:
    """A record's path with the login's stand-in taken out. The stand-in is not the password, but
    it is what the agent types to get it, and Activity is read by more people than the agent."""
    if not isinstance(path, str) or not cred.get("placeholder"):
        return path
    from urllib.parse import unquote
    found = _placeholder_re(cred["placeholder"])
    if found.search(path):
        return found.sub("[login stand-in]", path)
    return "/[login stand-in]" if found.search(unquote(path)) else path


def _tls_names_are(flow: http.HTTPFlow, host: str) -> bool:
    want = _ascii_host(host) or host.lower().rstrip(".")
    names = [getattr(flow.client_conn, "sni", None), getattr(flow.server_conn, "sni", None)]
    return all(isinstance(n, str) and (_ascii_host(n) or n.lower().rstrip(".")) == want for n in names)


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


# ----- where a password may be put in (docs/plans/login-swap-scope.md) ---------
#
# A login's hosts are often wide (github.com, *.google.com) and hold pages where people post
# content. Putting the password into any request that carries the stand-in would let an agent that
# was talked into it write the real password into a gist or a comment. So the password goes in only
# where a sign-in sends it: the body of a POST or PUT, over https, to the login's sign-in page, to
# a form target read off that page that the owner approved, or to an address the owner added. A
# login saved as HTTP Basic gets it in `Authorization: Basic` and nowhere else. A login with no
# sign-in page gets it nowhere. Anything else that carries the stand-in to the login's own hosts is
# refused like a stand-in sent to another site.
#
# A sign-in address is a host, a path and, when it has one, a query: many sites route on the query
# (`/w/index.php?title=Special:UserLogin`), where the path alone would also be every other page.

# login_id -> {"page": the login_url the targets were read from, "targets": {address: last seen}}.
# What this process read off sign-in pages. The firewall agent takes it from the file and shows it
# to the owner; a target counts only once the owner approved it (`sign_in_targets`).
_login_targets: dict[str, dict[str, Any]] = {}
_login_targets_loaded = False


def _load_login_targets() -> None:
    global _login_targets_loaded
    if _login_targets_loaded:
        return
    _login_targets_loaded = True
    try:
        with open(LOGIN_TARGETS_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return
    if not isinstance(data, dict):
        return
    for login_id, entry in data.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("targets"), dict):
            continue
        targets: dict[str, dict[str, Any]] = {}
        for url, seen in entry["targets"].items():
            if isinstance(seen, dict) and isinstance(seen.get("seen"), (int, float)):
                targets[str(url)] = {"seen": float(seen["seen"]), "field": seen.get("field") if isinstance(seen.get("field"), str) else None}
        _login_targets[str(login_id)] = {"page": entry.get("page"), "targets": targets}


def _save_login_targets() -> None:
    known = {c["login_id"] for c in _login_entries()}
    for login_id in [k for k in _login_targets if k not in known]:
        del _login_targets[login_id]
    tmp = LOGIN_TARGETS_PATH + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(_login_targets, fh)
        os.replace(tmp, LOGIN_TARGETS_PATH)
    except OSError as exc:
        log.warning(f"[mitm] could not write {LOGIN_TARGETS_PATH}: {exc}")


def _plain_path(path: str) -> str | None:
    """The path without its query, or None when a server could read it as some other path: dot
    segments, doubled or encoded slashes, backslashes, path parameters (`..;/`), an encoded percent
    (decoded twice it can be any of these) or a fragment. Such a path matches no sign-in address."""
    if "#" in path:
        return None
    only = path.split("?", 1)[0]
    low = only.lower()
    if not only.startswith("/") or "//" in only or "\\" in only or ";" in only:
        return None
    if any(t in low for t in ("%2f", "%5c", "%2e", "%00", "%25", "%3b", "%23", "%3f")):
        return None
    if any(seg in (".", "..") for seg in only.split("/")):
        return None
    return only


_METHOD_OVERRIDE_HEADERS = frozenset({"x-http-method-override", "x-http-method", "x-method-override"})


def _no_method_override(names: "Iterable[str]") -> None:
    """A `_method` field re-dispatches the request as another verb on servers that honour it."""
    if any(name.lower() == "_method" for name in names):
        raise _NotASignIn("method")


class _NotASignIn(Exception):
    """This request does not have the exact shape of a sign-in. `why` is the reason on the record."""

    def __init__(self, why: str = "body") -> None:
        super().__init__(why)
        self.why = why


# A form field name, a query key or a JSON member that may sit in a sign-in request. Nothing a
# server folds into another name: no `[`, no space, no NUL, no control character.
_FIELD_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
# What a password field is called, when the form was not read: `password`, `pwd`, `user_password`,
# `j_password`, `wpPassword`. Never `user_login`, `comment`, `wpTextbox1`, `c`.
_PASSWORD_NAME = re.compile(r"(?:.*[_.-])?(?:pass|passwd|password|pwd|passphrase|secret)(?:[_.-].*)?", re.I)
_PASSWORD_CAMEL = re.compile(r"[A-Za-z0-9]*[a-z0-9](?:Password|Passwd|Pwd)")


def _password_name(name: str) -> bool:
    return bool(_PASSWORD_NAME.fullmatch(name) or _PASSWORD_CAMEL.fullmatch(name))


def _fold(name: str) -> str:
    """A field name as the servers that fold names read it: PHP makes `page.id` `page_id`, and
    several frameworks ignore case."""
    return name.lower().replace(".", "_")


def _decode_once(text: str) -> str | None:
    """`text` percent-decoded once, `+` as a space, or None when it is not well-formed UTF-8
    percent-encoding."""
    from urllib.parse import unquote_to_bytes
    if re.search(r"%(?![0-9A-Fa-f]{2})", text):
        return None
    try:
        return unquote_to_bytes(text.replace("+", " ")).decode("utf-8")
    except UnicodeDecodeError:
        return None


def _strict_pairs(raw: str) -> list[tuple[str, str]] | None:
    """The `key=value` pairs of a query string or a url-encoded form, read the one way every
    server reads them, or None when any server could read it another way: a character a browser
    would have encoded (a space, a control character, `;`, anything outside ASCII), a piece with
    no `=`, a key that is not a plain name, or a key given twice (under any case, `.` as `_`)."""
    if raw == "":
        return []
    if re.search(r"[^\x21-\x7e]|;", raw):
        return None
    pieces = raw.split("&")
    if len(pieces) > LOGIN_FIELDS_MAX:
        return None
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for piece in pieces:
        key_raw, eq, value_raw = piece.partition("=")
        if not eq:
            return None
        key, value = _decode_once(key_raw), _decode_once(value_raw)
        if key is None or value is None or not _FIELD_NAME.fullmatch(key) or _fold(key) in seen:
            return None
        seen.add(_fold(key))
        out.append((key, value))
    return out


_HOST_NAME = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _ascii_host(host: str) -> str | None:
    """A host name in the form it has on the wire: lower case, no trailing dot, an international
    name in punycode. None when it is not a host name."""
    host = host.lower().rstrip(".")
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return host if _HOST_NAME.fullmatch(host) else None


def is_telegram_host(host: str | None) -> bool:
    """
    `api.telegram.org`, written any way that still reaches it: any case, the root's trailing dot,
    or dots and letters that IDNA folds into those (`。`, full-width). Like `_ascii_host`, with the
    dot dropped after the encoding too, since a trailing ideographic dot becomes one.
    """
    h = (host or "").lower()
    if not h.isascii():
        try:
            h = h.encode("idna").decode("ascii")
        except UnicodeError:
            return False
    return h.rstrip(".") == "api.telegram.org"


# Telegram's published address ranges (https://core.telegram.org/resources/cidr.txt, 2026-10-15).
# Plain HTTP carries no SNI, and its `Host:` header is the agent's to write, so a request to one of
# these addresses is Telegram whatever it calls itself.
TELEGRAM_NETWORKS = [ipaddress.ip_network(n) for n in (
    "91.108.56.0/22", "91.108.4.0/22", "91.108.8.0/22", "91.108.16.0/22", "91.108.12.0/22",
    "149.154.160.0/20", "91.105.192.0/23", "91.108.20.0/22", "185.76.151.0/24",
    "2001:b28:f23d::/48", "2001:b28:f23f::/48", "2001:67c:4e8::/48", "2001:b28:f23c::/48", "2a0a:f280::/32",
)]


def is_telegram_ip(address: Any) -> bool:
    try:
        ip = ipaddress.ip_address(str(address).strip("[]"))
    except ValueError:
        return False
    # An IPv4 address written as IPv6 (::ffff:149.154.167.220) is the same address.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip in net for net in TELEGRAM_NETWORKS)


# The Bot API's shape: what a flow that is Telegram only by its address has to look like to be
# checked. The same addresses serve t.me, telegram.org and web.telegram.org, which are not.
_TG_BOT_API_PATH = re.compile(r"^/(?:file/)?bot\d+:")


def is_telegram_flow(flow: http.HTTPFlow) -> bool:
    """
    Whether this request goes to Telegram by any of the names it carries: the `Host:` header, the
    connection's host, the name the client handshook with, or the address the connection really
    goes to. A `Host:` header naming somewhere else on a connection to Telegram must not skip the
    content check, and an agent in plain mode holds the real bot token, so nothing else would stop
    that request.
    """
    if any(is_telegram_host(h) for h in (flow.request.pretty_host, flow.request.host, getattr(flow.client_conn, "sni", None))):
        return True
    server = getattr(flow, "server_conn", None)
    address = getattr(server, "address", None) if server else None
    by_address = is_telegram_ip(flow.request.host) or (bool(address) and is_telegram_ip(address[0]))
    # Telegram only by its address (the transparent redirect connects by IP): the Bot API only.
    # A t.me link or telegram.org page on the same address is a web page, not a message.
    return by_address and bool(_TG_BOT_API_PATH.match(flow.request.path.split("?", 1)[0]))


def _sign_in_address(spec: str, default: tuple[str, int] | None = None) -> dict[str, Any] | None:
    """A sign-in address as the proxy matches it, or None when it cannot be one.

    `spec` is a full https address (the login's sign-in page, a learned form target), or, when
    `default` is given, what the owner typed as an extra: `/path` (on `default`, the sign-in page's
    host and port) or `host/path`. Every address is one exact path. Only an owner's extra written
    with a trailing `/*` covers what is under it. Plain http is never a sign-in address."""
    from urllib.parse import urlsplit
    if not isinstance(spec, str) or not spec or len(spec) > 2048 or any(c.isspace() or ord(c) < 32 for c in spec):
        return None
    owner = False
    if "://" in spec:
        try:
            u = urlsplit(spec)
            port = u.port
        except ValueError:
            return None
        if u.scheme != "https" or not u.hostname or u.username or u.password or u.fragment:
            return None
        host, port, path, query = _ascii_host(u.hostname), port or 443, u.path or "/", u.query
    elif default is None:
        return None
    elif spec.startswith("/"):
        owner = True
        host, port = default
        path, _, query = spec.partition("?")
    else:
        owner = True
        name, slash, rest = spec.partition("/")
        host, port = _ascii_host(name), 443
        if not slash:
            return None
        path, _, query = ("/" + rest).partition("?")
    if host is None:
        return None
    prefix = owner and path.endswith("/*") and not query
    if prefix:
        path = path[:-1]
    # The top of a site, or everything under it, is the site: not a sign-in address an owner can
    # add. (As a login's sign-in page it parses, so its host is known, and matches nothing.)
    if owner and path == "/":
        return None
    if "#" in path or "#" in query or "*" in path or _plain_path(path) != path:
        return None
    pairs = _strict_pairs(query)
    if pairs is None or ("?" in spec and not pairs):
        return None
    return {"host": host, "port": port, "path": path, "query": sorted(pairs), "prefix": prefix, "owner": owner}


def _address_text(a: dict[str, Any]) -> str:
    from urllib.parse import urlencode
    port = "" if a["port"] == 443 else f":{a['port']}"
    return f"https://{a['host']}{port}{a['path']}" + (f"?{urlencode(a['query'])}" if a["query"] else "")


def _goes_to(flow: http.HTTPFlow, host: str, address: dict[str, Any]) -> bool:
    """Whether this request is for `address`: https, its host and port, its exact path (or under
    it, for an owner's `/*`) and exactly its query: the same keys with the same values and nothing
    else. An address with no query takes a request with no `?` at all."""
    if flow.request.scheme != "https" or _ascii_host(host) != address["host"] or flow.request.port != address["port"]:
        return False
    target = flow.request.path
    path = _plain_path(target)
    if path is None or not (path.startswith(address["path"]) if address["prefix"] else path == address["path"]):
        return False
    if "?" not in target:
        return not address["query"]
    if not address["query"]:
        return False
    pairs = _strict_pairs(target.partition("?")[2])
    return pairs is not None and sorted(pairs) == address["query"]


def _login_page(cred: dict[str, Any]) -> dict[str, Any] | None:
    """The login's sign-in page as an address, or None when it has none the proxy can use: none at
    all, one it cannot read, or the top of a site (`/`), which is every visitor's page and not a
    sign-in. `/` is not a sign-in address in any role: not as the page, not read off a page, not
    added by the owner."""
    page = _sign_in_address(str(cred.get("login_url") or ""))
    return None if page is None or page["path"] == "/" else page


def _login_host(cred: dict[str, Any], host: str) -> bool:
    return any(secret_host_matches(pattern, host) or secret_host_matches(_ascii_pattern(pattern), host) for pattern in cred.get("allowed_hosts", []))


def _ascii_pattern(pattern: str) -> str:
    """A site pattern with an international name in punycode, as requests name it."""
    star = "*." if pattern.startswith("*.") else ""
    return star + (_ascii_host(pattern[len(star):]) or pattern[len(star):])


def _spellings(text: str) -> list[str]:
    """`text` as it is and as a server may read it: percent-decoded (twice), and with JSON
    `\\uXXXX` escapes turned into their characters."""
    from urllib.parse import unquote_plus
    out = [text]
    if "%" in text or "+" in text:
        once = unquote_plus(text)
        out.append(once)
        if "%" in once:
            out.append(unquote_plus(once))
    if "\\u" in text:
        out.append(re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text))
    return out


def _login_places(flow: http.HTTPFlow, cred: dict[str, Any]) -> dict[str, Any]:
    """Where this request carries the login's stand-in, in any spelling a server would read as it:
    in the path, in the query (keys too), in a header (every one but the navigation headers the
    browser fills in by itself; `Cookie` and `Proxy-Authorization` count), in the body."""
    placeholder = cred.get("placeholder") or ""
    found = _placeholder_re(placeholder)
    seen = lambda text: any(found.search(t) for t in _spellings(text))
    try:
        body = flow.request.get_text(strict=False) or ""
    except ValueError:
        body = ""
    raw = flow.request.raw_content or b""
    # Every spelling is looked for in a body the size of a form. A large body (an upload) is only
    # searched for the stand-in as written: it can never be a sign-in, so nothing is put in.
    # The bytes as they are, too: the declared charset is the client's to choose, and a body
    # declared UTF-16 that is plain ASCII would otherwise read here as noise.
    plain = raw.decode("latin-1")
    in_body = (seen(body) or seen(plain)) if len(raw) <= 4 * LOGIN_BODY_MAX else bool(found.search(body) or found.search(plain))
    if not in_body and raw and b"\x00" in raw and len(raw) <= 4 * LOGIN_BODY_MAX:
        # A form sent as UTF-16 reads as the stand-in to a server that honours the charset.
        in_body = any(found.search(raw.decode(codec, "ignore")) for codec in ("utf-16-le", "utf-16-be"))
    path_only, _, query = flow.request.path.partition("?")
    headers = []
    for name in sorted({k.lower() for k in flow.request.headers.keys()}):
        if name in _NAVIGATION_HEADERS:
            continue
        values = flow.request.headers.get_all(name)
        decoded = [d for d in (_basic_credentials(v) for v in values) if d is not None] if name in ("authorization", "proxy-authorization") else []
        if any(seen(v) for v in values + decoded):
            headers.append(name)
    return {"body": body, "in_path": seen(path_only), "in_query": seen(query), "in_body": in_body, "headers": headers}


def _only_basic_header(flow: http.HTTPFlow, places: dict[str, Any], placeholder: str | None = None) -> bool:
    """The stand-in is in an HTTP Basic `Authorization` header and nowhere else. With
    `placeholder`, it also has to be the whole password, not a part of it or the user name."""
    if places["in_path"] or places["in_query"] or places["in_body"] or places["headers"] != ["authorization"]:
        return False
    decoded = [_basic_credentials(v) for v in flow.request.headers.get_all("authorization")]
    if len(decoded) != 1 or decoded[0] is None:
        return False
    return placeholder is None or decoded[0].partition(":")[2] == placeholder


def _carries(found: "re.Pattern[str]", text: str) -> bool:
    return any(found.search(t) for t in _spellings(text))


def _content_type(flow: http.HTTPFlow) -> str | None:
    """`form` or `json` when the request says so the way a browser does: one `Content-Type` line,
    exactly `application/x-www-form-urlencoded` or `application/json`, with no parameter but
    `charset=utf-8`. Anything else is None. The type is never guessed from the body: a body two
    servers would read as two different things is how a password ends up in the wrong field."""
    lines = flow.request.headers.get_all("content-type")
    if len(lines) != 1:
        return None
    m = re.fullmatch(r"application/(x-www-form-urlencoded|json)(?:; ?charset=(?:utf-8|UTF-8))?", lines[0])
    return None if m is None else ("form" if m.group(1) == "x-www-form-urlencoded" else "json")


def _body_text(flow: http.HTTPFlow) -> str:
    """The body as UTF-8 text. Refused when it is long, compressed, not UTF-8, or starts with a
    byte-order mark: a sign-in is none of these."""
    raw = flow.request.raw_content or b""
    if len(raw) > LOGIN_BODY_MAX or flow.request.headers.get("content-encoding") or flow.request.headers.get("transfer-encoding", "").lower() not in ("", "chunked"):
        raise _NotASignIn()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _NotASignIn() from None
    if text.startswith("\ufeff") or "\x00" in text:
        raise _NotASignIn()
    return text


def _strict_json(text: str) -> Any:
    """`text` as JSON, refused when it nests deeper than a sign-in does, gives a member twice
    (parsers disagree on which one counts), or holds `NaN` and its kin."""
    depth = 0
    quoted = escaped = False
    for ch in text:
        if quoted:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
        elif ch in "[{":
            depth += 1
            if depth > LOGIN_JSON_DEPTH_MAX:
                raise _NotASignIn()
        elif ch in "]}":
            depth -= 1

    def members(items: list[tuple[str, Any]]) -> dict[str, Any]:
        if len({k for k, _ in items}) != len(items):
            raise _NotASignIn()
        return dict(items)

    def constant(_name: str) -> Any:
        raise _NotASignIn()

    try:
        return json.loads(text, object_pairs_hook=members, parse_constant=constant)
    except (ValueError, RecursionError):
        raise _NotASignIn() from None


def _strings(node: Any) -> "Iterator[str]":
    """Every string in a JSON value, at any depth. A member name comes marked, so that a name
    that is the stand-in is never taken for a value that is."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)
    elif isinstance(node, dict):
        for key, item in node.items():
            yield "\x00key:" + key
            yield from _strings(item)


def _sign_in_field(flow: http.HTTPFlow, placeholder: str) -> tuple[str, list[tuple[str, str]]]:
    """The one field of this request that holds the stand-in as its whole value, and the form's
    fields (empty for JSON). Raises `_NotASignIn` for every body that is not one of the two shapes
    a browser sign-in sends:

      form  `application/x-www-form-urlencoded`: plain field names, each once, and exactly one
            field whose value is the stand-in and nothing else.
      json  `application/json`: an object, and exactly one of its top-level members whose value is
            the string that is the stand-in and nothing else.

    The stand-in anywhere else in the body (a second field, part of a value, a field name, deeper
    in the JSON, in an array, in any spelling but the literal one) refuses the request. Multipart,
    XML, plain text and everything else are refused: sign-ins do not use them."""
    found = _placeholder_re(placeholder)
    kind = _content_type(flow)
    if kind is None:
        raise _NotASignIn()
    text = _body_text(flow)
    if len(found.findall(text)) != 1:
        raise _NotASignIn()
    if kind == "form":
        pairs = _strict_pairs(text)
        if pairs is None:
            raise _NotASignIn()
        _no_method_override(k for k, _ in pairs)
        holders = [k for k, v in pairs if v == placeholder]
        if len(holders) != 1 or any(_carries(found, k) or (v != placeholder and _carries(found, v)) for k, v in pairs):
            raise _NotASignIn()
        return holders[0], pairs
    doc = _strict_json(text)
    if not isinstance(doc, dict) or len(doc) > LOGIN_FIELDS_MAX:
        raise _NotASignIn()
    _no_method_override(doc)
    holders = [k for k, v in doc.items() if isinstance(v, str) and v == placeholder]
    if len(holders) != 1 or sum(1 for t in _strings(doc) if _carries(found, t)) != 1:
        raise _NotASignIn()
    return holders[0], []


def _google_sign_in(flow: http.HTTPFlow, placeholder: str) -> None:
    """Google's sign-in, as its page sends it (captured on a real box, T-googleshape):

        POST /v3/signin/_/AccountsSignInUi/data/batchexecute?rpcids=B4hajb&…
        Content-Type: application/x-www-form-urlencoded;charset=UTF-8
        f.req=<JSON>&at=<token>&

    The form ends with a `&`. `f.req` is the `batchexecute` envelope `[[[rpc, payload, null,
    "generic"]]]`, and `payload` is a string that is JSON again, in which the stand-in is the whole
    string at `[3][4][0]` (`[1,1,null,[1,null,null,null,[<stand-in>,null,1]],…]`) and nowhere else.
    That shape and no other; raises `_NotASignIn` otherwise. If Google changes it, the sign-in is
    refused (`body`) until the new shape is captured and added here."""
    found = _placeholder_re(placeholder)
    if _content_type(flow) != "form":
        raise _NotASignIn()
    text = _body_text(flow)
    # The one `&` Google's page ends the form with. Any other empty piece is refused below.
    pairs = _strict_pairs(text[:-1] if text.endswith("&") else text)
    if pairs is None or len(found.findall(text)) != 1:
        raise _NotASignIn()
    _no_method_override(k for k, _ in pairs)
    exact = 0
    for key, value in pairs:
        if _carries(found, key):
            raise _NotASignIn()
        if not _carries(found, value):
            continue
        if key != "f.req":
            raise _NotASignIn()
        envelope = _strict_json(value)
        if not (isinstance(envelope, list) and len(envelope) == 1 and isinstance(envelope[0], list) and len(envelope[0]) == 1):
            raise _NotASignIn()
        call = envelope[0][0]
        if not (isinstance(call, list) and len(call) == 4 and isinstance(call[0], str) and isinstance(call[1], str) and call[2] is None and isinstance(call[3], str)):
            raise _NotASignIn()
        if _carries(found, call[0]) or _carries(found, call[3]):
            raise _NotASignIn()
        payload = _strict_json(call[1])
        # Where the password sits in the payload: `payload[3][4][0]`.
        at = payload
        for index in (3, 4):
            at = at[index] if isinstance(at, list) and len(at) > index else None
        if not (isinstance(at, list) and at and at[0] == placeholder) or sum(1 for t in _strings(payload) if _carries(found, t)) != 1:
            raise _NotASignIn()
        exact += 1
    if exact != 1:
        raise _NotASignIn()


def login_scope(flow: http.HTTPFlow, cred: dict[str, Any], host: str, places: dict[str, Any]) -> tuple[str | None, str | None]:
    """Whether the password may go into this request. `(scope, None)` when it may: `basic` (the
    HTTP Basic header of a login saved as one) or `page` (a sign-in address). `(None, why)` when it
    may not:

      http     not https: a password is never put into plain http
      header   a login saved as HTTP Basic, anywhere but as that header's whole password
      place    not the body of a POST or PUT
      basic    an HTTP Basic header, on a login that is not saved as one
      method   the request asks to be run as another verb (`_method`, `X-HTTP-Method-Override`)
      body     not one of the two exact shapes a sign-in sends (`_sign_in_field`)
      no_page  the login has no sign-in page (or one that cannot be read)
      pending  a form target read off the sign-in page that the owner has not approved yet
      expired  an approved target that has not been on the sign-in page for 30 days
      field    a sign-in address, but not the password field
      page     not a sign-in address
    """
    placeholder = cred.get("placeholder") or ""
    if flow.request.scheme != "https":
        return None, "http"
    # Rails, Laravel and others let a request say it is really another verb: the POST the proxy
    # checked is then run as a PUT, PATCH or DELETE on the same path, which is some other action
    # than the sign-in. A sign-in never asks for that.
    if any(name.lower() in _METHOD_OVERRIDE_HEADERS for name in flow.request.headers.keys()) or re.search(r"(?:^|[?&])_method=", flow.request.path.partition("?")[2], re.I):
        return None, "method"
    if cred.get("login_auth") == "basic":
        return ("basic", None) if _only_basic_header(flow, places, placeholder) else (None, "header")
    if places["in_path"] or places["in_query"] or places["headers"] or flow.request.method not in ("POST", "PUT"):
        return None, "basic" if _only_basic_header(flow, places) else "place"
    here = _ascii_host(host) or ""
    try:
        # Google's sign-in is built in JavaScript: there is no form to read, so its path and its
        # one body shape are known here.
        for known in LOGIN_KNOWN_SIGN_IN.get(here, ()):
            path = _plain_path(flow.request.path)
            if flow.request.port == 443 and path is not None and path.startswith(known):
                _google_sign_in(flow, placeholder)
                return "page", None
        field, pairs = _sign_in_field(flow, placeholder)
    except _NotASignIn as refused:
        return None, refused.why
    # The sign-in page names the host that bare extra addresses are on, even when it is the top
    # of a site and so no sign-in address itself.
    base = _sign_in_address(str(cred.get("login_url") or ""))
    if base is None:
        return None, "no_page"
    page = _login_page(cred)
    known_fields = _login_fields(cred)

    def at(address: dict[str, Any]) -> tuple[str | None, str | None]:
        # The form may not name one of the address's own query keys with another value: a server
        # that reads the form before the address (PHP's `$_REQUEST`, MediaWiki) would follow it.
        routing = {_fold(k): (k, v) for k, v in address["query"]}
        for k, v in pairs:
            if _fold(k) in routing and (k, v) != routing[_fold(k)]:
                return None, "page"
        # The password field: the one the sign-in form has, when the form was read; otherwise a
        # field that is named like one.
        want = known_fields.get(_address_text(address))
        if field != want if want is not None else not _password_name(field):
            return None, "field"
        return "page", None

    if page is not None and _goes_to(flow, host, page):
        return at(page)
    refused = set(cred.get("refused_targets") or [])
    for target in cred.get("sign_in_targets") or []:
        address = None if target in refused else _sign_in_address(str(target))
        if address and address["path"] != "/" and _login_host(cred, address["host"]) and _goes_to(flow, host, address):
            return at(address)
    # Checked again here, whatever the firewall page let through: only on the host the owner
    # named (a bare path is the sign-in page's own host and port), one exact path unless it was
    # written with `/*`, and never the top of a site or everything under it.
    for extra in cred.get("sign_in_paths") or []:
        address = _sign_in_address(str(extra), (base["host"], base["port"]))
        if address and _login_host(cred, address["host"]) and _goes_to(flow, host, address):
            return at(address)
    for target in cred.get("expired_targets") or []:
        address = _sign_in_address(str(target))
        if address and _goes_to(flow, host, address):
            return None, "expired"
    for target in _login_pending(cred):
        address = _sign_in_address(target)
        if address and _goes_to(flow, host, address):
            return None, "pending"
    return None, "page"


def _login_fields(cred: dict[str, Any]) -> dict[str, str]:
    """address -> the name of the password field of the sign-in form that posts there, for the
    forms that were read: what the firewall agent kept, and what this process read since. Knowing
    it only ever narrows: the password then goes into that field and no other."""
    _load_login_targets()
    out = {str(u): str(f) for u, f in (cred.get("sign_in_fields") or {}).items() if isinstance(f, str) and f}
    mine = _login_targets.get(str(cred.get("login_id")))
    if mine and mine.get("page") == cred.get("login_url"):
        for url, entry in mine["targets"].items():
            if entry.get("field"):
                out.setdefault(url, entry["field"])
    return out


def _login_pending(cred: dict[str, Any]) -> set[str]:
    """Form targets read off the sign-in page that the owner has not approved: what the firewall
    agent already knows of, and what this process read since. Only used to say why a request was
    refused."""
    _load_login_targets()
    out = {str(u) for u in cred.get("pending_targets") or []}
    mine = _login_targets.get(str(cred.get("login_id")))
    if mine and mine.get("page") == cred.get("login_url"):
        out |= set(mine["targets"])
    return out - set(cred.get("refused_targets") or []) - {str(u) for u in cred.get("sign_in_targets") or []}


def login_out_of_scope(flow: http.HTTPFlow, vm_id: str | None = None) -> tuple[dict[str, Any], str] | None:
    """A login whose stand-in this request carries to one of its own hosts, but not where a
    sign-in sends it. `(login, why)`, or None."""
    host = flow.request.pretty_host
    for cred in credentials_for(host, vm_id):
        if not cred.get("login_id") or not cred.get("placeholder"):
            continue
        # A short stand-in (a PIN) can turn up in a page's own requests by chance. It is not put in
        # outside a sign-in either (`apply_login_swap`), but it is not an alarm.
        if len(cred["placeholder"]) < LOGIN_SHORT:
            continue
        places = _login_places(flow, cred)
        if not (places["in_path"] or places["in_query"] or places["in_body"] or places["headers"]):
            continue
        scope, why = login_scope(flow, cred, host, places)
        if scope is None:
            return cred, why or "page"
    return None


_LOGIN_BLOCK_TEXT = {
    "http": "This request is plain http. The firewall never puts a password into a connection that is not encrypted, so it blocked the request and recorded the attempt. Use the site's https address.",
    "header": "This login is saved as an HTTP Basic login: its password placeholder only works as the password of an HTTP Basic Authorization header. It was somewhere else in the request, so the firewall blocked it and recorded the attempt.",
    "page": "This password placeholder only works in the sign-in request of the login's sign-in page. This request went somewhere else on the site, so the firewall blocked it and recorded the attempt. If this is how the site signs in, ask the owner to add this address to the login on the firewall page (ControlClaw, Secrets, Website logins).",
    "pending": "The firewall read this address off the login's sign-in page, but the owner has not approved it yet, so the request was blocked and recorded. Ask the owner to open the login on the firewall page (ControlClaw, Secrets, Website logins) and tick this address under 'Read off the sign-in page'. Then sign in again.",
    "no_page": "This login has no sign-in page, so the firewall does not know which request is the sign-in and puts the password nowhere. The request was blocked and recorded. Ask the owner to add the sign-in page to the login on the firewall page (ControlClaw, Secrets, Website logins).",
    "body": "The sign-in request did not look like this site's sign-in, so the firewall blocked it and recorded the attempt. The password placeholder only works as the whole value of one field of an ordinary sign-in form (or of one top-level field of a JSON sign-in): not inside a longer text, in more than one field, in a file upload, or in a body the firewall does not read as a sign-in. Type only the placeholder into the password field of the sign-in page and submit that form. If you did exactly that, the site sends its sign-in in a way the firewall does not know: do not retry, tell the owner that Activity shows the block and that they can save the login again as 'Typed into the page' (ControlClaw, Secrets, Website logins) or sign you in themselves.",
    "field": "This password placeholder only works in the password field of the login's sign-in form. It was in another field, so the firewall blocked the request and recorded the attempt.",
    "method": "This request asks the site to run it as another kind of request (a _method field or an X-HTTP-Method-Override header). A sign-in never does that, so the firewall blocked it and recorded the attempt.",
    "error": "The firewall could not check this request, which carries a password placeholder, so it blocked it and recorded the attempt.",
    "expired": "The owner allowed this sign-in address, but it has not been on the login's sign-in page for 30 days, so the firewall stopped using it and blocked the request. Open the login's sign-in page again and retry; if it is still blocked, ask the owner to look at the login on the firewall page (ControlClaw, Secrets, Website logins).",
    "place": "This password placeholder only works in the body of the sign-in form (a POST). It was in the address, a header or another kind of request, so the firewall blocked it and recorded the attempt. Type it into the password field of the sign-in page and submit the form.",
    "basic": "This login is not saved as an HTTP Basic login, so its password placeholder does not work in an Authorization header. The firewall blocked the request and recorded the attempt. If the site signs in with HTTP Basic, ask the owner to save the login again as HTTP Basic on the firewall page (ControlClaw, Secrets, Website logins).",
}

# A sign-in page is read for its forms only up to this many characters once decoded, and only for
# this long. A page built to make a parser slow teaches nothing and costs the proxy nothing.
LOGIN_PAGE_TEXT_MAX = 256 * 1024
LOGIN_PARSE_BUDGET_S = 0.2
_LOGIN_TAG_MAX = 4096
# Elements whose content is text, not markup: a form written inside one is not a form.
_RAW_TEXT = ("script", "style", "textarea", "template", "title", "noscript", "xmp", "iframe", "noembed", "noframes", "plaintext")
_ATTR = re.compile(r"""([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`]+)))?""")
_USER_FIELD = re.compile(r"user|email|e-mail|login|account|ident|name", re.I)
# What a sign-up or a change-of-password form looks like. Such a form is not offered to the owner.
_NOT_SIGN_IN_FIELD = re.compile(r"confirm|repeat|retype|again|verify|new[-_ ]?pass|password[-_]?2|pass2|pw2", re.I)
_NOT_SIGN_IN_FORM = re.compile(r"regist|sign[-_ ]?up|join|create[-_ ]?account|new[-_ ]?user|enroll|subscribe", re.I)


def password_form_targets(html: str) -> list[tuple[str, str]] | None:
    """`(action, name of the password field)` for each POST form on a sign-in page that is a
    sign-in form: one named password field that is not for a new password, a field for a user name
    or an email, and nothing that makes it look like a sign-up (more than two fields to type in, a
    field to confirm or repeat something, "register", "signup" or "join" in its action, id or name).

    None when the page cannot be trusted to say where its forms go (`<base href>`), is too long, or
    took too long. A scanner of its own rather than `html.parser`: that one is quadratic on unclosed
    comments and tags, and this runs on the proxy's event loop. Every step moves forward, a tag is
    read at most `_LOGIN_TAG_MAX` characters far, and the whole thing stops at the time budget."""
    if len(html) > LOGIN_PAGE_TEXT_MAX:
        return None
    deadline = time.monotonic() + LOGIN_PARSE_BUDGET_S
    actions: list[tuple[str, str]] = []
    form: dict[str, Any] | None = None

    def close() -> None:
        nonlocal form
        if form and form["method"] == "post" and form["passwords"] == 1 and form["field"] and form["user"] and not form["new"] and form["typed"] <= 2:
            actions.append((form["action"], form["field"]))
        form = None

    low = html.lower()
    i, steps = 0, 0
    while True:
        i = html.find("<", i)
        if i < 0:
            break
        steps += 1
        if steps % 64 == 0 and time.monotonic() > deadline:
            return None
        if low.startswith("<!--", i):
            end = html.find("-->", i + 4)
            if end < 0:
                break
            i = end + 3
            continue
        end = html.find(">", i + 1, i + _LOGIN_TAG_MAX)
        if end < 0:
            i += 1
            continue
        tag = html[i + 1:end]
        i = end + 1
        m = re.match(r"/?([a-zA-Z][a-zA-Z0-9]*)", tag)
        if not m:
            continue
        name = m.group(1).lower()
        if tag.startswith("/"):
            if name == "form":
                close()
            continue
        if name == "textarea" and form is not None:
            form["typed"] += 1
        if name in _RAW_TEXT:
            end = low.find("</" + name, i)
            if end < 0:
                break
            i = end
            continue
        # Attribute values are character data: `&amp;` in an action is `&`.
        attrs = {a.group(1).lower(): html_unescape(a.group(2) or a.group(3) or a.group(4) or "") for a in _ATTR.finditer(tag[m.end():])}
        if name == "base" and "href" in attrs:
            return None
        if name == "form":
            close()
            form = {"action": attrs.get("action", ""), "method": attrs.get("method", "get").strip().lower(), "passwords": 0, "field": "", "user": False, "typed": 0,
                    "new": bool(_NOT_SIGN_IN_FORM.search(" ".join(attrs.get(k, "") for k in ("action", "id", "name", "class"))))}
        elif name in ("input", "textarea", "select") and form is not None:
            kind = attrs.get("type", "text").strip().lower() if name == "input" else name
            label = " ".join(attrs.get(k, "") for k in ("name", "id", "autocomplete"))
            if _NOT_SIGN_IN_FIELD.search(label):
                form["new"] = True
            if kind == "password":
                form["passwords"] += 1
                form["field"] = attrs.get("name", "")
                if attrs.get("autocomplete", "").strip().lower() == "new-password":
                    form["new"] = True
            elif kind in ("text", "email", "tel", "url", "number", "search", "date", "textarea", "select"):
                form["typed"] += 1
                if kind in ("text", "email", "tel") and (kind == "email" or _USER_FIELD.search(label)):
                    form["user"] = True
    close()
    return actions


def learn_login_targets(flow: http.HTTPFlow) -> None:
    """Many sites post the password to another address than the page (GitHub: `/login` posts to
    `/session`). When the agent loads a login's sign-in page, the sign-in form on it says where:
    that address is written down for the login. It does not count yet: the firewall agent shows it
    to the owner, and the password goes there only once the owner approved it."""
    if not flow.response or flow.request.method != "GET" or flow.response.status_code != 200:
        return
    vm_id = flow.metadata.get("cc_vm_id")
    host = flow.request.pretty_host
    # The page has to come from the site itself. `Host:` is the agent's to write, and behind the
    # transparent redirect the connection goes to whatever address the agent dialled; the TLS name
    # on both sides is what the upstream certificate was checked against. No TLS name, no lesson.
    if flow.request.scheme != "https" or not _tls_names_are(flow, host):
        return
    logins = [c for c in credentials_for(host, vm_id) if c.get("login_id") and c.get("login_url") and c.get("login_auth") != "basic"]
    if not logins or "html" not in (flow.response.headers.get("content-type") or "").lower():
        return
    # The page itself, query and all: `?title=User:Mallory` is not `?title=Special:UserLogin`, and
    # a page saved with no query is not that path with one.
    pages = [(c, _login_page(c)) for c in logins]
    logins = [c for c, page in pages if page is not None and _goes_to(flow, host, page)]
    if not logins or not flow.response.raw_content or len(flow.response.raw_content) > LOGIN_PAGE_MAX:
        return
    from urllib.parse import urljoin
    try:
        actions = password_form_targets(flow.response.get_text(strict=False) or "")
    except Exception:  # a page that cannot be read teaches nothing
        return
    if not actions:
        return
    page_url = "https://" + (_ascii_host(host) or host.lower()) + ("" if flow.request.port == 443 else f":{flow.request.port}") + flow.request.path.split("#", 1)[0]
    now = time.time()
    changed = False
    _load_login_targets()
    for cred in logins:
        refused = set(cred.get("refused_targets") or [])
        entry = _login_targets.get(cred["login_id"])
        if not entry or entry.get("page") != cred["login_url"]:
            entry = _login_targets[cred["login_id"]] = {"page": cred["login_url"], "targets": {}}
            changed = True
        targets = entry["targets"]
        for action, field in actions:
            address = _sign_in_address(urljoin(page_url, action.strip()).split("#", 1)[0])
            # The top of a site is not a sign-in address a page can teach.
            if address is None or address["path"] == "/" or not _login_host(cred, address["host"]):
                continue
            target = _address_text(address)
            if target in refused:
                continue
            # Written again at most once a day for a target already known.
            known = targets.get(target)
            if known is None or known["seen"] + 86400 < now or known.get("field") != field:
                targets[target] = {"seen": now, "field": field}
                changed = True
        for stale in [u for u, entry in targets.items() if entry["seen"] + LOGIN_TARGET_TTL_S <= now or u in refused]:
            del targets[stale]
            changed = True
        while len(targets) > LOGIN_TARGETS_MAX:
            del targets[min(targets, key=lambda u: targets[u]["seen"])]
            changed = True
    if changed:
        _save_login_targets()


def apply_login_swap(flow: http.HTTPFlow, cred: dict[str, Any], host: str) -> bool:
    placeholder = cred.get("placeholder") or ""
    secret = _secret_value(cred) or ""
    if not placeholder or not secret:
        return False
    places = _login_places(flow, cred)
    if not (places["in_body"] or places["in_query"] or places["in_path"] or places["headers"]):
        return False
    # `request` refuses an out-of-scope request before it gets here. Checked again so that no
    # other caller can put a password where a sign-in would not.
    try:
        scope, _why = login_scope(flow, cred, host, places)
    except Exception:  # a request the check cannot read gets no password
        return False
    if scope is None:
        return False
    if not _login_destination_ok(flow, host):
        return False
    if scope == "basic":
        flow.request.headers.set_all("authorization", [_swap_login_header("authorization", v, placeholder, secret) for v in flow.request.headers.get_all("authorization")])
        flow.metadata.setdefault("cc_login_in", []).append("header")
    else:
        # `login_scope` has read the body as exactly one of these two, with the stand-in once.
        body = _body_text(flow)
        if _content_type(flow) == "form":
            flow.request.set_text(swap_login_form(body, placeholder, secret))
        else:
            flow.request.set_text(swap_login_text(body, placeholder, secret, "json"))
        flow.metadata.setdefault("cc_login_in", []).append("body")
    # For the log record and the AI review: where the password went and why it was allowed there
    # (never the values).
    flow.metadata["cc_login_scope"] = scope
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
    if flow.request.scheme != "https":
        # Plain HTTP would carry the real secret in clear to whoever answers on port 80; the
        # placeholder goes out as it is instead (T-sni, docs/ops/t-sni-passthrough.md).
        return applied

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
    if "effect" in record:
        # Always there, null when no Websites rule decided: it tells the console this firewall sends
        # rule ids, so it never falls back to matching a rule by the record's label
        # (docs/plans/rule-metrics.md).
        record.setdefault("rule_id", None)
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
    ref = flow.metadata.get("cc_rule_ref")
    if ref is not None and ref[1] == rec["rule"]:
        rec["rule_id"] = ref[0]
    if flow.metadata.get("cc_email_sent"):
        rec["email"] = "sent"
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


def encode_host(host: str) -> bytes | None:
    """The hostname as it goes on the wire, or None if it cannot go there at all.

    A browser will happily put things in an SNI that `idna` refuses: a label over 63 bytes, a
    trailing dot, an underscore. Finding that out inside a handshake generator raises through
    `TunnelLayer`, which does not guard it, and the flow dies as an unhandled proxy error instead
    of the logged fail-closed record. So it is decided before the stack is built.
    """
    if not host or len(host) > 253:
        return None
    if is_ip_literal(host):
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
        **({"rule_id": str(rule["id"])[:64]} if rule and rule.get("id") else {}),
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
        "rule": rule.get("name") or rule.get("match_domain"), "rule_id": str(rule["id"])[:64] if rule.get("id") else None,
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
    proxy (CONNECT-by-host) AND transparent redsocks (CONNECT-by-IP). The SNI is only a name the
    client wrote, so the connection is then sent to that name and nowhere else (`_pass_through`):
    before 2026-10-28 it went to whatever address the box asked for, which made a forged SNI an
    uninspected tunnel to any IP. The built-in hosts pass on port 443 only.

    Defensive: a raised exception here would stall the handshake, so a match error never takes down
    an interceptable connection.
    """
    try:
        sni = (getattr(getattr(data, "client_hello", None), "sni", None) or "").lower()
        if not sni:
            return
        if sni in MEETING_MEDIA_RANGES:
            return
        ctx = getattr(data, "context", None)
        host, port = _server_addr(ctx)
        vm_id = ctx_vm_id(ctx)
        if residential_rule(sni, port, vm_id) is not None:
            # Residential is decided in `next_layer`, which runs first and has the ClientHello.
            # Reaching here means that decision was missed, and `ignore_connection` would send the
            # flow out of THIS box's IP — the one outcome a residential rule must never produce.
            log.error(f"[mitm] residential rule reached tls_clienthello for {sni}; refusing to pass through")
            return
        # Under an emergency stop the ONLY destination that still passes through is the control
        # plane: the vm-agent's own channel rides it, and so does the relay an owner uses to unlock
        # a box's disk. Everything else — the backup store, Tailscale, every `tunnel` rule the
        # organisation wrote — is intercepted and refused in `request`, because a passed-through
        # connection is one this proxy never sees again. (`tunnel_match` is None for a stopped box.)
        if kill_switched(vm_id):
            built_in: tuple[str, ...] = (CONTROL_PLANE_HOST,) if CONTROL_PLANE_HOST else ()
        else:
            built_in = PASSTHROUGH_HOSTS + (TAILSCALE_HOSTS if tailscale_allowed(vm_id) else ())
        if (
            (port == PASSTHROUGH_PORT and any(host_matches(h, sni) for h in built_in))
            or tunnel_match(sni, port, vm_id)
        ):
            _pass_through(data, ctx, sni, host, port, vm_id)
    except Exception as exc:  # noqa: BLE001 — never break interception over a match error
        log.warning(f"[mitm] tls_clienthello passthrough check failed: {exc}")


def _wire_name(name: str) -> str:
    """A name as it is compared: `_ascii_host`'s form, or lower case without the root's dot."""
    return _ascii_host(name) or name.lower().strip("[]").rstrip(".")


def is_ip_literal(host: str) -> bool:
    """True when `host` is an IP address (v4 or v6, brackets and a zone allowed), not a name."""
    return _unwrapped_ip((host or "").strip("[]")) is not None


def _pass_through(data, ctx, sni: str, host: str, port: int | None, vm_id: str | None) -> None:
    """Pass a connection matched by its SNI through, to that name and nowhere else.

    - Asked for by IP (redsocks, or a client that connected to an address): the upstream becomes the
      SNI, so the firewall resolves it with its own resolver in `server_connect`. Which of the
      name's addresses the box picked does not matter, so a CDN or S3 handing out a different one
      each time changes nothing; an address the name does not have is never reached.
    - Asked for by another NAME (the explicit proxy, `CONNECT evil.example:443` with the control
      plane as SNI): refused, with a `block` record. The client said two different things.
    - Either way the connection is marked, and `server_connect` refuses it unless every address the
      name resolves to is public: an uninspected connection never goes to a private range (other
      agents, the firewall's own listeners).

    A refused connection is still marked `ignore_connection`, so it is not intercepted instead:
    `server.error` closes it before anything is dialled.
    """
    server = ctx.server
    if _wire_name(host) != _wire_name(sni):
        if not is_ip_literal(host):
            why = f"the TLS name is {sni[:80]} but the connection was asked for {host[:80]}"
            server.error = f"{NON_ROUTABLE_REFUSAL} {why}"
            data.ignore_connection = True
            _log(_non_routable_record(vm_id, sni, port, why, rule=DESTINATION_RULE))
            log.warning(f"[mitm] refused passthrough to {host}:{port}: {why}")
            return
        if server.connected:
            # Only with `connection_strategy=eager`, which this firewall does not run: the socket to
            # the box's address is already open and cannot be moved. Leave the connection to be
            # intercepted, where `request` checks it by name like any other.
            log.error(f"[mitm] {sni} was asked for by address {host}, already connected; not passing it through")
            return
        server.address = (sni, port)
    server.cc_uninspected = True
    data.ignore_connection = True


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
                # Matched by the very address it dials, so there is no name to disagree with; it is
                # still uninspected, so `server_connect` keeps it off private ranges.
                ctx.server.cc_uninspected = True
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
        **({"rule_id": meta["rule_id"]} if meta.get("rule_id") else {}),
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


def _unwrapped_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """`ip` as an address, looking through the IPv6 forms that carry an IPv4 address
    (`::ffff:169.254.169.254`, NAT64). None when it is not an address."""
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return addr.ipv4_mapped
        if addr in _NAT64:
            return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return addr


# Smoke tests only: their stand-in servers sit on Docker's private networks.
_DEV_PRIVATE_PASSTHROUGH = os.environ.get("MITM_DEV_PRIVATE_PASSTHROUGH", "") not in ("", "0")


def is_public_ip(ip: str) -> bool:
    """True for an address on the public internet: not 10/8, 172.16/12, 192.168/16, 100.64/10 (the
    agents' and the firewall's own networks), nor anything else `ipaddress` does not call global."""
    addr = _unwrapped_ip(ip)
    if addr is not None and _DEV_PRIVATE_PASSTHROUGH and addr.is_private and non_routable_kind(ip) is None:
        return True
    return addr is not None and addr.is_global


def is_own_address(ip: str) -> bool:
    """True when `ip` is an address of this machine (any interface: the firewall's public and private
    IPs, Docker's bridge). Asked of the kernel, which lets a socket bind only to its own addresses, so
    it stays right when an address changes. With `ip_nonlocal_bind` on, every address would look
    local and every connection would be refused: closed, not open."""
    addr = _unwrapped_ip(ip)
    if addr is None or addr.is_link_local:
        return False  # link-local is refused as non-routable before this is asked
    family = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.bind((str(addr), 0))
        return True
    except OSError:
        return False


def non_routable_kind(ip: str) -> str | None:
    """Why `ip` is a target the firewall refuses, or None if it may be connected to."""
    addr = _unwrapped_ip(ip)
    if addr is None:
        return None
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


async def check_target(host: str, port: int | None, strict: bool, public_only: bool = False) -> tuple[str | None, str | None]:
    """Resolve `host` and refuse it if ANY address is non-routable, so a name that points at the
    metadata address is refused like the address itself. Returns (address to connect to, refusal).
    With `strict`, a name that does not resolve is refused too: the caller is about to connect, and
    connecting would resolve again — the answer we checked must be the one that is used. With
    `public_only` (a connection passed through uninspected), a private or other non-public address
    is refused as well: other agents and the firewall's own listeners are on those."""
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
        shown = host if host == ip else f"{host} ({ip})"
        if kind:
            return None, f"{shown[:120]} is a {kind} address; the firewall never connects there"
        if is_own_address(ip):
            # Dialled from here, the firewall's own listeners (the mitm-agent on 3100, the gates on
            # 39xx) would be reached over the loopback path, past the Hetzner firewall and UFW, and
            # from the firewall's own address. A name like <ip>.sslip.io is enough to ask for it.
            return None, f"{shown[:120]} is this firewall's own address; the firewall never connects there"
        if public_only and not is_public_ip(ip):
            return None, f"{shown[:120]} is not a public address; an uninspected connection never goes there"
    if not ips:
        return None, (f"could not resolve {host[:60]}" if strict else None)
    # Prefer IPv4, as most of these boxes route it; any address in the list passed the check.
    return next((ip for ip in ips if ":" not in ip), ips[0]), None


def _non_routable_record(vm_id: str | None, host: str, port: int | None, why: str, flow_id: str | None = None,
                         rule: str = NON_ROUTABLE_RULE) -> dict[str, Any]:
    return {
        "flow_id": flow_id or "nr_" + hashlib.sha256(f"{time.time()}{host}{port}".encode()).hexdigest()[:24],
        "ts": time.time(), "tenant": TENANT, "vm_id": vm_id,
        "host": host, "port": port, "effect": "block", "rule": rule, "error": why[:200],
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
    if getattr(server, "error", None):
        return  # already refused (`_pass_through`); nothing to resolve
    host, port = str(addr[0]), addr[1]
    try:
        ip, why = await check_target(host, port, strict=True, public_only=getattr(server, "cc_uninspected", False))
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


def _voice_judged(voice: dict[str, Any], message, event: Any) -> bool:
    """
    Whether `content_rules_voice` reads this frame's text: a question to the main agent, its answer,
    the box's spoken lines. Only these wait for the AI; audio and everything else never do.
    """
    if not isinstance(event, dict) or getattr(message, "injected", False):
        return False
    kind = event.get("type")
    if voice.get("family") == "live":
        if not message.from_client:
            return kind == "session.delegation.created"
        if kind == "session.commentary.append":
            return True
        return kind == "session.thinking.append" and isinstance(event.get("content"), str) and (
            event.get("delegation_id") is not None or event["content"].startswith(VOICE_ANSWER_PREFIXES))
    if not message.from_client:
        return kind in ("function-call-arguments-done", "response.function_call_arguments.done")
    item = event.get("item")
    return kind in ("conversation-item-create", "conversation.item.create") and isinstance(item, dict) and item.get("type") in ("function-call-output", "function_call_output")



def _voice_policies() -> bool:
    """Whether a policy covers voice either way: its frames are then checked off the event loop."""
    try:
        rules = content_rules()
    except ContentRulesUnreadable:
        return False  # refused on the loop, as before
    return content_policy_applies(rules, "in", "voice") or content_policy_applies(rules, "out", "voice")


def websocket_message(flow):
    if flow.request.pretty_host.lower() == AGENTMAIL_WS:
        agentmail_ws_message(flow)
        return
    if is_slack_socket(flow):
        content_rules_slack_socket(flow)
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
    if not reject and _voice_judged(voice, message, event) and _voice_policies():
        # A question or an answer a policy covers: the AI is asked off the event loop, with the
        # socket paused so the frames stay in order. The voice already waits for the main agent.
        loop = _running_loop()

        def work():
            try:
                content_rules_voice(flow, voice, message, event, loop)
            except Exception as exc:  # fail closed: a frame that could not be checked ends the voice
                log.warning(f"[content-rules] voice check failed, the voice was closed: {type(exc).__name__}")
                _content_audit(flow, "error", "voice", "out" if message.from_client else "in", "block", purpose=voice.get("purpose", "meeting"))
                message.drop()
                loop.call_soon_threadsafe(_voice_close, flow)
            finally:
                flow.websocket.messages.clear()
        if loop is not None and _off_loop(flow, work):
            return
    if not reject:
        try:
            content_rules_voice(flow, voice, message, event)
        except Exception as exc:  # fail closed: a frame that could not be checked ends the voice
            log.warning(f"[content-rules] voice check failed, the voice was closed: {type(exc).__name__}")
            _content_audit(flow, "error", "voice", "out" if message.from_client else "in", "block", purpose=voice.get("purpose", "meeting"))
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


def _authority_host(value: str) -> str:
    """The host of a `Host:` value or an authority, without its port (IPv6 brackets kept off)."""
    value = value.strip()
    if value.startswith("["):
        return value[1:].split("]", 1)[0]
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def _one_destination(flow: http.HTTPFlow, host: str) -> str | None:
    """Make the request go to `host` (its `Host:` header, which every rule and swap matches), or say
    why it cannot. None when the request may go on.

    Before 2026-10-28 rules and swaps read the `Host:` header while the socket went to the CONNECT
    target or the IP behind redsocks, so `Host: api.telegram.org` sent to an attacker's address got
    the real bot token put in. Now:
    - the request names one host: a single `Host:` header, and over HTTP/2 a `host` header (which
      mitmproxy forwards) must be the `:authority` that `pretty_host` reads;
    - over TLS the client's SNI must be `host`;
    - a CONNECT target or request authority that is another NAME is refused;
    - one that is an IP (redsocks) is re-pointed at `host`, so the firewall resolves it itself and
      `server_connect` checks and pins what it connects to.
    """
    want = _wire_name(host)
    named = flow.request.headers.get_all("host")
    if flow.request.authority:
        named = [flow.request.authority, *named]
    if len(flow.request.headers.get_all("host")) > 1 or any(_wire_name(_authority_host(n)) != want for n in named):
        flow.metadata["cc_misdirected"] = True
        return f"the request names more than one host ({', '.join(n[:60] for n in named[:3])})"
    sni = getattr(flow.client_conn, "sni", None)
    if sni and _wire_name(sni) != want:
        flow.metadata["cc_misdirected"] = True
        return f"the TLS name is {sni[:80]} but the request is for {host[:80]}"
    authority = flow.request.host
    if _wire_name(authority) == want:
        return None
    if not is_ip_literal(authority):
        return f"the request was sent to {authority[:80]} but is for {host[:80]}"
    # The HTTP layer connects to (request.host, port) and takes the upstream SNI from it, so the name
    # goes in as it is on the wire: no trailing dot, no capitals, punycode. A fresh Server drops the
    # IP from this flow, for the checks below that read `server_conn`.
    name = _wire_name(host)
    flow.request.host = name
    flow.server_conn = connection.Server(address=(name, flow.request.port), sni=name,
                                         transport_protocol=flow.server_conn.transport_protocol)
    return None


async def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    method = flow.request.method
    path = flow.request.path
    vm_id = flow_vm_id(flow)  # which VM (by source IP) this request belongs to; None if unknown
    flow.metadata["cc_vm_id"] = vm_id

    if await _refuse_non_routable_http(flow):
        return
    # One destination for everything below: every rule, the windows and every credential swap
    # match `host`, so the request may only go to `host` (`_one_destination`).
    mismatch = _one_destination(flow, host)
    if mismatch:
        # 421 Misdirected Request when the TLS name is another host: what an HTTP/2 client that
        # reused a connection for a second origin needs to retry on a connection of its own.
        status = 421 if flow.metadata.pop("cc_misdirected", False) else BLOCK_STATUS
        flow.metadata["cc_effect"] = "block"
        flow.metadata["cc_rule"] = DESTINATION_RULE
        flow.response = http.Response.make(
            status,
            json.dumps({"error": DESTINATION_RULE, "host": host, "reason": mismatch, "tenant": TENANT}),
            {"Content-Type": "application/json"},
        )
        rec = _http_record(flow, "block")
        rec.update({"status": status, "error": mismatch[:200]})
        _log_once(flow, rec)
        log.warning(f"[mitm] refused {host}: {mismatch}")
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

    # Fail closed. If the check itself fails on a request (a body built to break it), the request
    # is refused like any other stand-in out of place: an exception here must never let it through
    # unchecked, past the organisation's rules and the AI review that come after.
    misplaced = None
    try:
        tripped = login_tripwire(flow, vm_id)
        if tripped is None:
            misplaced = login_out_of_scope(flow, vm_id)
    except Exception as exc:  # RecursionError and MemoryError included
        log.warning("[mitm] login check failed host=%s: %s", host, type(exc).__name__)
        tripped = None
        logins = [c for c in _login_entries() if c.get("vm_id") == vm_id and _login_host(c, host)] or [c for c in _login_entries() if c.get("vm_id") == vm_id]
        misplaced = (logins[0] if logins else {"login_name": "login"}, "error")
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
        rec.update({"status": BLOCK_STATUS, "login": str(tripped.get("login_name") or "login")[:64], "path": _without_stand_in(rec.get("path"), tripped)})
        _log_once(flow, rec)
        log.warning("[mitm] login=%s host=%s verdict=tripwire", tripped.get("login_id"), host)
        return

    if misplaced is not None:
        cred, why = misplaced
        flow.metadata["cc_effect"] = "block"
        flow.metadata["cc_rule"] = LOGIN_TRIPWIRE_RULE
        flow.response = http.Response.make(
            BLOCK_STATUS,
            json.dumps({"error": "login_not_on_sign_in_page", "host": host, "message": _LOGIN_BLOCK_TEXT[why]}),
            {"Content-Type": "application/json"},
        )
        rec = _http_record(flow, "block")
        # `login_why` tells Activity this was the login's own site, and what the owner can do.
        rec.update({"status": BLOCK_STATUS, "login": str(cred.get("login_name") or "login")[:64], "login_why": why, "path": _without_stand_in(rec.get("path"), cred)})
        _log_once(flow, rec)
        log.warning("[mitm] login=%s host=%s verdict=tripwire why=%s", cred.get("login_id"), host, why)
        return

    rule = match_rule(host, method, path, vm_id)
    effect = (rule or {}).get("effect", "allow")
    flow.metadata["cc_effect"] = effect
    flow.metadata["cc_rule"] = (rule or {}).get("name") or (rule or {}).get("match_domain")
    if rule is not None and rule.get("id"):
        # The website rule that decided, by id, for the console's per-rule counts
        # (docs/plans/rule-metrics.md). Kept with the label it set: a later step that puts its own
        # label on the flow (a content rule, an MCP refusal, the phone) decided instead, and the
        # record then carries no `rule_id`.
        flow.metadata["cc_rule_ref"] = (str(rule["id"])[:64], flow.metadata["cc_rule"])

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
        if content_rules_agentmail_raw(flow) or content_rules_agentmail_before(flow):
            return
        if not await agentmail_attachment_allowed(flow):
            _email_refuse(flow, "thread_attachment" if _AM_THREAD_ATTACHMENT.match(flow.request.path.split("?", 1)[0]) else "held_back")
            return
        if not await email_outbound(flow, vm_id):
            return
        if await content_rules_email_out(flow, vm_id):
            return

    # Content rules (docs/plans/firewall-content-rules.md): after the organization's host rules have
    # let the request through, before any credential is swapped in.
    if is_telegram_flow(flow) and (content_rules_telegram_poll(flow) or await content_rules_telegram_out(flow, vm_id)):
        return
    if is_slack_out_flow(flow) and await content_rules_slack_out(flow, vm_id):
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

    # MCP (docs/plans/mcp-inspection.md): a tool call is checked by the integration rules and the
    # content rules' Integrations channel instead of as a website request; other MCP traffic passes.
    mcp = await mcp_request(flow, vm_id)
    if mcp == "answered":
        return
    # Only a tool call the admission service checked skips the website check: its arguments were read
    # under the Integrations channel. Any other body, JSON-RPC or not, is a website request's.
    if not flow.metadata.get("cc_mcp_checked") and await content_rules_web(flow, vm_id):
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
        rec["login_in"] = list(dict.fromkeys(flow.metadata.get("cc_login_in") or []))
        rec["login_scope"] = flow.metadata.get("cc_login_scope")
    if flow.metadata.get("cc_granted"):
        rec["permission_id"] = flow.metadata["cc_granted"]
    req_raw = flow.request.raw_content
    rec["bytes_out"] = len(req_raw) if req_raw else 0
    return rec


# ---- Approve with a button (packages/mitm-agent/src/code-buttons.ts) -----------------------------
# The firewall sends a confirmation code to Telegram with number buttons. A tap comes back as a
# `callback_query` in the agent's own `getUpdates` answer, which passes through here. Ours start with
# TAP_PREFIX: they are taken out before the agent sees them and posted to the firewall agent on
# loopback, which decides them. Nothing the agent sends or says about a tap is ever read.
TAP_PREFIX = "cc1:"
CODE_BUTTONS_URL = os.environ.get("MITM_CODE_BUTTONS_URL", "http://127.0.0.1:8793/")
_TG_GET_UPDATES_RE = re.compile(r"^/bot(\d+):[^/]+/getUpdates$", re.IGNORECASE)


def _is_tap(update: Any) -> bool:
    cq = update.get("callback_query") if isinstance(update, dict) else None
    return isinstance(cq, dict) and isinstance(cq.get("data"), str) and cq["data"].startswith(TAP_PREFIX)


def strip_taps(doc: Any) -> tuple[Any, list[dict[str, Any]]]:
    """
    Take our taps out of a `getUpdates` answer; returns the answer for the agent and the taps.

    The agent asks for the next batch with `offset` = the highest `update_id` it saw + 1, and
    Telegram keeps sending everything below the offset. So when the highest update in the batch is a
    tap, its id stays in the answer as an update with nothing else in it: dropping it outright would
    have Telegram send the same tap on every poll, and an empty answer to a long poll would have the
    agent poll again at once. Taps lower in the batch are covered by the update above them.
    """
    if not isinstance(doc, dict) or doc.get("ok") is not True or not isinstance(doc.get("result"), list):
        return doc, []
    updates = doc["result"]
    taps = [u["callback_query"] for u in updates if _is_tap(u)]
    if not taps:
        return doc, []
    kept = keep_top_update(updates, [u for u in updates if not _is_tap(u)])
    return {**doc, "result": kept}, taps


def keep_top_update(updates: list[Any], kept: list[Any]) -> list[Any]:
    """
    `kept`, with the batch's highest `update_id` still in it: an empty update when that one was
    taken out, so the agent's next `offset` moves past it and Telegram does not send it again.
    """
    ids = [u["update_id"] for u in updates if isinstance(u, dict) and isinstance(u.get("update_id"), int)]
    top = max(ids) if ids else None
    if top is not None and not any(isinstance(u, dict) and u.get("update_id") == top for u in kept):
        kept = [*kept, {"update_id": top}]
    return kept


def _post_taps(bot_id: str, taps: list[dict[str, Any]]) -> None:
    try:
        body = json.dumps({"botId": bot_id, "queries": taps[:100]}).encode()
        request = urllib.request.Request(CODE_BUTTONS_URL, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5) as answer:
            answer.read()
    except (OSError, ValueError) as exc:
        # The tap is gone either way (it must never reach the agent); the person taps again or types the code.
        log.warning("[mitm] could not hand a button tap to the firewall: %s", type(exc).__name__)


def telegram_taps_response(flow: http.HTTPFlow) -> None:
    """Strip our taps out of the agent's `getUpdates` answer and hand them to the firewall agent."""
    if not is_telegram_flow(flow) or flow.response is None or flow.response.status_code != 200:
        return
    match = _TG_GET_UPDATES_RE.match(flow.request.path.split("?", 1)[0])
    if not match:
        return
    raw = flow.response.get_content() or b""
    if TAP_PREFIX.encode() not in raw:
        return
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeError):
        return
    clean, taps = strip_taps(doc)
    if not taps:
        return
    flow.response.set_content(json.dumps(clean).encode())
    try:
        task = asyncio.get_running_loop().create_task(asyncio.to_thread(_post_taps, match.group(1), taps))
        _phone_settle_tasks.add(task)
        task.add_done_callback(_phone_settle_tasks.discard)
    except RuntimeError:  # no event loop: a direct call from a test
        _post_taps(match.group(1), taps)


_phone_settle_tasks = set()


# ---- Content rules (docs/plans/firewall-content-rules.md) ----------------------------------------
#
# What an organization says its agents may not send or receive, checked on the text of a message.
# One engine (`content_evaluate`, pure, no I/O) and one adapter per channel; Telegram is the first.
# The rules come from the mitm-agent (`content-rules.ts`), which writes them only after a change was
# confirmed with a code; this file only reads them. The "Leaking secrets" rule is not in that file:
# it ships here, is on for every organization, and nothing the control plane sends can turn it off.
#
# Fail closed: a check that cannot run stops the message. mitmproxy's own answer to an exception in
# a hook is to log it and let the flow through (seen in the spike), so every adapter catches its
# own errors and refuses.

CONTENT_RULES_PATH = os.environ.get("MITM_CONTENT_RULES_PATH", os.path.join(os.path.dirname(CREDS_PATH), "content-rules.json"))
CONTENT_RULES_URL = os.environ.get("MITM_CONTENT_RULES_URL", "http://127.0.0.1:8794")
# Written by the mitm-agent while it remembers a text it had an agent send for it (`own-messages.ts`).
CONTENT_OWN_PATH = os.path.join(os.path.dirname(CONTENT_RULES_PATH), "content-own.json")
CONTENT_AUDIT_PATH = os.environ.get("MITM_CONTENT_AUDIT_FILE", os.path.join(os.path.dirname(LOG_PATH), "content-rules.jsonl") if LOG_PATH else "")
CONTENT_TEXT_MAX = 65536
# Email, web and app call bodies are longer than any chat message; more than this is stopped, never cut.
CONTENT_TEXT_MAX_LONG = 524288
CONTENT_LONG_CHANNELS = ("email", "web", "apps")
CONTENT_HOLD_BODY_MAX = 262144
# The text the engine read, handed over with a hold: the approver's preview is built from it, not from one field.
CONTENT_HOLD_TEXT_MAX = 8192
# Of a stopped text, the mitm-agent keeps this much (`STOPPED_TEXT_MAX` in content-stopped.ts).
CONTENT_STOPPED_TEXT_MAX = 2000
CONTENT_HOLD_WAIT = 25
CONTENT_ACTIONS = ("log", "hold", "block")  # weakest to strongest
# Policies (docs/plans/firewall-content-rules.md §5.4): the judge's `/content`, next to its `/judge`.
CONTENT_POLICY_URL = os.environ.get("MITM_CONTENT_POLICY_URL", AI_JUDGE_URL.rsplit("/", 1)[0] + "/content" if AI_JUDGE_URL else "").strip()
# The judge gives the model 2.5 s (Jev measured at p50 220 ms, the slowest of 46 calls 1 s); the
# pieces of a long text are judged at once.
CONTENT_POLICY_TIMEOUT = float(os.environ.get("MITM_CONTENT_POLICY_TIMEOUT", "3.5"))
# The most text the AI judges (`CONTENT_AI_TEXT_MAX` in content-engine.ts: four overlapping pieces).
# More is not judged in part: the rules act on it as on a check that could not run.
CONTENT_AI_TEXT_MAX = 4 * (16000 - 500) + 500
CONTENT_AI_FAILED = " (the AI check could not run)"

CORE_SECRETS_RULE = {
    # Not the web: a browser signing in posts tokens on purpose (an OpenID `form_post` carries an
    # `id_token`), and so does an OAuth refresh (docs/plans/firewall-content-rules.md §5.1). Voice: a
    # key the main agent answers with would be read aloud in the meeting (§5.2).
    "id": "core-leaking-secrets", "name": "Leaking secrets", "direction": "out", "channels": ["telegram", "slack", "email", "teamchat", "voice", "apps"],
    "patterns": [], "detectors": ["secrets"], "action": "block",
    "reason": "it looks like it contains a password, key or token",
}

# Our own expressions, each linear: no nested repetition. Organization rules never reach `re`: their
# words are found with a plain search (see `content_phrase_in`).
_SECRET_RES = [re.compile(p) for p in (
    r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----",
    r"\bsk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{32,}",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bgh[pousr]_[A-Za-z0-9]{36,}",
    r"\bgithub_pat_[A-Za-z0-9_]{40,}",
    r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
    r"\bAIza[0-9A-Za-z_-]{35}\b",
    r"\b\d{6,12}:AA[A-Za-z0-9_-]{33}\b",
    r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    r"\bvck_[A-Za-z0-9]{24,}",
)]
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b")
_CARD_RE = re.compile(r"(?<![\d-])[2-6]\d{3}(?:[ -]?\d{4}){2}[ -]?\d{1,7}(?![\d-])")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}")
CONTENT_EMAILS_BULK = 5


def _iban_ok(candidate: str) -> bool:
    s = candidate.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    digits = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    return int(digits) % 97 == 1


def _luhn_ok(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def content_detect(name: str, text: str) -> bool:
    """One built-in detector on one text."""
    if name == "secrets":
        return any(r.search(text) for r in _SECRET_RES)
    if name == "iban":
        return any(_iban_ok(m.group(0)) for m in _IBAN_RE.finditer(text.upper()))
    if name == "card":
        return any(_luhn_ok(m.group(0)) for m in _CARD_RE.finditer(text))
    if name == "emails":
        return len({m.group(0).lower() for m in _EMAIL_RE.finditer(text)}) >= CONTENT_EMAILS_BULK
    raise ValueError(f"unknown detector {name}")


def _is_word_char(c: str) -> bool:
    return c.isalnum() or c == "_"


# Spaces and line breaks, the same set as `content-engine.ts` (Python's own `str.split()` and the
# JavaScript `\s` each miss a few the other has).
_CONTENT_WS = re.compile("[\t\n\v\f\r\x1c-\x1f \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+")


def content_fold(text: str) -> str:
    """Lower case, every run of spaces and line breaks (a non-breaking space included) one space."""
    return _CONTENT_WS.sub(" ", text.lower()).strip(" ")


def _phrase_in_folded(needle: str, hay: str) -> bool:
    if not needle:
        return False
    start = hay.find(needle)
    while start >= 0:
        end = start + len(needle)
        if (start == 0 or not _is_word_char(hay[start - 1])) and (end == len(hay) or not _is_word_char(hay[end])):
            return True
        start = hay.find(needle, start + 1)
    return False


def content_phrase_in(phrase: str, text: str) -> bool:
    """
    A word or phrase in a text, case-insensitive, on word edges: "customer list" is in "the Customer
    List." and in "customer\nlist", but not in "customer listing". A plain search, never a regex, so a
    phrase cannot be made to backtrack, and a long body is read at the speed of `str.find`.
    `content-engine.ts` in the mitm-agent does the same; `content-vectors.json` holds both to it.
    """
    return _phrase_in_folded(content_fold(phrase), content_fold(text))


def content_text_max(channel: str) -> int:
    return CONTENT_TEXT_MAX_LONG if channel in CONTENT_LONG_CHANNELS else CONTENT_TEXT_MAX


def content_applies(rules: list[dict[str, Any]], direction: str, channel: str) -> bool:
    """Whether any rule looks at this direction and channel: when none does, nothing is read."""
    return any(r["direction"] in (direction, "both") and (channel in r["channels"] or "*" in r["channels"]) for r in rules)


def content_evaluate(rules: list[dict[str, Any]], direction: str, channel: str, text: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """
    The engine. Every rule that applies to this direction and channel and matches the text, and the
    one whose action wins (block over hold over log; the first listed among equals). Pure: no I/O,
    so the same function can run in the console's test box and in the Rust rewrite.

    Never cut: a text over the channel's limit (`content_text_max`) raises, and the adapter refuses
    it, so padding one field cannot push what matters out of reach.
    """
    if len(text) > content_text_max(channel):
        raise ContentTooLong(len(text))
    hits = []
    folded = None  # once per text, not once per phrase
    for rule in rules:
        if rule["direction"] not in (direction, "both"):
            continue
        if channel not in rule["channels"] and "*" not in rule["channels"]:
            continue
        if rule["patterns"] and folded is None:
            folded = content_fold(text)
        if any(_phrase_in_folded(content_fold(p), folded) for p in rule["patterns"]) or any(content_detect(d, text) for d in rule["detectors"]):
            hits.append(rule)
    winner = None
    for rule in hits:
        if winner is None or CONTENT_ACTIONS.index(rule["action"]) > CONTENT_ACTIONS.index(winner["action"]):
            winner = rule
    return winner, hits


def content_policy_applies(rules: list[dict[str, Any]], direction: str, channel: str) -> bool:
    """Whether a policy looks at this direction and channel: when none does, the model is not called."""
    return any(r.get("policy") and r["direction"] in (direction, "both") and (channel in r["channels"] or "*" in r["channels"]) for r in rules)


def _running_loop() -> asyncio.AbstractEventLoop | None:
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def _on_event_loop() -> bool:
    return _running_loop() is not None


def _content_policy_ask(direction: str, channel: str, text: str, asked: list[dict[str, Any]], vm_id: str | None = None) -> set[str] | None:
    """
    The judge's answer (`/content`): the ids of the policies the message goes against, or None when
    it could not answer. Blocking: never on the event loop, where it is refused (fail closed).
    """
    if _on_event_loop():
        log.warning("[content-rules] a policy check was asked on the event loop; refused")
        return None
    if not CONTENT_POLICY_URL:
        return None
    # Secrets out first, as the judge does (the length is what it will judge).
    for pattern in _SECRET_RES:
        text = pattern.sub("[secret]", text)
    if len(text) > CONTENT_AI_TEXT_MAX:
        log.warning(f"[content-rules] the AI check could not run: {len(text)} characters is more than it judges")
        return None
    payload = {"direction": direction, "channel": channel, "text": text, "rules": [{"id": r["id"], "policy": r["policy"]} for r in asked],
               "vm_id": vm_id if isinstance(vm_id, str) else None}
    try:
        req = urllib.request.Request(CONTENT_POLICY_URL, data=json.dumps(payload).encode("utf-8"), headers={"content-type": "application/json"}, method="POST")
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=CONTENT_POLICY_TIMEOUT) as res:
            doc = json.loads(res.read(64 * 1024))
    except Exception as exc:  # a 400, a timeout, the judge not listening
        log.warning(f"[content-rules] the AI check could not run: {type(exc).__name__}")
        return None
    matches = doc.get("matches") if isinstance(doc, dict) else None
    if not isinstance(matches, list) or not all(isinstance(m, str) for m in matches):
        log.warning(f"[content-rules] the AI check could not run: {str(doc.get('why') if isinstance(doc, dict) else 'answer')[:40]}")
        return None
    return set(matches)


def content_judge(rules: list[dict[str, Any]], direction: str, channel: str, text: str,
                  found: tuple[dict[str, Any] | None, list[dict[str, Any]]] | None = None, vm_id: str | None = None) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """
    `content_evaluate`, then the AI on the policies that cover the text and did not match already,
    unless a rule already blocks it: one call to the judge. A hit the AI made carries `by: "found"`.
    When it could not answer, every block or hold policy it was asked about acts, with its reason
    and "(the AI check could not run)" and `by: "failed"`; a log-only one records nothing (fail
    closed). Blocking when a policy is asked: only off the event loop. `found`: `content_evaluate`'s
    answer on this text, when the caller has it.
    """
    winner, hits = found if found is not None else content_evaluate(rules, direction, channel, text)
    if (winner is not None and winner["action"] == "block") or not text.strip():
        return winner, hits
    hit_ids = {h["id"] for h in hits}
    asked = [r for r in rules if r.get("policy") and r["id"] not in hit_ids and r["direction"] in (direction, "both")
             and (channel in r["channels"] or "*" in r["channels"])]
    if not asked:
        return winner, hits
    matched = _content_policy_ask(direction, channel, text, asked, vm_id)
    if matched is None:
        # "Pay is not discussed (the AI check could not run)": the reason's own full stop is dropped.
        more = [{**r, "reason": f"{r['reason'].rstrip(' .')}{CONTENT_AI_FAILED}", "by": "failed"} for r in asked if r["action"] != "log"]
    else:
        more = [{**r, "by": "found"} for r in asked if r["id"] in matched]
    hits = hits + more
    for rule in more:
        if winner is None or CONTENT_ACTIONS.index(rule["action"]) > CONTENT_ACTIONS.index(winner["action"]):
            winner = rule
    return winner, hits


def _content_mark(flow: http.HTTPFlow | None, hits: list[dict[str, Any]]) -> None:
    """The AI's part in each hit, left on the flow for the audit lines (`ai: found | failed`)."""
    if flow is not None:
        for hit in hits:
            if hit.get("by"):
                flow.metadata.setdefault("cc_content_ai", {})[hit["id"]] = hit["by"]


class ContentCheckUnavailable(Exception):
    """A message coming in that the AI could not judge: answered "try again" where the channel can, not hidden."""


class ContentRulesUnreadable(Exception):
    """The rules cannot be known (no file, a broken one, a store the firewall could not open): every check refuses."""


class ContentTooLong(Exception):
    """More text than a check reads. Telegram's own limits are far below it, so it is refused, never cut."""


_content_cache: dict[str, Any] = {"key": None, "rules": []}


def _content_rule_ok(r: Any) -> bool:
    return (isinstance(r, dict) and isinstance(r.get("id"), str) and isinstance(r.get("reason"), str)
            and r.get("direction") in ("in", "out", "both") and r.get("action") in CONTENT_ACTIONS
            and isinstance(r.get("channels"), list) and all(isinstance(c, str) for c in r["channels"])
            and isinstance(r.get("patterns"), list) and all(isinstance(p, str) and 0 < len(p) <= 100 for p in r["patterns"])
            and isinstance(r.get("detectors"), list) and all(d in ("secrets", "iban", "card", "emails") for d in r["detectors"])
            and (r.get("policy") is None or (isinstance(r["policy"], str) and 0 < len(r["policy"]) <= 300)))


def content_rules() -> list[dict[str, Any]]:
    """The organization's rules (re-read when the file changes), with the core rule first. Raises when they cannot be known."""
    try:
        st = os.stat(CONTENT_RULES_PATH)
    except OSError as exc:
        # No file is not "no rules": the directory is a tmpfs, so after a reboot the proxy starts
        # before the mitm-agent has written it, and a mitm-agent that failed never writes it.
        raise ContentRulesUnreadable(str(exc)) from exc
    key = (st.st_mtime_ns, st.st_size)
    if _content_cache["key"] != key:
        try:
            with open(CONTENT_RULES_PATH, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as exc:
            raise ContentRulesUnreadable(str(exc)) from exc
        if isinstance(doc, dict) and doc.get("unreadable") is True:
            # The mitm-agent could not open its store: the organization's rules are unknown.
            raise ContentRulesUnreadable("the firewall could not read its content rules")
        rules = doc.get("rules") if isinstance(doc, dict) and doc.get("version") == 1 else None
        if not isinstance(rules, list) or not all(_content_rule_ok(r) for r in rules):
            raise ContentRulesUnreadable("the rule file is not in the expected shape")
        # Nothing holds a message coming in (the agent's next poll would have to hand it over later):
        # a hold on that side stops it instead.
        _content_cache.update(key=key, rules=rules)
    return [CORE_SECRETS_RULE, *_content_cache["rules"]]


def content_rules_wait(seconds: float = 15) -> list[dict[str, Any]]:
    """`content_rules`, waiting up to `seconds` for them to be known. Blocking: only off the event loop."""
    deadline = time.monotonic() + seconds
    while True:
        try:
            return content_rules()
        except ContentRulesUnreadable:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.5)


_audit_seen: dict[str, float] = {}
CONTENT_AUDIT_ONCE = 3600


def _content_audit(flow: http.HTTPFlow | None, rule_id: str, channel: str, direction: str, action: str, once: str | None = None, **extra: Any) -> None:
    """
    The firewall's own record of a rule that fired. Metadata only, never the text: a block's text
    goes to the mitm-agent's encrypted record instead (`_content_stopping`). `once` names the message
    on a read the agent repeats (a list it polls): recorded once an hour, not on every poll.
    """
    # The text this rule stopped on this flow, taken whatever happens next, so it cannot be kept under another line.
    stopping = flow.metadata.get("cc_content_stopped", {}).pop(rule_id, None) if flow is not None and action == "block" else None
    vm_id = flow.metadata.get("cc_vm_id") if flow else None
    # The id is the console's dedupe key for the line (activity source `content_rule`). A read the
    # agent repeats gets the same id every hour, so the console counts it once.
    line_id = uuid.uuid4().hex[:24]
    if once is not None:
        key = f"{rule_id}|{channel}|{direction}|{action}|{vm_id}|{once}"
        now = time.monotonic()
        if now - _audit_seen.get(key, -CONTENT_AUDIT_ONCE) < CONTENT_AUDIT_ONCE:
            return
        if len(_audit_seen) > 10000:
            _audit_seen.clear()
        _audit_seen[key] = now
        line_id = hashlib.sha256(key.encode()).hexdigest()[:24]
    by = flow.metadata.get("cc_content_ai", {}).get(rule_id) if flow is not None else None
    rec = {"ts": time.time(), "id": line_id, "rule": rule_id, "channel": channel, "direction": direction, "action": action,
           "vm_id": vm_id, "flow_id": flow.id if flow else None, **({"ai": by} if by else {}), **extra}
    log.info(f"[content-rules] {json.dumps(rec)}")
    # Holds are recorded by the mitm-agent, which keeps them; a check that failed has no text worth keeping.
    if stopping is not None and rule_id != "error":
        _content_stopped(rec["vm_id"], stopping[0], channel, direction, stopping[1], line_id)
    if not CONTENT_AUDIT_PATH:
        return
    try:
        try:
            if os.path.getsize(CONTENT_AUDIT_PATH) >= LOG_MAX_BYTES:
                os.replace(CONTENT_AUDIT_PATH, CONTENT_AUDIT_PATH + ".1")
        except FileNotFoundError:
            pass
        with open(CONTENT_AUDIT_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError as exc:
        log.warning(f"[content-rules] audit write failed: {exc}")


def _content_stopping(flow: http.HTTPFlow | None, rule: dict[str, Any], text: str) -> None:
    """The text a rule acts on, left on the flow (one per rule) for the audit line that records the block."""
    if flow is not None and rule.get("action") in ("block", "hold"):
        flow.metadata.setdefault("cc_content_stopped", {})[rule.get("id")] = (rule, text)


def _content_unstop(flow: http.HTTPFlow, rule_id: Any) -> None:
    """A hold: the mitm-agent records it, kept or not, so the proxy does not."""
    flow.metadata.get("cc_content_stopped", {}).pop(rule_id, None)


def _content_stopped(vm_id: str | None, rule: dict[str, Any], channel: str, direction: str, text: str, line_id: str) -> None:
    """
    Fire and forget: a stopped text to the mitm-agent's encrypted record, for the firewall's own
    Content rules page. A rule that looks for secrets sends none: the record would be one more copy.
    """
    secret = rule.get("id") == CORE_SECRETS_RULE["id"] or "secrets" in rule.get("detectors", ())
    payload = {"vmId": vm_id if isinstance(vm_id, str) and vm_id else None,
               "rule": _rule_brief(rule),
               "channel": channel, "direction": direction, "id": line_id,
               # One more than the record keeps, so it knows the text was cut.
               "text": "" if secret else text[:CONTENT_STOPPED_TEXT_MAX + 1]}

    def send() -> None:
        try:
            _content_post("/stopped", payload)
        except (OSError, ValueError) as exc:
            log.warning(f"[content-rules] stopped text not handed over: {exc}")
    try:
        task = asyncio.get_running_loop().create_task(asyncio.to_thread(send))
        _phone_settle_tasks.add(task)
        task.add_done_callback(_phone_settle_tasks.discard)
    except RuntimeError:  # no event loop: a direct call from a test
        send()


def _content_post(path: str, payload: dict[str, Any], timeout: float = 5) -> dict[str, Any]:
    # A hold waits for `CONTENT_HOLD_WAIT`, longer than the mitm-agent can take to ask everyone (it
    # asks in parallel, 10 s per Telegram call): a hold the proxy gave up on would still be sendable.
    """Loopback to the mitm-agent (`content-rules.ts`). Raises on anything but a JSON 200."""
    request = urllib.request.Request(CONTENT_RULES_URL + path, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=timeout) as answer:
        doc = json.loads(answer.read() or b"{}")
    if not isinstance(doc, dict):
        raise ValueError("unexpected answer")
    return doc


def _content_notice(payload: dict[str, Any]) -> None:
    """Fire and forget: the firewall's own notice to the person in the chat."""
    def send() -> None:
        try:
            _content_post("/notice", payload)
        except (OSError, ValueError) as exc:
            log.warning(f"[content-rules] notice not handed over: {exc}")
    try:
        task = asyncio.get_running_loop().create_task(asyncio.to_thread(send))
        _phone_settle_tasks.add(task)
        task.add_done_callback(_phone_settle_tasks.discard)
    except RuntimeError:  # no event loop: a direct call from a test
        send()


_TG_METHOD_RE = re.compile(r"^/bot(\d+):[^/]+/([A-Za-z]+)$")
_TG_FILE_RE = re.compile(r"^/file/bot\d+:[^/]+/[A-Za-z0-9_./-]+$")
# The methods a held message can be sent with later (content-rules.ts holds the same list).
_TG_HOLDABLE = {"sendMessage", "editMessageText", "editMessageCaption", "sendPhoto", "sendDocument", "sendVideo", "sendAudio", "sendAnimation", "sendVoice", "sendMediaGroup"}
# Every field that carries words someone reads: messages, captions, polls, contacts, venues,
# inline results, descriptions. Checked wherever they sit, at any depth.
_TG_TEXT_KEYS = {"text", "caption", "question", "explanation", "title", "description", "short_description", "address",
                 "first_name", "last_name", "name", "message_text", "vcard", "quote", "label", "options"}


class _DuplicateKey(ValueError):
    pass


class _TooDeep(ValueError):
    pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        # Which copy Telegram reads is not ours to guess: refuse rather than check the other one.
        raise _DuplicateKey("a JSON object repeats a key")
    return dict(pairs)


class _JsonInt(int):
    """A JSON number as written: Telegram and Slack take a number where a text goes and send its digits."""
    raw: str

    def __new__(cls, literal: str) -> "_JsonInt":
        number = super().__new__(cls, literal)
        number.raw = literal
        return number


class _JsonFloat(float):
    raw: str

    def __new__(cls, literal: str) -> "_JsonFloat":
        number = super().__new__(cls, literal)
        number.raw = literal
        return number


def _json_loads(text: str | bytes) -> Any:
    """JSON with no repeated key, its numbers kept as written."""
    return json.loads(text, object_pairs_hook=_no_duplicates, parse_int=_JsonInt, parse_float=_JsonFloat)


# A parameter of a Content-Type or Content-Disposition header: a token, `=`, a token or a quoted string.
_HEADER_PARAM_RE = re.compile(r';[ \t]*([!#$%&\'*+.^_`|~0-9A-Za-z-]+)[ \t]*=[ \t]*("(?:[^"\\\r\n]|\\.)*"|[!#$%&\'*+.^_`|~0-9A-Za-z-]+)[ \t]*')
_HEADER_EMPTY_PARAM_RE = re.compile(r";[ \t]*")


def _header_params(value: str) -> tuple[str, dict[str, str]]:
    """
    A header's first word, lower case, and its parameters (names lower case, quotes taken off).
    Raises on anything else, a repeated parameter included: a header read one way here and another
    way by the service is not checked.
    """
    head, _, rest = value.partition(";")
    rest = ";" + rest if _ else ""
    params: dict[str, str] = {}
    pos = 0
    while pos < len(rest.rstrip(" \t")):
        m = _HEADER_PARAM_RE.match(rest, pos)
        if m is None and (empty := _HEADER_EMPTY_PARAM_RE.match(rest, pos)) and (empty.end() >= len(rest.rstrip(" \t")) or rest[empty.end()] == ";"):
            pos = empty.end()  # an empty parameter (`application/json;`)
            continue
        if not m or m.group(1).lower() in params:
            raise ValueError("a header the firewall cannot read")
        v = m.group(2)
        params[m.group(1).lower()] = re.sub(r"\\(.)", r"\1", v[1:-1]) if v.startswith('"') else v
        pos = m.end()
    return head.strip(" \t").lower(), params


def _charset_ok(params: dict[str, str]) -> bool:
    # Telegram and Slack read UTF-8 whatever the header says; a body that says otherwise is not checked.
    return params.get("charset", "utf-8").lower() in ("utf-8", "utf8")


_MP_HEADER_RE = re.compile(rb"([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*(.*?)[ \t]*")
_MP_LOOSE_FILENAME_RE = re.compile(r';[ \t]*filename=(?!")', re.IGNORECASE)


def _multipart_fields(boundary: str | None, body: bytes) -> list[tuple[str, bytes]]:
    """
    The named parts of a `multipart/form-data` body, read strictly: every delimiter on its own CRLF
    line, nothing before the first or after the last, each part a block of headers, a blank line and
    its value, with one `Content-Disposition: form-data` naming it. Anything else raises: mitmproxy's
    own reader skips such parts, and an empty form would pass unchecked. The values as sent.
    """
    if not boundary or len(boundary) > 70 or not boundary.isascii():
        raise ValueError("a multipart body with no usable boundary")
    delimiter = b"\r\n--" + boundary.encode()
    pieces = (b"\r\n" + body).split(delimiter)
    if pieces[0] != b"" or len(pieces) < 2 or pieces[-1] not in (b"--", b"--\r\n"):
        raise ValueError("a multipart body that does not start and end on its boundary")
    fields: list[tuple[str, bytes]] = []
    for piece in pieces[1:-1]:
        if not piece.startswith(b"\r\n"):
            raise ValueError("a multipart delimiter not on a line of its own")
        head, sep, value = piece[2:].partition(b"\r\n\r\n")
        if not sep or not head:
            raise ValueError("a multipart part without headers")
        headers: dict[str, str] = {}
        for line in head.split(b"\r\n"):
            m = _MP_HEADER_RE.fullmatch(line)
            name = m.group(1).decode().lower() if m else None
            if name is None or name in headers:
                raise ValueError("a multipart part header the firewall cannot read")
            headers[name] = m.group(2).decode("utf-8")
        disposition = headers.get("content-disposition", "")
        # grammY writes a file's name unquoted, spaces and all (`filename=my photo.jpg`): it runs to
        # the end of the line, and must not hold a second name.
        loose = _MP_LOOSE_FILENAME_RE.search(disposition)
        if loose:
            if re.search(r"[;\s]name\*?[ \t]*=", disposition[loose.end():], re.IGNORECASE):
                raise ValueError("a multipart part named twice")
            disposition = disposition[:loose.start()] + ';filename=""'
        kind, params = _header_params(disposition)
        if kind != "form-data" or not params.get("name") or "name*" in params:
            raise ValueError("a multipart part without a name")
        if headers.get("content-transfer-encoding", "binary").lower() not in ("binary", "8bit", "7bit"):
            raise ValueError("a multipart part in an encoding the firewall cannot read")
        if "filename" not in params and "content-type" in headers and not _charset_ok(_header_params(headers["content-type"])[1]):
            raise ValueError("a multipart part in a charset the firewall cannot read")
        fields.append((params["name"], value))
    return fields


def _out_body(flow: http.HTTPFlow) -> tuple[str, dict[str, str], str]:
    """
    An outgoing chat call's body as Telegram and Slack read it: its media type, the type's
    parameters, and the body as UTF-8 text. A compressed body, or one in another charset, raises:
    what the check would read is not what the service reads.
    """
    encodings = [e.strip().lower() for v in flow.request.headers.get_all("content-encoding") for e in v.split(",")]
    transfer = [e.strip().lower() for v in flow.request.headers.get_all("transfer-encoding") for e in v.split(",")]
    if any(e not in ("", "identity") for e in encodings) or any(e not in ("", "chunked") for e in transfer):
        raise ValueError("a compressed body")
    media, params = _header_params(flow.request.headers.get("content-type") or "")
    if not _charset_ok(params):
        raise ValueError("a body in a charset the firewall cannot read")
    return media, params, (flow.request.raw_content or b"").decode("utf-8", errors="replace")


def _tg_out_fields(flow: http.HTTPFlow) -> tuple[list[tuple[str, Any]], bool]:
    """
    Every field of an outgoing Telegram call, query string included, every value of a repeated
    key; and whether the call is a JSON body with no fields in the query (only that can be held and
    sent again as it was).
    """
    from urllib.parse import parse_qsl
    fields: list[tuple[str, Any]] = list(flow.request.query.items(multi=True))
    media, params, raw = _out_body(flow)
    is_json = False
    if media == "multipart/form-data":
        fields += [(k, v.decode("utf-8", errors="replace")) for k, v in _multipart_fields(params.get("boundary"), flow.request.raw_content or b"")]
    elif media == "application/x-www-form-urlencoded":
        fields += parse_qsl(raw, keep_blank_values=True, encoding="utf-8", errors="replace")
    elif raw.strip():
        doc = _json_loads(raw)
        if not isinstance(doc, dict):
            raise ValueError("not a JSON object")
        fields += list(doc.items())
        is_json = not flow.request.query
    return fields, is_json


def _tg_texts(value: Any, under_text_key: bool, out: list[str], depth: int = 0, keys: set[str] = _TG_TEXT_KEYS,
              skip: frozenset[str] = frozenset()) -> None:
    """
    The strings under any of `keys`, at any depth (`under_text_key=True` takes every string), and
    the numbers there as written. A string that is JSON is read inside too, and kept as it is when
    it is under a text key: Telegram shows it as written. `skip`: keys not read at all.
    """
    if depth > 20:
        raise _TooDeep("nested too deep")
    if isinstance(value, str):
        stripped = value.lstrip()
        if stripped[:1] in ("[", "{"):
            # Form and multipart calls carry objects as JSON in a string (media, options, results).
            try:
                parsed = _json_loads(value)
            except _DuplicateKey:
                raise
            except ValueError:
                # JSON to Telegram's parser but not to Python's (a control character in a string, a
                # 5000-digit number): every word in it is read, its escapes undone, whatever its keys.
                out.append(_json_unescape_loose(value))
            else:
                # Outside the `try`: too deep inside is refused, as at the top.
                _tg_texts(parsed, under_text_key, out, depth + 1, keys, skip)
        if under_text_key:
            out.append(value)
    elif isinstance(value, (_JsonInt, _JsonFloat)) or (isinstance(value, (int, float)) and not isinstance(value, bool)):
        if under_text_key:
            out.append(getattr(value, "raw", None) or str(value))
    elif isinstance(value, dict):
        for k, v in value.items():
            if k not in skip:
                _tg_texts(v, under_text_key or k in keys, out, depth + 1, keys, skip)
    elif isinstance(value, list):
        for v in value:
            _tg_texts(v, under_text_key, out, depth + 1, keys, skip)


def _tg_text(fields: list[tuple[str, Any]], keys: set[str] = _TG_TEXT_KEYS) -> str:
    out: list[str] = []
    for key, value in fields:
        _tg_texts(value, key in keys, out, 0, keys)
    return "\n".join(out)


_MARKUP_TAG_RE = re.compile(r"</?[A-Za-z][^<>]*>")
# MarkdownV2 lets any character from 1 to 126 be escaped.
_MARKDOWN_ESCAPE_RE = re.compile(r"\\([\x01-\x7e])")
_MARKDOWN_MARKS_RE = re.compile(r"[*_~`|\[\]]")
# A Markdown link (`[label](url)`) and a Slack one (`<url|label>`, `<url>`): the chat shows the label.
_MARKDOWN_LINK_RE = re.compile(r"\[((?:\\.|[^\]\\])*)\]\((?:\\.|[^)\\])*\)")
_SLACK_LINK_RE = re.compile(r"<([^<>|]*)\|([^<>]*)>")


def _rendered(text: str) -> list[str]:
    """
    The text, and the text as the chat shows it when the message is formatted: links as their
    labels (`[cust](http://a.b)omer`, Slack's `<https://x|cust>omer`), then HTML tags out and
    entities decoded (`pass<b></b>word`, `customer&#32;list`), or Markdown escapes and marks out
    (`cust\\_omer`, `cust*om*er`). Only the ways that differ, so a plain message is read once.
    """
    variants = [text]
    linked = _SLACK_LINK_RE.sub(r"\2", text) if "|" in text else text
    if "<" in text or "&" in text:
        variants.append(html_unescape(_MARKUP_TAG_RE.sub("", linked)))
    if "\\" in text or _MARKDOWN_MARKS_RE.search(text):
        # Links first, on the text as written: an escaped `\\)` belongs to the URL.
        labelled = _MARKDOWN_ESCAPE_RE.sub(r"\1", _MARKDOWN_LINK_RE.sub(r"\1", linked))
        variants.append(_MARKDOWN_MARKS_RE.sub("", labelled))
    return list(dict.fromkeys(variants))


def _content_evaluate_shown(rules: list[dict[str, Any]], direction: str, channel: str, text: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """
    `content_evaluate` on the text and on each way the chat can show it (`_rendered`), each on its
    own, so the length limit is the message's and not the sum: every hit, and the winner among them.
    What a hold or a stopped record shows is the text as sent.
    """
    winner, hits = None, []
    for variant in _rendered(text):
        rule, found = content_evaluate(rules, direction, channel, variant)
        hits += [h for h in found if h not in hits]
        if rule is not None and (winner is None or CONTENT_ACTIONS.index(rule["action"]) > CONTENT_ACTIONS.index(winner["action"])):
            winner = rule
    return winner, hits


def _tg_refuse(flow: http.HTTPFlow, rule: dict[str, Any] | None, detail: str, reason: str | None = None) -> None:
    reason = rule["reason"] if rule else (reason or "the check could not run")
    flow.response = http.Response.make(400, json.dumps({"ok": False, "error_code": 400, "description": f"Bad Request: blocked by your organization's rules: {reason}{detail}"}), {"Content-Type": "application/json"})
    flow.metadata["cc_effect"] = "block"
    flow.metadata["cc_rule"] = f"content: {rule['id']}" if rule else "content: error"
    rec = _http_record(flow, "block")
    rec["status"] = 400
    _log_once(flow, rec)


async def content_rules_telegram_out(flow: http.HTTPFlow, vm_id: str | None) -> bool:
    """An agent's outgoing Telegram call: True when it was answered here (blocked or held)."""
    path = flow.request.path.split("?", 1)[0]
    match = _TG_METHOD_RE.match(path)
    if not match:
        # A file download is a read. Anything else the pattern does not take (a trailing slash, an
        # encoded method name) still reaches Telegram with the real token after the swap, so it is
        # refused rather than passed unchecked.
        if _TG_FILE_RE.match(path) and flow.request.method in ("GET", "HEAD"):
            return False
        _tg_refuse(flow, None, "", reason="this Telegram call could not be checked")
        _content_audit(flow, "error", "telegram", "out", "block", detail="unmatched path")
        return True
    # Every method that is not a read: text can ride on a poll, a contact, a description, a GET.
    if match.group(2).lower().startswith("get"):
        return False
    try:
        fields, is_json = _tg_out_fields(flow)
        if match.group(2).lower() == "setwebhook" and any(k == "url" and str(v).strip() for k, v in fields):
            # A webhook takes the agent's messages off `getUpdates`, where the incoming rules and the
            # approval buttons are read. Deleting one (an empty url) is allowed.
            _tg_refuse(flow, None, "", reason="a Telegram webhook would skip the firewall's checks")
            _content_audit(flow, "error", "telegram", "out", "block", detail="webhook")
            return True
        text = _tg_text(fields)
        if not text:
            return False
        rule, hits, text = await _content_out_evaluate(content_rules(), "telegram", text, vm_id)
        _content_mark(flow, hits)
        for hit in hits:
            if hit["action"] == "log":
                _content_audit(flow, hit["id"], "telegram", "out", "log")
        if rule is None or rule["action"] == "log":
            return False
        _content_stopping(flow, rule, text)
        chat_id = next((v for k, v in fields if k == "chat_id"), None)
        if rule["action"] == "hold":
            if is_json and match.group(2) in _TG_HOLDABLE and chat_id is not None and len(flow.request.raw_content or b"") <= CONTENT_HOLD_BODY_MAX:
                key = uuid.uuid4().hex
                message = None
                try:
                    _content_unstop(flow, rule["id"])
                    answer = await asyncio.to_thread(_content_post, "/hold", timeout=CONTENT_HOLD_WAIT, payload={
                        "key": key, "botId": match.group(1), "method": match.group(2), "body": _out_body(flow)[2],
                        "chatId": str(chat_id), "vmId": vm_id, "rule": _rule_brief(rule),
                        "text": text[:CONTENT_HOLD_TEXT_MAX],
                    })
                    if answer.get("ok") is True and isinstance(answer.get("holdId"), str):
                        # The agent is told it went (decided 2026-10-15): the people who get codes decide.
                        first_text = next((v for k, v in fields if k == "text" and isinstance(v, str)), None)
                        message = {"message_id": int(answer.get("messageId") or 0) or 1, "date": int(time.time()),
                                   "chat": {"id": chat_id}, **({"text": first_text} if first_text is not None else {})}
                except Exception:
                    # Gave up waiting, or an answer that cannot be told to the agent (a message id
                    # that is not a number): the agent is told it was stopped, so a hold must not survive.
                    try:
                        await asyncio.to_thread(_content_post, "/cancel", {"key": key})
                    except Exception as exc:
                        log.warning(f"[content-rules] hold cancel not handed over: {exc!r}")
                    raise
                if message is not None:
                    flow.response = http.Response.make(200, json.dumps({"ok": True, "result": message}), {"Content-Type": "application/json"})
                    flow.metadata["cc_effect"] = "hold"
                    flow.metadata["cc_rule"] = f"content: {rule['id']}"
                    _log_once(flow, {**_http_record(flow, "hold"), "status": 200})
                    _content_audit(flow, rule["id"], "telegram", "out", "hold", hold=answer["holdId"])
                    return True
                detail = " (nobody could be asked to approve it)"
            else:
                detail = " (it could not be held for approval)"
            _tg_refuse(flow, rule, detail)
            _content_audit(flow, rule["id"], "telegram", "out", "block", held=False)
        else:
            _tg_refuse(flow, rule, "")
            _content_audit(flow, rule["id"], "telegram", "out", "block")
        if chat_id is not None:
            _content_notice({"kind": "out", "botId": match.group(1), "chatId": str(chat_id), "vmId": vm_id, "reason": rule["reason"]})
        return True
    except ContentTooLong:
        _tg_refuse(flow, None, "", reason="it is too long to check")
        _content_audit(flow, "error", "telegram", "out", "block", detail="too long")
        return True
    except Exception as exc:  # fail closed, RecursionError and MemoryError included
        log.warning(f"[content-rules] outgoing Telegram check failed, refusing: {exc!r}")
        _tg_refuse(flow, None, "")
        _content_audit(flow, "error", "telegram", "out", "block")
        return True


def content_rules_telegram_poll(flow: http.HTTPFlow) -> bool:
    """
    An agent asking Telegram for its messages (`getUpdates`) while the rules are unknown: refused
    here, before Telegram is asked, with Telegram's own "retry after". Telegram keeps the messages,
    and the agent gets them once the rules are known. Stripping them from the answer instead would
    move the agent's offset past them, and they would be lost for good.
    """
    if not _TG_GET_UPDATES_RE.match(flow.request.path.split("?", 1)[0]):
        return False
    try:
        content_rules()
        return False
    except ContentRulesUnreadable:
        pass
    flow.response = http.Response.make(429, json.dumps({"ok": False, "error_code": 429, "description": "Too Many Requests: retry after 5 (the firewall is loading its rules)", "parameters": {"retry_after": 5}}), {"Content-Type": "application/json"})
    flow.metadata["cc_effect"] = "block"
    flow.metadata["cc_rule"] = "content: rules unknown"
    _log_once(flow, {**_http_record(flow, "block"), "status": 429})
    _content_audit(flow, "error", "telegram", "in", "wait", detail="rules unknown")
    return True


# Who sent a message and where, never its words: a name is not checked, or every message from a
# person whose name holds a blocked word would be stopped.
_TG_IN_SKIP = frozenset({"from", "chat", "sender_chat", "sender_business_bot", "via_bot", "forward_from", "forward_from_chat",
                         "forward_origin", "origin", "user", "new_chat_members", "left_chat_member", "users", "chats",
                         "old_chat_member", "new_chat_member", "actor_chat", "entities", "caption_entities"})
# Words a person writes that come in on an update: the outgoing fields, an inline query, a join request's bio.
_TG_IN_KEYS = _TG_TEXT_KEYS | {"query", "bio"}


# Where the agent's own message can sit on an update: checked when it went out, not read again
# coming in (a rule on messages coming in would otherwise stop a reply to it, or a tap under it).
_TG_IN_OWN_KEYS = frozenset({"reply_to_message", "pinned_message", "external_reply", "message"})


def _tg_own(msg: Any, bot_id: str) -> bool:
    """Whether a message on an update is the agent's own: its sender, or the sender it is quoted from, is the bot."""
    if not isinstance(msg, dict):
        return False
    origin = msg.get("origin") if isinstance(msg.get("origin"), dict) else {}
    senders = [msg.get("from"), origin.get("sender_user")]
    return any(isinstance(s, dict) and str(s.get("id")) == bot_id for s in senders)


def _tg_in_texts(value: Any, under_text_key: bool, out: list[str], bot_id: str, depth: int = 0) -> None:
    """
    The texts on an incoming update. Telegram's own JSON: a string is shown as written and never
    parsed, so nothing a person types can make the walk fail.
    """
    if depth > 40:
        raise _TooDeep("nested too deep")
    if isinstance(value, str):
        if under_text_key:
            out.append(value)
    elif isinstance(value, dict):
        for k, v in value.items():
            if k in _TG_IN_SKIP or (depth > 0 and k in _TG_IN_OWN_KEYS and _tg_own(v, bot_id)):
                continue
            if k == "quote" and _tg_own(value.get("reply_to_message"), bot_id):
                continue  # a quote of the agent's own message
            _tg_in_texts(v, under_text_key or k in _TG_IN_KEYS, out, bot_id, depth + 1)
    elif isinstance(value, list):
        for v in value:
            _tg_in_texts(v, under_text_key, out, bot_id, depth + 1)


def _tg_update_text(update: dict[str, Any], bot_id: str) -> tuple[str, Any, Any] | None:
    """
    The text of one incoming update, its chat and its sender; None when it carries nothing. Every
    text in it is read, wherever it sits: the message, the one it replies to or quotes
    (`reply_to_message`, `quote`, `external_reply`), a pinned one, a poll, an inline query, every
    kind of update Telegram has or adds. Not the agent's own messages (`_TG_IN_OWN_KEYS`).
    """
    body = next((v for k, v in update.items() if k != "update_id" and isinstance(v, dict)), None)
    if body is None:
        return None
    out: list[str] = []
    _tg_in_texts({k: v for k, v in update.items() if k != "update_id"}, False, out, bot_id)
    # A button tap's chat is on the message it was tapped under.
    chat = body.get("chat") if isinstance(body.get("chat"), dict) else (body.get("message") or {}).get("chat") if isinstance(body.get("message"), dict) else None
    sender = body.get("from") if isinstance(body.get("from"), dict) else None
    return "\n".join(out), (chat or {}).get("id"), (sender or {}).get("id")


def content_rules_telegram_in(flow: http.HTTPFlow) -> None:
    """Messages coming in to the agent (`getUpdates`): a blocked one is taken out, offset kept moving."""
    if not is_telegram_flow(flow) or flow.response is None or flow.response.status_code != 200:
        return
    match = _TG_GET_UPDATES_RE.match(flow.request.path.split("?", 1)[0])
    if not match:
        return
    try:
        doc = json.loads(flow.response.get_content() or b"")
        if not isinstance(doc, dict) or doc.get("ok") is not True or not isinstance(doc.get("result"), list):
            raise ValueError("not a getUpdates answer")
    except Exception as exc:
        # An answer that cannot be read cannot be checked: the agent gets nothing this time. Its
        # offset stays where it was, so Telegram sends the same batch again on the next poll.
        log.warning(f"[content-rules] incoming Telegram answer unreadable, held back: {exc!r}")
        _content_audit(flow, "error", "telegram", "in", "block", detail="unreadable answer")
        flow.response.set_content(json.dumps({"ok": True, "result": []}).encode())
        return
    updates = doc["result"]
    if not updates:
        return
    try:
        policies = content_policy_applies(content_rules(), "in", "telegram")
    except ContentRulesUnreadable:
        policies = False  # the check below answers that
    # A policy is a call to the AI: the answer waits for it off the event loop, the flow paused.
    if policies and _off_loop(flow, lambda: _tg_in_filter(flow, match, doc, updates)):
        return
    _tg_in_filter(flow, match, doc, updates)


def _tg_in_filter(flow: http.HTTPFlow, match: "re.Match[str]", doc: dict[str, Any], updates: list[Any]) -> None:
    """`content_rules_telegram_in`'s check of one answer. Blocking when a policy covers it."""
    vm_id = flow.metadata.get("cc_vm_id")
    kept, notices = [], []
    try:
        rules = content_rules()
        texts = [(_tg_update_text(u, match.group(1)) if isinstance(u, dict) else None) for u in updates]

        def judged(found):
            try:
                return content_judge(rules, "in", "telegram", found[0], vm_id=vm_id)
            except ContentTooLong:
                return {"id": "error", "reason": "it is too long to check", "action": "block"}, []
        # Each may be a call to the AI: a few at once, so a batch waits about as long as one.
        todo = [i for i, found in enumerate(texts) if found and found[0]]
        if len(todo) > 1 and content_policy_applies(rules, "in", "telegram"):
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(todo))) as pool:
                answers = dict(zip(todo, pool.map(lambda i: judged(texts[i]), todo)))
        else:
            answers = {i: judged(texts[i]) for i in todo}
        for i, update in enumerate(updates):
            found = texts[i]
            if not found or not found[0]:
                kept.append(update)
                continue
            rule, hits = answers[i]
            _content_mark(flow, hits)
            for hit in hits:
                if hit["action"] == "log":
                    _content_audit(flow, hit["id"], "telegram", "in", "log")
            if rule is None or rule["action"] == "log":
                kept.append(update)
                continue
            _content_stopping(flow, rule, found[0])
            _content_audit(flow, rule["id"], "telegram", "in", "block")
            if found[1] is not None:
                # Not judged (the AI could not run): Telegram will not send it again, so the person is asked to.
                notices.append({"kind": "in", "botId": match.group(1), "chatId": str(found[1]), "vmId": vm_id, "reason": rule["reason"],
                                **({"failed": True} if rule.get("by") == "failed" else {})})
    except ContentRulesUnreadable:
        # The rules became unknown while Telegram answered: an empty answer, so the agent's offset
        # does not move and Telegram sends the same messages again on the next poll.
        _content_audit(flow, "error", "telegram", "in", "wait", detail="rules unknown")
        flow.response.set_content(json.dumps({**doc, "result": []}).encode())
        return
    except Exception as exc:  # fail closed: nothing with text goes in unchecked
        log.warning(f"[content-rules] incoming Telegram check failed, holding back messages: {exc!r}")
        _content_audit(flow, "error", "telegram", "in", "block")
        notices = []
        try:
            kept = [u for u in updates if not (isinstance(u, dict) and (_tg_update_text(u, match.group(1)) or ("",))[0])]
        except Exception:
            # Not even that could be worked out: only the offset goes through.
            kept = []
    if len(kept) == len(updates):
        return
    kept = keep_top_update(updates, kept)
    flow.response.set_content(json.dumps({**doc, "result": kept}).encode())
    for notice in notices:
        _content_notice(notice)


_own_marker: tuple[float, float] = (0.0, 0.0)  # (the marker's mtime, until when it says to ask)


def _content_own_marker_fresh() -> bool:
    """Whether the mitm-agent's marker says it remembers a text it had an agent send. A stat and, when it changed, a small read."""
    global _own_marker
    try:
        mtime = os.stat(CONTENT_OWN_PATH).st_mtime
    except OSError:
        return False
    if mtime != _own_marker[0]:
        try:
            with open(CONTENT_OWN_PATH, encoding="utf-8") as fh:
                until = float(json.load(fh)["until"])
        except (OSError, ValueError, KeyError, TypeError):
            until = 0.0
        _own_marker = (mtime, until)
    return time.time() <= _own_marker[1]


def _content_own_ask(text: str) -> str | None:
    """Blocking: the mitm-agent's answer to `/own`. Any failure is None, so the message is checked whole."""
    try:
        rest = _content_post("/own", {"text": text}, timeout=2).get("rest")
    except (OSError, ValueError) as exc:
        log.warning(f"[content-rules] could not ask about the firewall's own text: {exc}")
        return None
    return rest if isinstance(rest, str) else None


async def _content_out_evaluate(rules: list[dict[str, Any]], channel: str, text: str, vm_id: str | None = None) -> tuple[dict[str, Any] | None, list[dict[str, Any]], str]:
    """
    The engine and the policies on a Telegram or Slack message going out (the channels a code goes
    on). When a rule would act, or a policy is to be asked, and the marker is fresh, the mitm-agent
    is asked, off the event loop, for the message with the firewall's own text taken out (a code it
    had the agent send, which quotes the rule and its policy), and the rest is checked.
    """
    rule, hits = _content_evaluate_shown(rules, "out", channel, text)
    policies = content_policy_applies(rules, "out", channel)
    if ((rule is not None and rule["action"] != "log") or policies) and _content_own_marker_fresh():
        rest = await asyncio.to_thread(_content_own_ask, text)
        if rest is not None:
            text = rest
            rule, hits = _content_evaluate_shown(rules, "out", channel, text)
    if policies:
        rule, hits = await asyncio.to_thread(content_judge, rules, "out", channel, text, (rule, hits), vm_id)
    return rule, hits, text


def _content_acted(flow: http.HTTPFlow | None, rule: dict[str, Any] | None, hits: list[dict[str, Any]], direction: str, channel: str, text: str, once: str | None = None) -> dict[str, Any] | None:
    """Every log-only hit recorded, and the rule that acts (block or hold), or None."""
    _content_mark(flow, hits)
    for hit in hits:
        if hit["action"] == "log":
            _content_audit(flow, hit["id"], channel, direction, "log", once=once)
    if rule is None or rule["action"] == "log":
        return None
    _content_stopping(flow, rule, text)
    return rule


def _content_acting(flow: http.HTTPFlow | None, rules: list[dict[str, Any]], direction: str, channel: str, text: str, once: str | None = None,
                    found: tuple[dict[str, Any] | None, list[dict[str, Any]]] | None = None) -> dict[str, Any] | None:
    """
    The engine and the policies on one text: every log-only hit recorded, and the rule that acts
    (block or hold), or None. Blocking when a policy covers it: off the event loop only. `found`:
    the engine's answer, when the caller read the text its own way.
    """
    rule, hits = content_judge(rules, direction, channel, text, found, vm_id=flow.metadata.get("cc_vm_id") if flow is not None else None)
    return _content_acted(flow, rule, hits, direction, channel, text, once)


def _held_answer(flow: http.HTTPFlow, rule: dict[str, Any], channel: str, hold_id: str, status: int, body: dict[str, Any]) -> None:
    """The agent is told its message went (decided 2026-10-15): the people who get codes decide."""
    flow.response = http.Response.make(status, json.dumps(body), {"Content-Type": "application/json"})
    flow.metadata["cc_effect"] = "hold"
    flow.metadata["cc_rule"] = f"content: {rule['id']}"
    _log_once(flow, {**_http_record(flow, "hold"), "status": status})
    _content_audit(flow, rule["id"], channel, "out", "hold", hold=hold_id)


async def _content_hold(flow: http.HTTPFlow, payload: dict[str, Any]) -> dict[str, Any] | None:
    """Hand a message to the mitm-agent to keep and ask about; its answer, or None when nobody could be asked."""
    _content_unstop(flow, (payload.get("rule") or {}).get("id"))
    key = uuid.uuid4().hex
    try:
        answer = await asyncio.to_thread(_content_post, "/hold", {**payload, "key": key}, CONTENT_HOLD_WAIT)
    except Exception:
        # Gave up waiting: the agent is told it was stopped, so a hold must not survive.
        try:
            await asyncio.to_thread(_content_post, "/cancel", {"key": key})
        except Exception as exc:
            log.warning(f"[content-rules] hold cancel not handed over: {exc!r}")
        raise
    return answer if answer.get("ok") is True and isinstance(answer.get("holdId"), str) else None


def _rule_brief(rule: dict[str, Any]) -> dict[str, Any]:
    """A rule as a hold or the stopped record names it; `ai` when the AI found it or could not run."""
    return {"id": str(rule.get("id"))[:64], "name": str(rule.get("name") or rule.get("id"))[:80], "reason": str(rule.get("reason", ""))[:240],
            **({"ai": rule["by"]} if rule.get("by") in ("found", "failed") else {})}


# ---- Slack ---------------------------------------------------------------------------------------
# Out: the Web API (`slack.com/api/<method>`) and incoming webhooks (`hooks.slack.com`). In: the
# Socket Mode websocket the agent's Slack app holds open (`wss-*.slack.com`), one JSON frame per
# event, each acknowledged by the client with its `envelope_id`.

_SLACK_API_HOSTS = ("slack.com", "api.slack.com")
_SLACK_METHOD_RE = re.compile(r"^/api/([A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)+)$")
_SLACK_TEXT_KEYS = {"text", "initial_comment", "title", "pretext", "fallback", "footer", "author_name", "alt_text", "topic",
                    "purpose", "description", "markdown", "markdown_text", "status_text", "label", "placeholder", "name", "value",
                    "header", "subtitle", "content"}
_SLACK_HOLDABLE = {"chat.postMessage", "chat.update"}


def _flow_names(flow: http.HTTPFlow) -> set[str]:
    return {n.lower() for n in (flow.request.pretty_host, getattr(flow.client_conn, "sni", None) or "") if n}


def is_slack_out_flow(flow: http.HTTPFlow) -> bool:
    names = _flow_names(flow)
    return (bool(names & set(_SLACK_API_HOSTS)) and flow.request.path.startswith("/api/")) or "hooks.slack.com" in names


def _slack_refuse(flow: http.HTTPFlow, rule: dict[str, Any] | None, detail: str, reason: str | None = None) -> None:
    reason = rule["reason"] if rule else (reason or "the check could not run")
    # Slack answers its errors with HTTP 200 and `ok: false`; its clients raise on that.
    flow.response = http.Response.make(200, json.dumps({
        "ok": False, "error": "blocked_by_organization_rules",
        "response_metadata": {"messages": [f"Blocked by your organization's rules: {reason}{detail}"]},
    }), {"Content-Type": "application/json"})
    flow.metadata["cc_effect"] = "block"
    flow.metadata["cc_rule"] = f"content: {rule['id']}" if rule else "content: error"
    _log_once(flow, {**_http_record(flow, "block"), "status": 200})


def _slack_auth(flow: http.HTTPFlow, fields: list[tuple[str, Any]]) -> str | None:
    """The token the call was made with (a placeholder on a secured box), for the mitm-agent to find the bot."""
    header = flow.request.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header[7:].strip()[:200] or None
    token = next((v for k, v in fields if k == "token" and isinstance(v, str)), None)
    return token[:200] if token else None


async def content_rules_slack_out(flow: http.HTTPFlow, vm_id: str | None) -> bool:
    """An agent's outgoing Slack call: True when it was answered here (blocked or held)."""
    try:
        hook = "hooks.slack.com" in _flow_names(flow)
        match = None if hook else _SLACK_METHOD_RE.match(flow.request.path.split("?", 1)[0])
        if not hook and not match:
            # Anything else under /api/ still reaches Slack with the real token after the swap.
            _slack_refuse(flow, None, "", reason="this Slack call could not be checked")
            _content_audit(flow, "error", "slack", "out", "block", detail="unmatched path")
            return True
        if flow.request.method.upper() in ("GET", "HEAD") and not flow.request.query:
            return False
        fields, is_json = _tg_out_fields(flow)
        text = _tg_text(fields, _SLACK_TEXT_KEYS)
        if not text:
            return False
        rule, hits, text = await _content_out_evaluate(content_rules(), "slack", text, vm_id)
        rule = _content_acted(flow, rule, hits, "out", "slack", text)
        if rule is None:
            return False
        method = match.group(1) if match else None
        channel = next((v for k, v in fields if k == "channel" and isinstance(v, str)), None)
        auth = _slack_auth(flow, fields)
        if rule["action"] == "hold":
            detail = " (it could not be held for approval)"
            if method in _SLACK_HOLDABLE and channel and not flow.request.query and len(flow.request.raw_content or b"") <= CONTENT_HOLD_BODY_MAX:
                answer = await _content_hold(flow, {
                    "channel": "slack", "method": method, "body": _out_body(flow)[2],
                    "contentType": "json" if is_json else "form", "chatId": channel, "auth": auth, "vmId": vm_id,
                    "rule": _rule_brief(rule), "text": text[:CONTENT_HOLD_TEXT_MAX]})
                if answer:
                    first_text = next((v for k, v in fields if k == "text" and isinstance(v, str)), "")
                    ts = next((v for k, v in fields if k == "ts" and isinstance(v, str)), None) or f"{int(time.time())}.{secrets.randbelow(1_000_000):06d}"
                    body = ({"ok": True, "channel": channel, "ts": ts, "message": {"type": "message", "text": first_text, "ts": ts}}
                            if method == "chat.postMessage" else {"ok": True, "channel": channel, "ts": ts, "text": first_text})
                    _held_answer(flow, rule, "slack", answer["holdId"], 200, body)
                    return True
                detail = " (nobody could be asked to approve it)"
            _slack_refuse(flow, rule, detail)
            _content_audit(flow, rule["id"], "slack", "out", "block", held=False)
        else:
            _slack_refuse(flow, rule, "")
            _content_audit(flow, rule["id"], "slack", "out", "block")
        if channel:
            thread = next((v for k, v in fields if k == "thread_ts" and isinstance(v, str)), None)
            _content_notice({"kind": "out", "channel": "slack", "chatId": channel, "auth": auth, "vmId": vm_id, "reason": rule["reason"],
                             **({"threadTs": thread} if thread else {})})
        return True
    except ContentTooLong:
        _slack_refuse(flow, None, "", reason="it is too long to check")
        _content_audit(flow, "error", "slack", "out", "block", detail="too long")
        return True
    except Exception as exc:  # fail closed, the rules being unknown included
        log.warning(f"[content-rules] outgoing Slack check failed, refusing: {exc!r}")
        _slack_refuse(flow, None, "")
        _content_audit(flow, "error", "slack", "out", "block")
        return True


def is_slack_socket(flow) -> bool:
    host = flow.request.pretty_host.lower()
    return host.endswith(".slack.com") and host.startswith("wss")


def _slack_ack(flow, envelope_id: str) -> None:
    """Acknowledge an event the agent will not see, so Slack does not send it again."""
    try:
        _mitm_ctx.master.commands.call("inject.websocket", flow, False, json.dumps({"envelope_id": envelope_id}).encode())
    except Exception as exc:  # no master (a test), or the socket is closing: Slack sends it again, and it is stopped again
        log.warning(f"[content-rules] could not acknowledge a stopped Slack event: {exc!r}")


def content_rules_slack_socket(flow) -> None:
    """One frame from Slack to the agent's Socket Mode client: an event with a message on it is checked."""
    message = flow.websocket.messages[-1] if flow.websocket and flow.websocket.messages else None
    if message is None or message.from_client:
        return
    try:
        policies = content_policy_applies(content_rules(), "in", "slack")
    except ContentRulesUnreadable:
        policies = False  # the check answers that
    if policies:
        # A policy is a call to the AI: the frame waits for it off the event loop, the socket paused.
        loop = _running_loop()
        if loop is not None and _off_loop(flow, lambda: _slack_socket_check(flow, message, loop)):
            return
    _slack_socket_check(flow, message, None)


def _slack_socket_check(flow, message, loop: asyncio.AbstractEventLoop | None) -> None:
    """`content_rules_slack_socket`'s check of one frame. Blocking when a policy covers it."""
    try:
        try:
            frame = json.loads(message.content)
        except (ValueError, UnicodeError):
            return  # not an event: Slack's pings and the like
        if not isinstance(frame, dict) or frame.get("type") not in ("events_api", "slash_commands"):
            return
        payload = frame.get("payload") if isinstance(frame.get("payload"), dict) else {}
        event = payload.get("event") if frame["type"] == "events_api" else payload
        if not isinstance(event, dict):
            return
        out: list[str] = []
        _tg_texts(event, False, out, 0, _SLACK_TEXT_KEYS)
        text = "\n".join(out)
        if not text:
            return
        try:
            rules = content_rules()
            rule = _content_acting(flow, rules, "in", "slack", text, found=_content_evaluate_shown(rules, "in", "slack", text))
        except ContentTooLong:
            rule = {"id": "error", "reason": "it is too long to check", "action": "block"}
        if rule is None:
            return
        message.drop()
        failed = rule.get("by") == "failed"
        # Not judged (the AI could not run): not acknowledged, so Slack sends it again later.
        if isinstance(frame.get("envelope_id"), str) and not failed:
            # mitmproxy's injection runs on its event loop, not in this thread.
            if loop is not None:
                loop.call_soon_threadsafe(_slack_ack, flow, frame["envelope_id"])
            else:
                _slack_ack(flow, frame["envelope_id"])
        _content_audit(flow, rule["id"], "slack", "in", "block")
        channel = event.get("channel") or event.get("channel_id")
        user = event.get("user") or event.get("user_id")
        if isinstance(channel, str) and isinstance(user, str):
            _content_notice({"kind": "in", "channel": "slack", "chatId": channel, "userId": user, "vmId": flow.metadata.get("cc_vm_id"), "reason": rule["reason"],
                             **({"failed": True} if failed else {})})
    except Exception as exc:  # fail closed: the frame is not passed on, and not acknowledged, so Slack sends it again
        log.warning(f"[content-rules] incoming Slack check failed, held back: {exc!r}")
        _content_audit(flow, "error", "slack", "in", "block")
        message.drop()
    finally:
        flow.websocket.messages.clear()


# ---- Voice ---------------------------------------------------------------------------------------
# Meetings and calls (docs/plans/firewall-content-rules.md §5.2), on the voice socket that
# `voice_request` admitted, after its frame policy. In: the question to the main agent. gpt-realtime
# carries it in the `ask_agent` arguments, which become a fixed sentence. gpt-live delegates with no
# text and the box builds the question from what it heard since its last delegation and what the
# voice just said, so the firewall checks all of the last VOICE_QUESTION_WINDOW of both: never less
# than the box sends. A stopped delegation is answered here and never reaches the box. Out: the main
# agent's answer, replaced with the refusal. A hold stops (a voice cannot wait). No transcript is
# filtered and nothing is kept past the socket.

VOICE_BLOCKED_QUESTION = "This request was blocked by the firewall. Reply only with the word blocked."
# At least the box's own windows (`live.js`: QUESTION_WINDOW, 45 s, for what was heard, 15 s for what
# was said), with a margin: the firewall times a line by its arrival, the box by its own event loop.
VOICE_QUESTION_WINDOW = 50
# The main agent's words as the box marks them (`live.js`): a lookup's answer, and with no delegation
# of the session, a task's result and an answer to a lookup taken over from an ended session.
VOICE_ANSWER_PREFIXES = ("Result of the lookup:", "Result of a task:", "Answer to an earlier lookup:")
# Said instead of a rule's reason that itself contains what the rule stops: the voice would say the
# words aloud, and hear them again in the next question.
VOICE_PLAIN_REASON = "this is not discussed here"
VOICE_APPEND_MAX = 4000
# How often a socket asks whether any rule reads voice coming in, to skip keeping its transcript.
VOICE_APPLIES_EVERY = 5
_JSON_ESCAPE_RE = re.compile(r'\\(?:u([0-9a-fA-F]{4})|(["\\/bfnrt]))')
_JSON_ESCAPES = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def _voice_refusal(reason: str) -> str:
    # A reason that ends a sentence itself is not given a second full stop.
    return (f"Blocked by your organization's rules: {reason.rstrip(' .')}. Tell the person plainly that you cannot help with this "
            "here. This is a policy decision, not a technical failure.")[:VOICE_APPEND_MAX]


def _voice_rule(flow, voice: dict[str, Any], direction: str, text: str, must_check: bool = True) -> dict[str, Any] | None:
    """
    The rule that stops this text, recorded; None when it may pass. Rules that cannot be read stop it
    when `must_check` (a question, an answer of the agent's), and let the box's own lines through.
    """
    extra = {"purpose": voice.get("purpose", "meeting")}
    try:
        rules = content_rules()
    except ContentRulesUnreadable:
        if not must_check:
            return None
        # Once per socket and direction: a call does not write a line for every frame.
        _content_audit(flow, "error", "voice", direction, "block", once=getattr(flow, "id", None), detail="rules unknown", **extra)
        return {"id": "error", "reason": "the firewall's rules are not available", "action": "block"}
    if not text or not content_applies(rules, direction, "voice"):
        return None
    try:
        rule = _content_acting(flow, rules, direction, "voice", text)
    except ContentTooLong:
        rule = {"id": "error", "reason": "it is too long to check", "action": "block"}
    if rule is None:
        return None
    _content_audit(flow, rule["id"], "voice", direction, "block", **extra, **({"held": False} if rule["action"] == "hold" else {}))
    if any(content_evaluate(rules, d, "voice", rule["reason"])[1] for d in ("in", "out")):
        rule = {**rule, "reason": VOICE_PLAIN_REASON}
    return rule


def _json_unescape_loose(text: str) -> str:
    """JSON escapes undone in a string that may not parse (an answer the box cut to fit)."""
    def one(m: "re.Match[str]") -> str:
        if m.group(1):
            return chr(int(m.group(1), 16))
        return _JSON_ESCAPES.get(m.group(2), m.group(2))
    return _JSON_ESCAPE_RE.sub(one, text)


def _voice_texts(value: Any) -> str:
    """Every string in an answer, JSON in a string included; escapes undone where it does not parse."""
    out: list[str] = []
    try:
        _tg_texts(value, True, out)
    except ValueError:  # a repeated key, too deep: the raw text is checked instead
        out = [value if isinstance(value, str) else json.dumps(value)]
    return "\n".join(_json_unescape_loose(t) if "\\" in t else t for t in out)


def _voice_reads_in(state: dict[str, Any]) -> bool:
    """Whether to keep this socket's transcript: a rule reads voice coming in, or the rules are unknown."""
    now = time.monotonic()
    if now - state.get("applies_at", -VOICE_APPLIES_EVERY) >= VOICE_APPLIES_EVERY:
        try:
            state["applies"] = content_applies(content_rules(), "in", "voice")
        except ContentRulesUnreadable:
            state["applies"] = True
        state["applies_at"] = now
    return state["applies"]


def content_rules_voice(flow, voice: dict[str, Any], message, event: Any, loop: asyncio.AbstractEventLoop | None = None) -> None:
    """
    One frame the voice policy let through. Raises on a frame it cannot check: the caller closes the
    voice. `loop` when it runs in a thread (a policy to ask): a frame is then injected on the loop.
    """
    if not isinstance(event, dict) or getattr(message, "injected", False):
        return
    kind = event.get("type")
    state = voice.setdefault("content", {})
    if voice.get("family") == "live":
        if not message.from_client:
            if kind in ("session.input_transcript.delta", "session.output_transcript.delta") and isinstance(event.get("delta"), str):
                if not _voice_reads_in(state):
                    return
                now = time.monotonic()
                heard = state.setdefault("heard", collections.deque())
                heard.append((now, event["delta"]))
                while heard and now - heard[0][0] > VOICE_QUESTION_WINDOW:
                    heard.popleft()
            elif kind == "session.delegation.created":
                delegation = event.get("delegation")
                did = delegation.get("id") if isinstance(delegation, dict) else None
                if not isinstance(did, str) or not did or len(did) > 200:
                    return  # the box refuses it itself
                now = time.monotonic()
                text = "".join(t for at, t in state.get("heard", ()) if now - at <= VOICE_QUESTION_WINDOW).strip()
                rule = _voice_rule(flow, voice, "in", text)
                if rule is None:
                    return
                # The box never starts this lookup. The answer is spoken, but the box plays the voice
                # only to someone who addressed it (wake word, always listening), as for its own answers.
                message.drop()
                answer = json.dumps({"type": "session.commentary.append", "delegation_id": did, "content": _voice_refusal(rule["reason"])}).encode()
                if loop is not None:
                    loop.call_soon_threadsafe(lambda: _mitm_ctx.master.commands.call("inject.websocket", flow, False, answer))
                else:
                    _mitm_ctx.master.commands.call("inject.websocket", flow, False, answer)
            return
        if kind in ("session.commentary.append", "session.thinking.append") and isinstance(event.get("content"), str):
            content = event["content"]
            answer = event.get("delegation_id") is not None or content.startswith(VOICE_ANSWER_PREFIXES)
            # Quiet context (lines of the meeting heard) is not the agent's words.
            if kind == "session.thinking.append" and not answer:
                return
            # The box's own spoken lines (the greeting, an acknowledgement, an older box's task result)
            # are checked when the rules are known, and not stopped for want of them.
            rule = _voice_rule(flow, voice, "out", content, must_check=answer)
            if rule is not None:
                event["content"] = _voice_refusal(rule["reason"])
                message.content = json.dumps(event).encode()
        return
    gateway = voice.get("provider") == "gateway"
    call_key = "callId" if gateway else "call_id"
    if not message.from_client:
        if kind not in ("function-call-arguments-done", "response.function_call_arguments.done"):
            return
        call_id, raw = event.get(call_key), event.get("arguments")
        try:
            args = json.loads(raw) if isinstance(raw, str) else None
        except ValueError:
            return  # the box refuses it itself
        if not isinstance(args, dict) or not isinstance(call_id, str):
            return
        rule = _voice_rule(flow, voice, "in", _voice_texts({k: args.get(k) for k in ("question", "context")}))
        if rule is None:
            return
        event["arguments"] = json.dumps({"question": VOICE_BLOCKED_QUESTION})
        message.content = json.dumps(event).encode()
        blocked = state.setdefault("blocked", {})
        blocked[call_id] = rule["reason"]
        while len(blocked) > 50:
            del blocked[next(iter(blocked))]
        return
    if kind not in ("conversation-item-create", "conversation.item.create"):
        return
    item = event.get("item")
    if not isinstance(item, dict) or item.get("type") not in ("function-call-output", "function_call_output"):
        return
    reason = state.get("blocked", {}).pop(item.get(call_key), None)
    if reason is None:
        rule = _voice_rule(flow, voice, "out", _voice_texts(item.get("output")))
        reason = rule["reason"] if rule is not None else None
    if reason is not None:
        item["output"] = json.dumps({"status": "blocked", "message": _voice_refusal(reason)})
        message.content = json.dumps(event).encode()


# ---- Email ---------------------------------------------------------------------------------------
# Out: after the email rules let a write through (recipients, limits), the text of the message:
# AgentMail's JSON (subject, text, HTML) and Gmail's MIME message (subject, text and HTML parts).
# Drafts are read when they are written, because sending one carries no text. In: AgentMail messages
# the email rules kept (`agentmail_filter`), and Gmail's `messages.get` and `threads.get`.

_TAG_RE = re.compile(r"<[^<>]{0,4000}>")
# Tags that do not break a word where they sit, and comments.
_INLINE_TAG_RE = re.compile(r"<(?:!--|/?(?:a|abbr|b|bdi|bdo|code|em|font|i|kbd|mark|q|s|samp|small|span|strike|strong|sub|sup|u|var|wbr)\b)", re.IGNORECASE)


def _html_text(html: str) -> str:
    """
    The words of an HTML body: tags as spaces (`<p>customer</p><p>list</p>`), and again, when it has
    inline tags, with those taken out, as a mail client shows them (`pass<b></b>word`).
    """
    spaced = html_unescape(_TAG_RE.sub(" ", html))
    if not _INLINE_TAG_RE.search(html):
        return spaced
    return spaced + "\n" + html_unescape(_TAG_RE.sub(lambda m: "" if _INLINE_TAG_RE.match(m.group(0)) else " ", html))


def _mime_text(message: bytes) -> str:
    """The subject and the text and HTML parts of a MIME message, decoded."""
    import email.parser
    import email.policy
    msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(message)
    out = [str(msg.get("subject") or "")]
    for part in msg.walk():
        ctype = part.get_content_type()
        if part.is_multipart() or ctype not in ("text/plain", "text/html") or part.get_filename():
            continue
        body = part.get_content()
        out.append(_html_text(body) if ctype == "text/html" else body)
    return "\n".join(t for t in out if t)


def _agentmail_text(item: dict[str, Any]) -> str:
    out = [item.get(k) for k in ("subject", "preview", "text", "extracted_text")]
    out += [_html_text(item[k]) for k in ("html", "extracted_html") if isinstance(item.get(k), str)]
    return "\n".join(t for t in out if isinstance(t, str) and t)


_GM_DRAFT_WRITE = re.compile(r"^/(upload/)?gmail/v1/users/[^/]+/drafts(?:/[^/]+)?$")


def _email_out_text(flow: http.HTTPFlow) -> tuple[str, bool] | None:
    """The text of an outgoing message and whether it can be held, or None when the request carries no message."""
    from urllib.parse import unquote
    host = flow.request.pretty_host.lower()
    method = flow.request.method.upper()
    path = flow.request.path.split("?", 1)[0]
    if method not in ("POST", "PUT", "PATCH"):
        return None
    if host == AGENTMAIL_API:
        body = _json_body(flow)
        if body is None or not any(k in body for k in ("subject", "text", "html")):
            return None
        return _agentmail_text(body), bool(_AM_SEND.match(path) or _AM_MSG_OP.match(path))
    if not is_googleapis(host):
        return None
    path = re.sub(r"/+", "/", unquote(path)).rstrip("/")
    if not (_GM_SEND.match(path) or _GM_DRAFT_WRITE.match(path)):
        return None
    if path.startswith("/upload/"):
        upload_type = flow.request.query.get("uploadType", "")
        if upload_type not in ("media", "multipart"):
            # A resumable upload sends the message in a later request this check cannot tie back:
            # refused, as the email rules refuse it for a send.
            raise ValueError("an upload the firewall cannot read")
        message = flow.request.get_content() if upload_type == "media" else _multipart_message(flow)
        if not message:
            raise ValueError("an upload the firewall cannot read")
    else:
        body = _json_body(flow) or {}
        inner = body.get("message") if isinstance(body.get("message"), dict) else body
        message = _b64url(inner.get("raw")) if inner.get("raw") is not None else None
    if not message:
        return None  # a draft sent by its id: its text was read when it was written
    return _mime_text(message), False


def _agentmail_forward(flow: http.HTTPFlow) -> tuple[str, str] | None:
    """The inbox and message of an AgentMail forward, or None."""
    from urllib.parse import unquote
    if flow.request.pretty_host.lower() != AGENTMAIL_API or flow.request.method.upper() != "POST":
        return None
    m = _AM_MSG_OP.match(flow.request.path.split("?", 1)[0])
    return (unquote(m.group(1)), unquote(m.group(2))) if m and m.group(3) == "forward" else None


AGENTMAIL_FORWARD_READ_MAX = 4 * 1024 * 1024


def _agentmail_get(url: str, key: str) -> dict[str, Any]:
    """One AgentMail read from the firewall itself. Blocking: run it off the event loop."""
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as res:
        raw = res.read(AGENTMAIL_FORWARD_READ_MAX + 1)
    if len(raw) > AGENTMAIL_FORWARD_READ_MAX:
        raise ContentTooLong(len(raw))
    doc = json.loads(raw)
    if not isinstance(doc, dict):
        raise ValueError("not a message")
    return doc


def _agentmail_message_text(flow: http.HTTPFlow, vm_id: str | None, inbox: str, message_id: str) -> str:
    """The text of a message a forward sends on. Raises when it cannot be read: the forward is refused."""
    from urllib.parse import quote
    auth = flow.request.headers.get("authorization", "")
    token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
    # The agent holds a placeholder; the key is the one the proxy would put in its place.
    key = next((_secret_value(c) for c in credentials_for(AGENTMAIL_API, vm_id) if token and c.get("placeholder") == token), None) or token
    if not key:
        raise ValueError("a forward with no key")
    try:
        doc = _agentmail_get(f"https://{AGENTMAIL_API}/v0/inboxes/{quote(inbox, safe='@')}/messages/{quote(message_id, safe='')}", key)
    except ContentTooLong:
        raise
    except Exception as exc:
        # Its own words only: an error about the request can carry the key (a header that would not encode).
        raise ValueError(f"the forwarded mail could not be read ({type(exc).__name__})") from None
    return _agentmail_text(doc)


async def content_rules_email_out(flow: http.HTTPFlow, vm_id: str | None) -> bool:
    """An agent's outgoing email, after the email rules: True when it was answered here (blocked or held)."""
    def refuse(rule: dict[str, Any] | None, detail: str, reason: str | None = None) -> None:
        why = rule["reason"] if rule else (reason or "the check could not run")
        _email_refuse(flow, "content_rule", f"Blocked by your organization's rules: {why}{detail}", f"content: {rule['id']}" if rule else "content: error")
    try:
        found = _email_out_text(flow)
        forward = _agentmail_forward(flow)
        if not forward and (not found or not found[0]):
            return False
        rules = content_rules()
        if not content_applies(rules, "out", "email"):
            return False
        text, holdable = found or ("", True)
        if forward:
            # A forward sends a received mail on, which its body does not carry: read with the
            # agent's own key, as the agent could read it, and checked with the forward's own words.
            original = await asyncio.to_thread(_agentmail_message_text, flow, vm_id, *forward)
            text = "\n".join(t for t in (text, original) if t)
            if not text:
                return False
        rule = (await asyncio.to_thread(_content_acting, flow, rules, "out", "email", text) if content_policy_applies(rules, "out", "email")
                else _content_acting(flow, rules, "out", "email", text))
        if rule is None:
            return False
        if rule["action"] == "hold":
            detail = " (it could not be held for approval)"
            m = _AM_SEND.match(flow.request.path.split("?", 1)[0]) or _AM_MSG_OP.match(flow.request.path.split("?", 1)[0])
            if holdable and m and len(flow.request.raw_content or b"") <= CONTENT_HOLD_BODY_MAX:
                from urllib.parse import unquote
                answer = await _content_hold(flow, {
                    "channel": "email", "method": flow.request.method.upper(), "path": flow.request.path.split("?", 1)[0],
                    "body": flow.request.get_text(strict=False), "chatId": unquote(m.group(1)), "vmId": vm_id, "rule": _rule_brief(rule),
                    "text": text[:CONTENT_HOLD_TEXT_MAX]})
                if answer:
                    held = f"held-{answer['holdId']}"
                    _held_answer(flow, rule, "email", answer["holdId"], 200, {"message_id": held, "thread_id": held})
                    return True
                detail = " (nobody could be asked to approve it)"
            refuse(rule, detail)
            _content_audit(flow, rule["id"], "email", "out", "block", held=False)
        else:
            refuse(rule, "")
            _content_audit(flow, rule["id"], "email", "out", "block")
        return True
    except ContentTooLong:
        refuse(None, "", reason="it is too long to check")
        _content_audit(flow, "error", "email", "out", "block", detail="too long")
        return True
    except Exception as exc:  # fail closed
        log.warning(f"[content-rules] outgoing email check failed, refusing: {exc!r}")
        refuse(None, "")
        _content_audit(flow, "error", "email", "out", "block")
        return True


def _agentmail_blocked(flow: http.HTTPFlow | None, rules: list[dict[str, Any]]):
    """The content rules' word on one AgentMail message or thread the email rules kept. Errors hide it."""
    applies = content_applies(rules, "in", "email")

    def blocked(item: dict[str, Any]) -> bool:
        """Raises on a check that could not run: the caller answers "try again" rather than hide the
        message, which the agent's channel would settle for good."""
        if not applies:
            return False
        once = str(item.get("message_id") or item.get("thread_id") or "")[:200] or None
        text = _agentmail_text(item)
        try:
            rule = _content_acting(flow, rules, "in", "email", text, once) if text else None
        except ContentTooLong:
            rule = {"id": "error"}  # stopped like a block: more than a check reads
        if rule is not None and rule.get("by") == "failed":
            # Not judged: "try again" keeps the mail, where hiding it would settle it for good.
            _content_audit(flow, rule["id"], "email", "in", "wait", once=once)
            raise ContentCheckUnavailable("the AI check could not run")
        if rule is not None:
            _content_audit(flow, rule["id"], "email", "in", "block", once=once)
        return rule is not None
    return blocked


def content_rules_agentmail_before(flow: http.HTTPFlow) -> bool:
    """
    An AgentMail write reads the rules before it goes, for its answer to be checked with: while they
    are not known it is refused ("try again") here, before anything was sent. True when refused.
    """
    if flow.request.pretty_host.lower() != AGENTMAIL_API or flow.request.method.upper() in ("GET", "HEAD", "OPTIONS"):
        return False
    try:
        flow.metadata["cc_content_rules"] = content_rules()
        return False
    except ContentRulesUnreadable:
        flow.response = http.Response.make(503, '{"error":"rules_loading","message":"The firewall is loading its rules. Try again in a few seconds."}', {"Content-Type": "application/json"})
        flow.metadata["cc_effect"] = "block"
        flow.metadata["cc_rule"] = "content: rules unknown"
        _log_once(flow, {**_http_record(flow, "block"), "status": 503})
        return True


_AM_RAW = re.compile(r"^/v0/inboxes/[^/]+/messages/[^/]+/raw$")


def content_rules_agentmail_raw(flow: http.HTTPFlow) -> bool:
    """
    The raw message is the whole mail, which the JSON filter never sees: while a rule reads mail
    coming in, it is refused (the agent reads the message itself, which is checked). True when refused.
    """
    if flow.request.pretty_host.lower() != AGENTMAIL_API or not _AM_RAW.match(flow.request.path.split("?", 1)[0]):
        return False
    try:
        if not content_applies(content_rules(), "in", "email"):
            return False
    except ContentRulesUnreadable:
        pass
    _email_refuse(flow, "content_rule", "Read the message instead of its raw form: your organization's content rules check messages coming in.", "content: raw read")
    return True


_GM_READ = re.compile(r"^/gmail/v1/users/[^/]+/(messages|threads)/[^/]+$")
_GM_NOT_FOUND = json.dumps({"error": {"code": 404, "message": "Requested entity was not found.", "status": "NOT_FOUND"}})


def _gmail_message_text(m: dict[str, Any]) -> str:
    out = [m.get("snippet") if isinstance(m.get("snippet"), str) else ""]
    raw = _b64url(m.get("raw")) if m.get("raw") is not None else None
    if raw:
        out.append(_mime_text(raw))

    def walk(part: Any, depth: int = 0) -> None:
        if not isinstance(part, dict) or depth > 30:
            return
        for h in part.get("headers") or []:
            if isinstance(h, dict) and str(h.get("name", "")).lower() == "subject" and isinstance(h.get("value"), str):
                out.append(h["value"])
        mime = str(part.get("mimeType") or "")
        data = (part.get("body") or {}).get("data") if isinstance(part.get("body"), dict) else None
        if mime in ("text/plain", "text/html") and not part.get("filename") and data:
            decoded = (_b64url(data) or b"").decode("utf-8", errors="replace")
            out.append(_html_text(decoded) if mime == "text/html" else decoded)
        for child in part.get("parts") or []:
            walk(child, depth + 1)
    walk(m.get("payload"))
    return "\n".join(t for t in out if t)


def content_rules_gmail_in(flow: http.HTTPFlow) -> None:
    """A message or thread the agent reads from Gmail: a blocked message is not found, or left out of its thread."""
    from urllib.parse import unquote
    if not is_googleapis(flow.request.pretty_host) or flow.request.method.upper() != "GET" or flow.response is None or flow.response.status_code != 200:
        return
    m = _GM_READ.match(re.sub(r"/+", "/", unquote(flow.request.path.split("?", 1)[0])).rstrip("/"))
    if not m:
        return
    try:
        rules = content_rules()
        if not content_applies(rules, "in", "email"):
            return
    except ContentRulesUnreadable:
        flow.response = http.Response.make(503, json.dumps({"error": {"code": 503, "message": "The firewall is loading its rules. Try again in a few seconds.", "status": "UNAVAILABLE"}}), {"Content-Type": "application/json"})
        return
    # A raw message is the whole mail (up to 25 MB): decoded and parsed off the event loop.
    if not _off_loop(flow, lambda: _gmail_in_check(flow, m.group(1), rules)):
        _gmail_in_check(flow, m.group(1), rules)


def _gmail_in_check(flow: http.HTTPFlow, kind: str, rules: list[dict[str, Any]]) -> None:
    """`content_rules_gmail_in`'s check of one answer. Blocking."""
    try:
        doc = json.loads(flow.response.get_content() or b"")
        if not isinstance(doc, dict):
            raise ValueError("not a Gmail answer")

        def blocked(msg: Any) -> bool:
            if not isinstance(msg, dict):
                return False
            once = str(msg.get("id") or "")[:200] or None
            try:
                rule = _content_acting(flow, rules, "in", "email", _gmail_message_text(msg), once)
            except ContentTooLong:
                rule = {"id": "error"}
            if rule is not None and rule.get("by") == "failed":
                _content_audit(flow, rule["id"], "email", "in", "wait", once=once)
                raise ContentCheckUnavailable("the AI check could not run")
            if rule is not None:
                _content_audit(flow, rule["id"], "email", "in", "block", once=once)
            return rule is not None
        if kind == "messages":
            if blocked(doc):
                flow.response = http.Response.make(404, _GM_NOT_FOUND, {"Content-Type": "application/json"})
            return
        messages = doc.get("messages") if isinstance(doc.get("messages"), list) else []
        kept = [x for x in messages if not blocked(x)]
        if len(kept) == len(messages):
            return
        if not kept:
            flow.response = http.Response.make(404, _GM_NOT_FOUND, {"Content-Type": "application/json"})
            return
        flow.response.set_content(json.dumps({**doc, "messages": kept}).encode())
    except ContentCheckUnavailable:
        # Not judged: Gmail's own "try again", so the agent reads it once the AI answers.
        flow.response = http.Response.make(503, json.dumps({"error": {"code": 503, "message": "The firewall could not check this mail just now. Try again later.", "status": "UNAVAILABLE"}}), {"Content-Type": "application/json"})
    except Exception as exc:  # fail closed
        log.warning(f"[content-rules] incoming Gmail check failed, holding it back: {exc!r}")
        _content_audit(flow, "error", "email", "in", "block")
        flow.response = http.Response.make(404, _GM_NOT_FOUND, {"Content-Type": "application/json"})


# ---- The web -------------------------------------------------------------------------------------
# The body of every other request the host rules let through. Not the model providers (§1: a rule
# there would stop the agent's every later turn), the control plane, Twilio, or the channels above,
# which have adapters of their own.

MODEL_HOSTS = frozenset({
    "ai-gateway.vercel.sh", "api.openai.com", "chatgpt.com", "api.anthropic.com", "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com", "openrouter.ai", "api.x.ai", "api.mistral.ai", "api.groq.com", "api.deepseek.com",
    "api.moonshot.ai", "api.together.xyz", "api.fireworks.ai", "api.cerebras.ai", "api.perplexity.ai",
})


def _is_gmail_api_path(raw_path: str) -> bool:
    """The Gmail API, which the email checks read: by the path alone, as they read it (never the query)."""
    from urllib.parse import unquote
    path = re.sub(r"/+", "/", unquote(raw_path.split("?", 1)[0]))
    return path.startswith(("/gmail/", "/upload/gmail/"))


def _own_channel_flow(flow: http.HTTPFlow, vm_id: str | None) -> bool:
    """A request to a service the firewall reads its own way (chat, mail, phone, the control plane, AI models)."""
    host = flow.request.pretty_host.lower()
    if is_telegram_flow(flow) or is_slack_out_flow(flow) or host in (AGENTMAIL_API, AGENTMAIL_WS, "api.twilio.com"):
        return True
    if is_googleapis(host) and _is_gmail_api_path(flow.request.path):
        return True
    if CONTROL_PLANE_HOST and host_matches(CONTROL_PLANE_HOST, host):
        return True
    return host in MODEL_HOSTS or any(c.get("model") for c in credentials_for(host, vm_id))


def _web_flow(flow: http.HTTPFlow, vm_id: str | None) -> bool:
    if flow.request.method.upper() in ("GET", "HEAD", "OPTIONS") or not flow.request.raw_content:
        return False
    return not _own_channel_flow(flow, vm_id)


# Bytes of a text body (after its content encoding) the web check parses: twice what it reads, as
# JSON's quotes, keys and escapes take room. More is stopped before it is parsed.
WEB_BODY_READ_MAX = 2 * CONTENT_TEXT_MAX_LONG


def _web_text(flow: http.HTTPFlow) -> str | None:
    """The words in a request body: string values of JSON, form values, text parts, plain text. None when it is not text."""
    from urllib.parse import parse_qsl
    ctype = flow.request.headers.get("content-type") or ""
    try:
        media, params = _header_params(ctype)
    except ValueError:
        media, params = ctype.split(";", 1)[0].strip().lower(), {}
    textual = media.startswith("text/") or any(t in media for t in ("json", "xml", "javascript", "graphql", "x-www-form-urlencoded"))
    # The size before any parsing: more text than a check reads is stopped without reading it.
    # A body that says nothing of its type is read as text, as below.
    if (textual or not ctype) and len(flow.request.raw_content or b"") > WEB_BODY_READ_MAX:
        raise ContentTooLong(len(flow.request.raw_content or b""))
    raw = flow.request.get_content()
    if raw is None:
        raise ValueError("an encoding the firewall cannot read")
    if media == "multipart/form-data":
        # Read strictly (a body mitmproxy's own reader half reads is refused); a part that is not
        # UTF-8 is a file, not read.
        out = []
        for _k, v in _multipart_fields(params.get("boundary"), raw):
            try:
                out.append(v.decode("utf-8"))
            except UnicodeDecodeError:
                continue
        return "\n".join(out)
    if len(raw) > WEB_BODY_READ_MAX:
        if textual or not ctype:
            raise ContentTooLong(len(raw))
        return None  # a file, not read
    if media == "application/x-www-form-urlencoded":
        return "\n".join(v for _k, v in parse_qsl(raw.decode("utf-8", errors="replace"), keep_blank_values=True, encoding="utf-8", errors="replace"))
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        if not textual:
            return None  # binary
        text = raw.decode("utf-8", errors="replace")  # another charset: its ASCII words still read
    if "json" in media or text.lstrip()[:1] in ("{", "["):
        try:
            doc = json.loads(text, parse_int=_JsonInt, parse_float=_JsonFloat)
        except (ValueError, RecursionError):
            doc = None
        if doc is not None:
            out = []
            try:
                _tg_texts(doc, True, out, 0, set())
            except (ValueError, RecursionError):
                # Deeper than the walk goes, or a repeated key in JSON in a string: every string in
                # it, escapes undone, rather than none.
                return _json_unescape_loose(text)
            return "\n".join(out)
    if ctype and not textual:
        return None
    return text


def _web_refuse(flow: http.HTTPFlow, rule: dict[str, Any] | None, detail: str, reason: str | None = None) -> None:
    why = rule["reason"] if rule else (reason or "the check could not run")
    flow.response = http.Response.make(BLOCK_STATUS, json.dumps({
        "error": "blocked_by_content_rule", "host": flow.request.pretty_host,
        "message": f"Blocked by your organization's rules: {why}{detail}"}), {"Content-Type": "application/json"})
    flow.metadata["cc_effect"] = "block"
    flow.metadata["cc_rule"] = f"content: {rule['id']}" if rule else "content: error"
    _log_once(flow, {**_http_record(flow, "block"), "status": BLOCK_STATUS})


async def content_rules_web(flow: http.HTTPFlow, vm_id: str | None) -> bool:
    """A request body to any other site: True when it was refused here. Nothing can be held."""
    if not _web_flow(flow, vm_id):
        return False
    try:
        rules = content_rules()
        if not content_applies(rules, "out", "web"):
            return False
        text = _web_text(flow)
        if not text:
            return False
        rule = (await asyncio.to_thread(_content_acting, flow, rules, "out", "web", text) if content_policy_applies(rules, "out", "web")
                else _content_acting(flow, rules, "out", "web", text))
        if rule is None:
            return False
        # A website's answer cannot be made up, so a hold stops the request.
        _web_refuse(flow, rule, " (a request to a website cannot be held for approval)" if rule["action"] == "hold" else "")
        _content_audit(flow, rule["id"], "web", "out", "block", **({"held": False} if rule["action"] == "hold" else {}))
        return True
    except ContentTooLong:
        _web_refuse(flow, None, "", reason="it is too long to check")
        _content_audit(flow, "error", "web", "out", "block", detail="too long")
        return True
    except Exception as exc:  # fail closed
        log.warning(f"[content-rules] web check failed, refusing: {exc!r}")
        _web_refuse(flow, None, "")
        _content_audit(flow, "error", "web", "out", "block")
        return True


# ---- MCP (docs/plans/mcp-inspection.md) ----------------------------------------------------------
# A remote MCP server an agent added itself is ordinary HTTPS to this proxy. A POST whose JSON body
# holds a `tools/call` is a tool call, whatever its content type or the order of its fields: it goes
# to the mitm-agent's admission service (`mcp-admission.ts`), which runs the integration rules,
# approvals and content rules and answers pass, answer or allow. A `tools/list` answer goes there too,
# to teach the catalog and lose the tools a rule blocks. The decision is the mitm-agent's, so there is
# one rule engine; this only finds the traffic. Only a POST body that starts like JSON is parsed.
#
# Fail closed for tool calls: no answer from the admission service refuses the call. Everything else
# (initialize, notifications, pings, event streams) passes as it did.

MCP_ADMISSION_URL = os.environ.get("MITM_MCP_ADMISSION_URL", "http://127.0.0.1:8796").rstrip("/")
MCP_BODY_MAX = 1024 * 1024
MCP_ANSWER_MAX = 4 * 1024 * 1024
# A body larger than MCP_BODY_MAX is still parsed up to this, to tell a tool call (refused as too
# large) from any other large JSON, such as a JSON upload to an API. JSON larger still is refused as
# a tool call, since only a parse can tell (an escaped `tools\u002fcall` has no bytes to find).
MCP_PARSE_MAX = 32 * 1024 * 1024
# Headers a held call is not sent again with: the connection's own, and the proxy's.
_MCP_HEADERS_DROP = ("host", "content-length", "transfer-encoding", "connection", "keep-alive", "upgrade", "proxy-authorization", "proxy-connection", "te", "accept-encoding")


def _mcp_admission(path: str, payload: dict[str, Any], timeout: float = 30) -> dict[str, Any]:
    request = urllib.request.Request(MCP_ADMISSION_URL + path, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    # Never through an environment proxy: the admission service is on this box.
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=timeout) as response:
        return json.load(response)


# `tools/call` as a body can carry it in bytes: plain, with JSON's escaped slash, in UTF-16 or UTF-32.
_MCP_CALL_NEEDLES = tuple({n.encode(enc) for n in ("tools/call", "tools\\/call", "tools\\u002fcall", "tools\\u002Fcall")
                           for enc in ("utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")})
_BOMS = (b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")


# The keys a server reads a call by. Go's encoding/json (mcp-go, GitHub's MCP server) takes any
# case, and folds `ſ` to `s` and the Kelvin sign to `k`: `"Method": "tools/call"` is a call there.
_MCP_KEYS = ("jsonrpc", "method", "params", "name", "arguments", "id")


def _mcp_odd_keys(msgs: list[Any]) -> bool:
    """
    Whether a tool call (its method `tools/call` under a key of any case) has one of those keys, in
    it or in its params, written in another case. Other JSON (`{"Name": ...}` to an API) is not one.
    """
    def odd(d: Any) -> bool:
        return isinstance(d, dict) and any(isinstance(k, str) and k not in _MCP_KEYS and k.casefold() in _MCP_KEYS for k in d)

    def call(m: Any) -> bool:
        return isinstance(m, dict) and any(isinstance(k, str) and k.casefold() == "method" and v == "tools/call" for k, v in m.items())
    return any(call(m) and (odd(m) or any(isinstance(k, str) and k.casefold() == "params" and odd(v) for k, v in m.items())) for m in msgs)


def _mcp_mentions_call(raw: bytes) -> bool:
    return any(n in raw for n in _MCP_CALL_NEEDLES)


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _mcp_plain(raw: bytes) -> Any:
    """
    The body as plain UTF-8 JSON, the one reading every server shares; raises on anything else: a
    BOM, a bad byte, or `NaN`/`Infinity`, which Python's parser takes and JavaScript's does not.
    """
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("a BOM")
    return json.loads(raw.decode("utf-8"), parse_constant=_no_constant)


def _looks_wide_json(raw: bytes) -> bool:
    """JSON in UTF-16 or UTF-32: zero bytes round a `{` or `[` at the start."""
    head = raw[:8]
    return b"\x00" in head and head.replace(b"\x00", b"").lstrip()[:1] in (b"{", b"[")


def mcp_request_kind(flow: http.HTTPFlow) -> str | None:
    """`call` when a JSON body holds a `tools/call`; `list` or `other` for other JSON-RPC; None otherwise."""
    req = flow.request
    if req.method != "POST":
        return None
    try:
        raw = req.get_content(strict=False) or b""
    except Exception:
        return None
    # JSON, or JSON in UTF-16/32 (a zero byte next to the first character) or behind a BOM: servers
    # read all of them (Python's `json.loads(bytes)` does), so all are looked at.
    head = raw.lstrip()[:1]
    if head not in (b"{", b"[") and not raw.startswith(_BOMS) and not _looks_wide_json(raw):
        return None
    if len(raw) > MCP_PARSE_MAX:
        # Too large to parse: JSON this large is refused as a tool call, never sent unchecked (a byte
        # search for tools/call misses `tools\u002fcall` and the like). Model providers and the
        # firewall's own channels never get here (`mcp_request`), and below this size a body that only
        # quotes tools/call (a model request with it in its text) is parsed and passes.
        # The byte search cannot see an escaped `tools/call`: anything that starts like JSON counts.
        return "call"
    doc = None
    # As a server could read it: plain UTF-8, then bytes (BOM and UTF-16/32 detected), then UTF-8
    # with bad bytes replaced (the TypeScript SDK's way). Only the first is `cc_mcp_plain`: a tool
    # call read any other way is refused (`mcp_request`).
    for i, attempt in enumerate((lambda: _mcp_plain(raw), lambda: json.loads(raw), lambda: json.loads(raw.decode("utf-8", "replace").lstrip("\ufeff")))):
        try:
            doc = attempt()
            flow.metadata["cc_mcp_plain"] = i == 0
            break
        except (ValueError, RecursionError):
            continue
    else:
        # Not JSON to us; a server may still run it. A body that names a tool call is one (refused).
        flow.metadata["cc_mcp_plain"] = False
        return "call" if _mcp_mentions_call(raw) else None
    msgs = doc if isinstance(doc, list) else [doc]
    if _mcp_odd_keys(msgs):
        # Read one way here and another by a server that matches keys in any case: refused as a call.
        flow.metadata["cc_mcp_plain"] = False
        first = next((m for m in msgs if isinstance(m, dict) and isinstance(m.get("id"), (str, int)) and not isinstance(m.get("id"), bool)), None)
        if first is not None:
            flow.metadata["cc_mcp_id"] = first["id"]
        return "call"
    methods = [m.get("method") for m in msgs if isinstance(m, dict) and isinstance(m.get("method"), str)]
    if "tools/call" in methods:
        first = next(m for m in msgs if isinstance(m, dict) and m.get("method") == "tools/call")
        if isinstance(first.get("id"), (str, int)) and not isinstance(first.get("id"), bool):
            flow.metadata["cc_mcp_id"] = first["id"]
        return "call"
    if not methods or not any(isinstance(m, dict) and "jsonrpc" in m for m in msgs):
        return None
    return "list" if "tools/list" in methods else "other"


def mcp_host(flow: http.HTTPFlow) -> str | None:
    """
    The server as the integration rules name it: its host, and its port when it is not 443. Over TLS
    it is the name the client handshook with, which must be the `Host:` header's too: a header naming
    another server cannot move a call onto that server's rules. None when they differ.
    """
    host = (flow.request.pretty_host or "").lower().rstrip(".")
    sni = (getattr(flow.client_conn, "sni", None) or "").lower().rstrip(".")
    if sni and sni != host:
        return None
    port = flow.request.port
    return host if port in (443, None) else f"{host}:{port}"


def _mcp_answer(flow: http.HTTPFlow, status: int, content_type: str, body: str, rule: str) -> None:
    flow.response = http.Response.make(status, body.encode("utf-8"), {"Content-Type": content_type})
    flow.metadata["cc_effect"] = "block"
    flow.metadata["cc_rule"] = rule
    _log_once(flow, {**_http_record(flow, "block"), "status": status})


def _mcp_refuse_text(message: str, rpc_id: str | int | None = None) -> str:
    # The call's own id when it is known, so the client pairs the refusal with the call it waits on.
    return json.dumps({"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32001, "message": message}})


async def mcp_request(flow: http.HTTPFlow, vm_id: str | None) -> str | None:
    """None: not MCP. "answered": refused or held here, with the answer already set. Else the kind."""
    # Model providers, the control plane and the channels the firewall reads its own way are never MCP
    # servers: their requests are not parsed for tool calls.
    if _own_channel_flow(flow, vm_id):
        return None
    kind = mcp_request_kind(flow)
    if kind is None:
        return None
    flow.metadata["cc_mcp"] = kind
    flow.metadata["cc_mcp_vm"] = vm_id
    if kind != "call":
        return kind
    host = mcp_host(flow)
    if not vm_id or not host:
        # A tool call from a box this proxy cannot name, or one whose Host header is not the server it
        # connected to, cannot be checked: refused.
        _mcp_answer(flow, 403, "application/json", _mcp_refuse_text("The firewall could not tell which agent or which server this tool call is for, so it did not send it.", flow.metadata.get("cc_mcp_id")), "integrations: unknown")
        return "answered"
    body = flow.request.get_content(strict=False) or b""
    if len(body) > MCP_BODY_MAX:
        _mcp_answer(flow, 413, "application/json", _mcp_refuse_text("That tool call is too large for the firewall to check.", flow.metadata.get("cc_mcp_id")), "integrations: too large")
        return "answered"
    if not flow.metadata.get("cc_mcp_plain"):
        # A BOM, UTF-16/32, a bad byte, NaN, or not JSON to us: the check would read it one way and the server another.
        _mcp_answer(flow, 400, "application/json", _mcp_refuse_text("The firewall could not read this tool call, so it did not send it. Send it as plain UTF-8 JSON.", flow.metadata.get("cc_mcp_id")), "integrations: unreadable")
        return "answered"
    headers = {k.lower(): v for k, v in flow.request.headers.items() if k.lower() not in _MCP_HEADERS_DROP}
    try:
        verdict = await asyncio.to_thread(_mcp_admission, "/call", {
            "vm_id": vm_id, "host": host, "url": f"{flow.request.scheme}://{host}{flow.request.path}",
            "headers": headers, "body": body.decode("utf-8", "replace")})
    except Exception as exc:  # fail closed: a tool call nobody could check does not go out
        log.warning(f"[mcp] admission failed, refusing the tool call: {exc!r}")
        _mcp_answer(flow, 503, "application/json", _mcp_refuse_text("The firewall could not check this tool call, so it did not send it. Try again in a minute.", flow.metadata.get("cc_mcp_id")), "integrations: check failed")
        return "answered"
    action = verdict.get("action")
    if action == "answer":
        hold_ref = verdict.get("hold_ref")
        if hold_ref:
            # Held for Send: the call goes out later from the firewall, with the headers this proxy would
            # have sent, credentials swapped in. This flow is answered here and never sent on, so the
            # swap is done on it to read them.
            try:
                apply_swaps(flow, vm_id)
                swapped = {k.lower(): v for k, v in flow.request.headers.items() if k.lower() not in _MCP_HEADERS_DROP}
                await asyncio.to_thread(_mcp_admission, "/held", {"hold_ref": hold_ref, "headers": swapped}, 5)
            except Exception as exc:
                log.warning(f"[mcp] could not keep a held call's headers: {exc!r}")
        _mcp_answer(flow, int(verdict.get("status") or 200), str(verdict.get("content_type") or "application/json"), str(verdict.get("body") or ""), "integrations")
        return "answered"
    if action == "allow":
        flow.metadata["cc_mcp_ticket"] = verdict.get("ticket")
        flow.metadata["cc_mcp_read"] = bool(verdict.get("read_result"))
        # Its arguments were read under the Integrations channel: the website check is not run again.
        flow.metadata["cc_mcp_checked"] = True
    return kind


def _mcp_try_done(ticket: str) -> None:
    try:
        _mcp_admission("/done", {"ticket": ticket, "status": 0, "ok": False, "error": "server_unreachable"}, timeout=5)
    except Exception:
        pass


def mcp_response(flow: http.HTTPFlow) -> None:
    """A `tools/list` answer to the catalog (and rewritten), a tool call's result to its checks."""
    kind = flow.metadata.get("cc_mcp")
    ticket = flow.metadata.get("cc_mcp_ticket")
    vm_id = flow.metadata.get("cc_mcp_vm")
    if not flow.response or (kind != "list" and not ticket):
        return
    ctype = flow.response.headers.get("content-type") or ""
    status = flow.response.status_code
    try:
        body = flow.response.get_content(strict=False) or b""
    except Exception:
        body = None

    def work() -> None:
        try:
            if kind == "list":
                host = mcp_host(flow)
                if body is None or len(body) > MCP_ANSWER_MAX or not vm_id or not host:
                    return
                r = _mcp_admission("/tools", {"vm_id": vm_id, "host": host, "content_type": ctype, "body": body.decode("utf-8", "replace")})
                if r.get("action") == "replace":
                    flow.response.set_content(str(r.get("body") or "").encode("utf-8"))
                return
            if not flow.metadata.get("cc_mcp_read"):
                _mcp_admission("/done", {"ticket": ticket, "status": status, "ok": status < 400}, timeout=5)
                return
            if body is None or len(body) > MCP_ANSWER_MAX:
                # A result too large to check does not reach the agent while a rule covers results.
                r = _mcp_admission("/result", {"ticket": ticket, "status": status, "content_type": ctype, "body": "", "too_large": True})
            else:
                r = _mcp_admission("/result", {"ticket": ticket, "status": status, "content_type": ctype, "body": body.decode("utf-8", "replace")})
            if r.get("action") == "replace":
                flow.response.set_content(str(r.get("body") or "").encode("utf-8"))
        except Exception as exc:
            log.warning(f"[mcp] answer check failed: {exc!r}")
            if ticket and flow.metadata.get("cc_mcp_read"):
                # Fail closed: a result that was to be checked and could not be does not reach the agent.
                flow.response.set_content(_mcp_refuse_text("The firewall could not check this result, so it kept it from you.").encode("utf-8"))
                flow.response.headers["content-type"] = "application/json"

    if not _off_loop(flow, work):
        work()


def response(flow: http.HTTPFlow) -> None:
    mcp_response(flow)
    telegram_taps_response(flow)
    content_rules_telegram_in(flow)
    content_rules_gmail_in(flow)
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
    try:
        learn_login_targets(flow)
    except Exception as exc:  # a page that breaks the reader teaches nothing, and costs nothing else
        log.warning("[mitm] reading a sign-in page failed: %s", type(exc).__name__)
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
    model_error = classify_model_error(flow, flow.metadata.get("cc_vm_id"))
    if model_error:
        rec_extra["model_error"] = model_error
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
    ticket = flow.metadata.get("cc_mcp_ticket")
    if ticket:
        # The tool call's row ends here: it never got an answer.
        threading.Thread(target=lambda: _mcp_try_done(ticket), daemon=True).start()
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
