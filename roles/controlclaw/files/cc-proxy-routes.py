#!/usr/bin/env python3
"""Rebuild the HAProxy route map from Hetzner server labels.

Agent boxes are created with cc-role=agent and cc-host=<slug>. FIREWALL boxes carry
cc-role=mitm and a cc-host of their own, because inbound webhooks arrive at the firewall and
need the same blind SNI route an agent gets (controlclaw docs/plans/webhooks.md). BRAIN boxes
(cc-role=gbrain) carry one too, so the control plane can reach the brain's vm-agent (controlclaw
docs/plans/gbrain.md §9). All three are listed here with a READ-ONLY token; this script writes
"<slug>.<domain> <public ipv4>" lines to
the map and reloads HAProxy only when the map changed. Stdlib only; runs from
cc-proxy-routes.timer.

Which domain (controlclaw T-105). A box names its own with cc-domain=<suffix> (e.g. ccl.bot), and
a box without the label is <slug> under CC_DOMAIN_SUFFIX — every box created before cc-domain
existed. A cc-domain is honoured only if it is in CC_DOMAIN_SUFFIXES (comma-separated; the
default suffix is always allowed), so a label cannot route a domain this proxy was not told about.
Who may reach a suffix (a source allow-list, T-104) is HAProxy's rule, not the map's: this script
only says where a name goes.

The proxy stays blind either way: it forwards ciphertext by server name and holds no
certificate. What a firewall box serves on the far side of that route is one path prefix
(Caddyfile-mitm.j2), not the agent console.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

API = "https://api.hetzner.cloud/v1/servers"


def env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None or value == "":
        sys.exit(f"cc-proxy-routes: {name} is not set")
    return value


def list_boxes(token: str) -> list[dict]:
    servers: list[dict] = []
    page = 1
    while True:
        query = urllib.parse.urlencode({"label_selector": "cc-role in (agent,mitm,gbrain)", "per_page": 50, "page": page})
        req = urllib.request.Request(f"{API}?{query}", headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=15) as res:
            body = json.load(res)
        servers.extend(body.get("servers", []))
        next_page = (body.get("meta") or {}).get("pagination", {}).get("next_page")
        if not next_page:
            return servers
        page = next_page


# One DNS label: a handle is never a dotted name, so cc-host cannot smuggle a domain in.
HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


def normalize_domain(value: str) -> str:
    """".vm.controlclaw.com" and "CCL.BOT" are "vm.controlclaw.com" and "ccl.bot"."""
    return value.strip().lower().strip(".")


def allowed_domains(default: str, listed: str) -> set[str]:
    """The default suffix plus every valid entry of CC_DOMAIN_SUFFIXES."""
    domains = {default}
    for entry in listed.split(","):
        name = normalize_domain(entry)
        if not name:
            continue
        if not DOMAIN_RE.match(name):
            print(f"cc-proxy-routes: ignoring allowed suffix {name!r}: not a domain")
            continue
        domains.add(name)
    return domains


def build_map(servers: list[dict], suffix: str, allowed: set[str] | None = None) -> str:
    default = normalize_domain(suffix)
    allowed = allowed if allowed is not None else {default}
    routes: dict[str, tuple[str, str]] = {}  # host -> (created, ip)
    for server in servers:
        labels = server.get("labels") or {}
        host = labels.get("cc-host", "").strip().lower()
        ip = ((server.get("public_net") or {}).get("ipv4") or {}).get("ip")
        if not host or not ip:
            continue
        if not HOST_RE.match(host):
            print(f"cc-proxy-routes: ignoring {server.get('name')!r}: cc-host {host!r} is not a hostname label")
            continue
        domain = normalize_domain(labels.get("cc-domain", "")) or default
        if domain not in allowed:
            print(f"cc-proxy-routes: ignoring {host}: cc-domain {domain!r} is not an allowed suffix")
            continue
        created = server.get("created", "")
        hosts = [host]
        alias = labels.get("cc-host-alias", "")
        if alias and HOST_RE.fullmatch(alias):
            hosts.append(alias)
        for name in hosts:
            fqdn = f"{name}.{domain}"
            previous = routes.get(fqdn)
            if previous and previous[0] >= created:
                continue
            routes[fqdn] = (created, ip)
    lines = [f"{fqdn} {ip}" for fqdn, (_, ip) in sorted(routes.items())]
    return "\n".join(lines) + ("\n" if lines else "")


def main() -> None:
    suffix = env("CC_DOMAIN_SUFFIX")
    allowed = allowed_domains(normalize_domain(suffix), os.environ.get("CC_DOMAIN_SUFFIXES", ""))
    token_file = env("CC_TOKEN_FILE")
    map_path = env("CC_ROUTES_MAP")
    with open(token_file, encoding="utf-8") as fh:
        token = fh.read().strip()

    content = build_map(list_boxes(token), suffix, allowed)
    try:
        with open(map_path, encoding="utf-8") as fh:
            current = fh.read()
    except FileNotFoundError:
        current = None
    if content == current:
        print(f"cc-proxy-routes: unchanged ({content.count(chr(10))} routes)")
        return

    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(map_path), prefix=".routes.")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(tmp, 0o644)
    os.replace(tmp, map_path)
    subprocess.run(["systemctl", "reload", "haproxy"], check=True)
    print(f"cc-proxy-routes: updated ({content.count(chr(10))} routes), haproxy reloaded")


if __name__ == "__main__":
    main()
