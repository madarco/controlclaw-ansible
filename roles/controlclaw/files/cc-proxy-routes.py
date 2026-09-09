#!/usr/bin/env python3
"""Rebuild the HAProxy route map from Hetzner server labels.

Every agent box is created with labels cc-role=agent and cc-host=<slug>. This script lists
them with a READ-ONLY token, writes "<slug><suffix> <public ipv4>" lines to the map, and
reloads HAProxy only when the map changed. Stdlib only; runs from cc-proxy-routes.timer.
"""
import json
import os
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


def list_agents(token: str) -> list[dict]:
    servers: list[dict] = []
    page = 1
    while True:
        query = urllib.parse.urlencode({"label_selector": "cc-role==agent", "per_page": 50, "page": page})
        req = urllib.request.Request(f"{API}?{query}", headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=15) as res:
            body = json.load(res)
        servers.extend(body.get("servers", []))
        next_page = (body.get("meta") or {}).get("pagination", {}).get("next_page")
        if not next_page:
            return servers
        page = next_page


def build_map(servers: list[dict], suffix: str) -> str:
    routes: dict[str, tuple[str, str]] = {}  # host -> (created, ip)
    for server in servers:
        host = (server.get("labels") or {}).get("cc-host", "").strip().lower()
        ip = ((server.get("public_net") or {}).get("ipv4") or {}).get("ip")
        if not host or not ip:
            continue
        created = server.get("created", "")
        fqdn = f"{host}{suffix}"
        previous = routes.get(fqdn)
        if previous and previous[0] >= created:
            print(f"cc-proxy-routes: duplicate host {fqdn}: keeping newest ({previous[1]}), ignoring {ip}")
            continue
        if previous:
            print(f"cc-proxy-routes: duplicate host {fqdn}: replacing {previous[1]} with newer {ip}")
        routes[fqdn] = (created, ip)
    lines = [f"{fqdn} {ip}" for fqdn, (_, ip) in sorted(routes.items())]
    return "\n".join(lines) + ("\n" if lines else "")


def main() -> None:
    suffix = env("CC_DOMAIN_SUFFIX")
    token_file = env("CC_TOKEN_FILE")
    map_path = env("CC_ROUTES_MAP")
    with open(token_file, encoding="utf-8") as fh:
        token = fh.read().strip()

    content = build_map(list_agents(token), suffix)
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
