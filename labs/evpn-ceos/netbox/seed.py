#!/usr/bin/env python3
"""Populate the lab NetBox with the EVPN fabric (idempotent: re-running converges, never
duplicates). Inputs are the lab's own files, so NetBox ends up describing exactly what
containerlab deploys:
    inventory.json        roles, tenant, ASNs, loopbacks, VLANs, VNI, host IPs
    topology.clab.yml     cables (clab ethN on cEOS = EthernetN) and host addresses
    configs/*.cfg         point-to-point /31s (and loopbacks, cross-checked)

Env: NETBOX_URL (default http://127.0.0.1:8000), NETBOX_TOKEN. Stdlib only.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LAB.parent.parent))
from agenticos.sot.netbox import NetBox, NetBoxError  # noqa: E402

SITE, TENANT = "evpn-dc", "customer-a"
SWITCH_PORTS = ["Ethernet1", "Ethernet2", "Ethernet3"]
ROLES = {"spine": "2196f3", "leaf": "4caf50", "server": "9e9e9e"}
CUSTOM_FIELDS = [  # name, type, object types, description
    ("asn", "integer", ["dcim.device"], "BGP AS number of the switch"),
    ("container", "text", ["dcim.device"], "containerlab container (default clab-evpn-dc-<name>)"),
    ("vni", "integer", ["ipam.vlan"], "VXLAN VNI the VLAN is stretched over"),
]


class Seeder:
    def __init__(self, nb: NetBox):
        self.nb, self.created, self.updated = nb, 0, 0

    def ensure(self, path: str, lookup: dict, body: dict) -> dict:
        """Get-or-create by `lookup`; existing objects are patched to `body` if they differ."""
        found = self.nb._get(path, **lookup)
        if len(found) > 1:
            raise NetBoxError(f"{path} {lookup}: {len(found)} matches, expected one")
        if not found:
            self.created += 1
            return self.nb._send("POST", path, body)
        obj = found[0]
        if any(_differs(obj.get(k), v) for k, v in body.items()):
            self.updated += 1
            return self.nb._send("PATCH", f"{path}/{obj['id']}", body)
        return obj


def _differs(have, want) -> bool:
    if isinstance(want, dict):
        return not isinstance(have, dict) or any(_differs(have.get(k), v) for k, v in want.items())
    if isinstance(want, list):
        return sorted(map(str, have or [])) != sorted(map(str, want))
    if isinstance(have, dict):                       # nested object vs id / value / slug
        return want not in (have.get("id"), have.get("value"), have.get("slug"))
    return have != want


def config_ips() -> dict[tuple[str, str], str]:
    out = {}
    for cfg in sorted((LAB / "configs").glob("*.cfg")):
        iface = None
        for line in cfg.read_text().splitlines():
            if line.startswith("interface "):
                iface = line.split()[1]
            elif not line.startswith(" "):
                iface = None
            elif iface and line.strip().startswith("ip address "):
                out[(cfg.stem, iface)] = line.split()[2]
    return out


def topology():
    text = (LAB / "topology.clab.yml").read_text()
    links = re.findall(r'endpoints:\s*\["(\w+):(\w+)",\s*"(\w+):(\w+)"\]', text)
    host_ips = {}
    for node, body in re.findall(r"^    (\w+):\n((?:      .*\n)+)", text, re.M):
        for addr, dev in re.findall(r"ip addr add (\S+) dev (\w+)", body):
            host_ips[node] = (dev, addr)
    return links, host_ips


def seed(nb: NetBox) -> Seeder:
    inv = json.loads((LAB / "inventory.json").read_text())
    links, host_ips = topology()
    s = Seeder(nb)

    for name, typ, objs, desc in CUSTOM_FIELDS:
        s.ensure("extras/custom-fields", {"name": name},
                 {"name": name, "label": name.upper() if name != "container" else "Container",
                  "type": typ, "object_types": objs, "description": desc, "required": False})
    tenant = s.ensure("tenancy/tenants", {"slug": TENANT}, {"name": TENANT, "slug": TENANT})
    site = s.ensure("dcim/sites", {"slug": SITE},
                    {"name": SITE, "slug": SITE, "status": "active", "tenant": tenant["id"]})
    roles = {r: s.ensure("dcim/device-roles", {"slug": r},
                         {"name": r, "slug": r, "color": c})["id"] for r, c in ROLES.items()}
    arista = s.ensure("dcim/manufacturers", {"slug": "arista"}, {"name": "Arista", "slug": "arista"})
    linux = s.ensure("dcim/manufacturers", {"slug": "linux"}, {"name": "Linux", "slug": "linux"})
    ceos = s.ensure("dcim/device-types", {"slug": "ceos-lab"},
                    {"manufacturer": arista["id"], "model": "cEOS-lab", "slug": "ceos-lab"})
    server = s.ensure("dcim/device-types", {"slug": "linux-server"},
                      {"manufacturer": linux["id"], "model": "Linux server", "slug": "linux-server"})

    svc = inv["service"]
    vlans = {}
    for vid, vname in inv["vlans"].items():
        vid = int(vid)
        body = {"vid": vid, "name": vname, "site": site["id"], "tenant": tenant["id"],
                "status": "active"}
        if vid == svc["vlan"]:
            body["custom_fields"] = {"vni": svc["vni"]}
        vlans[vid] = s.ensure("ipam/vlans", {"site_id": site["id"], "vid": vid}, body)["id"]

    devices = {}
    for name, d in inv["devices"].items():
        devices[name] = s.ensure("dcim/devices", {"site_id": site["id"], "name": name}, {
            "name": name, "role": roles[d["role"]], "device_type": ceos["id"],
            "site": site["id"], "tenant": tenant["id"], "status": "active",
            "custom_fields": {"asn": d["asn"]}})
    for name in inv["hosts"]:
        devices[name] = s.ensure("dcim/devices", {"site_id": site["id"], "name": name}, {
            "name": name, "role": roles["server"], "device_type": server["id"],
            "site": site["id"], "tenant": tenant["id"], "status": "active"})

    ifaces = {}
    for name, d in inv["devices"].items():
        for port in SWITCH_PORTS:
            body = {"device": devices[name]["id"], "name": port, "type": "1000base-t"}
            if port in d.get("host_ports", {}):
                body.update(mode="access", untagged_vlan=vlans[svc["vlan"]])
            ifaces[(name, port)] = s.ensure(
                "dcim/interfaces", {"device_id": devices[name]["id"], "name": port}, body)
        ifaces[(name, "Loopback0")] = s.ensure(
            "dcim/interfaces", {"device_id": devices[name]["id"], "name": "Loopback0"},
            {"device": devices[name]["id"], "name": "Loopback0", "type": "virtual"})
    for name, (dev, _) in host_ips.items():
        ifaces[(name, dev)] = s.ensure(
            "dcim/interfaces", {"device_id": devices[name]["id"], "name": dev},
            {"device": devices[name]["id"], "name": dev, "type": "1000base-t"})

    def port(node, ifn):                       # clab name -> NetBox interface name
        return f"Ethernet{ifn[3:]}" if node in inv["devices"] else ifn

    for a_node, a_if, b_node, b_if in links:
        a, b = ifaces[(a_node, port(a_node, a_if))], ifaces[(b_node, port(b_node, b_if))]
        if nb._get("dcim/interfaces", id=a["id"])[0].get("cable"):
            continue                           # cabled already (idempotent re-run)
        s.created += 1
        nb._send("POST", "dcim/cables", {
            "a_terminations": [{"object_type": "dcim.interface", "object_id": a["id"]}],
            "b_terminations": [{"object_type": "dcim.interface", "object_id": b["id"]}],
            "status": "connected"})

    addrs = config_ips()
    for name, d in inv["devices"].items():
        lo = addrs.get((name, "Loopback0"), "").split("/")[0]
        if lo != d["loopback"]:
            raise NetBoxError(f"{name}: Loopback0 {lo!r} in config != {d['loopback']} in inventory")
    for name, (dev, addr) in host_ips.items():
        addrs[(name, dev)] = addr
    for (name, ifn), addr in sorted(addrs.items()):
        i = ifaces[(name, ifn)]
        ip = s.ensure("ipam/ip-addresses", {"address": addr, "interface_id": i["id"]}, {
            "address": addr, "status": "active", "tenant": tenant["id"],
            "assigned_object_type": "dcim.interface", "assigned_object_id": i["id"]})
        if name in inv["hosts"]:
            if inv["hosts"][name]["ip"] != addr.split("/")[0]:
                raise NetBoxError(f"{name}: topology IP {addr} != inventory "
                                  f"{inv['hosts'][name]['ip']}")
            s.ensure("dcim/devices", {"site_id": site["id"], "name": name},
                     {"primary_ip4": ip["id"]})
    return s


def main() -> int:
    nb = NetBox(os.environ.get("NETBOX_URL", "http://127.0.0.1:8000"),
                os.environ.get("NETBOX_TOKEN", ""))
    try:
        s = seed(nb)
    except NetBoxError as e:
        print(f"seed failed: {e}", file=sys.stderr)
        return 1
    print(f"seeded NetBox site {SITE}: {s.created} created, {s.updated} updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
