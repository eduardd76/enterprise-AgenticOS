"""NetBox as source of truth: load_inventory against a local fake of the NetBox REST API, and
(opt-in, AOS_NETBOX=1) against the live lab NetBox seeded by labs/evpn-ceos/netbox/seed.py."""

import copy
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from agenticos.sot.netbox import NetBox, NetBoxError, load_inventory

INV = os.path.join(os.path.dirname(__file__), "..", "labs", "evpn-ceos", "inventory.json")
TOKEN = "0123456789abcdef0123456789abcdef01234567"
V2_TOKEN = "nbt_abc123.secretpart"
PAGE = 2                                    # tiny pages so every list exercises `next`


def expected():
    inv = json.load(open(INV))
    inv.pop("_comment", None)
    return inv


def strip_intent(inv):
    inv = copy.deepcopy(inv)
    for d in inv["devices"].values():
        d.pop("intended_vlans", None)
    return inv


def netbox_data():
    """NetBox objects (API shapes) for the EVPN lab, as seed.py would create them."""
    site = {"id": 1, "name": "evpn-dc", "slug": "evpn-dc"}
    tenant = {"id": 1, "name": "customer-a", "slug": "customer-a"}
    vlans = [{"id": 10, "vid": 10, "name": "tenant-a", "custom_fields": {"vni": 10010}},
             {"id": 20, "vid": 20, "name": "tenant-b", "custom_fields": {"vni": None}}]
    devs = {"spine1": ("spine", 65000), "leaf1": ("leaf", 65001), "leaf2": ("leaf", 65002),
            "host1": ("server", None), "host2": ("server", None)}
    devices = []
    for i, (name, (role, asn)) in enumerate(devs.items(), 1):
        devices.append({"id": i, "name": name, "site": site, "tenant": tenant,
                        "role": {"slug": role, "name": role}, "primary_ip4": None,
                        "custom_fields": {"asn": asn, "container": None}})
    by = {d["name"]: d for d in devices}
    ifaces, n = [], 0

    def iface(dev, name, **kw):
        nonlocal n
        n += 1
        ifaces.append({"id": n, "name": name, "device": {"id": by[dev]["id"], "name": dev},
                       "link_peers": [], "connected_endpoints": None, "mode": None,
                       "untagged_vlan": None, **kw})
        return ifaces[-1]

    for sw in ("spine1", "leaf1", "leaf2"):
        for e in ("Ethernet1", "Ethernet2", "Ethernet3", "Loopback0"):
            iface(sw, e)
    for h in ("host1", "host2"):
        iface(h, "eth1")
    find = lambda d, i: next(x for x in ifaces if x["device"]["name"] == d and x["name"] == i)
    for a, b in [(("spine1", "Ethernet1"), ("leaf1", "Ethernet1")),
                 (("spine1", "Ethernet2"), ("leaf2", "Ethernet1")),
                 (("leaf1", "Ethernet3"), ("host1", "eth1")),
                 (("leaf2", "Ethernet3"), ("host2", "eth1"))]:
        x, y = find(*a), find(*b)
        x["link_peers"] = [{"id": y["id"], "name": y["name"], "device": y["device"]}]
        y["link_peers"] = [{"id": x["id"], "name": x["name"], "device": x["device"]}]
    for leaf in ("leaf1", "leaf2"):
        p = find(leaf, "Ethernet3")
        p["mode"] = {"value": "access", "label": "Access"}
        p["untagged_vlan"] = {"id": 10, "vid": 10, "name": "tenant-a"}
    ips = []
    for dev, ifn, addr in [("spine1", "Loopback0", "10.255.0.1/32"),
                           ("leaf1", "Loopback0", "10.255.0.11/32"),
                           ("leaf2", "Loopback0", "10.255.0.12/32"),
                           ("spine1", "Ethernet1", "10.0.1.0/31"),
                           ("leaf1", "Ethernet1", "10.0.1.1/31"),
                           ("host1", "eth1", "10.10.10.11/24"),
                           ("host2", "eth1", "10.10.10.12/24")]:
        i = find(dev, ifn)
        ips.append({"id": len(ips) + 1, "address": addr,
                    "assigned_object_type": "dcim.interface",
                    "assigned_object": {"id": i["id"], "name": ifn, "device": i["device"]}})
        if dev.startswith("host"):
            by[dev]["primary_ip4"] = {"id": ips[-1]["id"], "address": addr}
    return {"dcim/sites": [site], "dcim/devices": devices, "ipam/vlans": vlans,
            "dcim/interfaces": ifaces, "ipam/ip-addresses": ips}


def _match(obj, key, values):
    if key == "site_id":
        return str(obj.get("site", {}).get("id", 1)) in values
    if key == "device_id":
        dev = obj.get("device") or (obj.get("assigned_object") or {}).get("device") or {}
        return str(dev.get("id")) in values
    return str(obj.get(key)) in values


class FakeNetBox:
    def __init__(self, data=None):
        self.data, self.calls = data or netbox_data(), []
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                u = urlparse(self.path)
                fake.calls.append((u.path, self.headers.get("Authorization")))
                if self.headers.get("Authorization") not in (f"Token {TOKEN}",
                                                             f"Bearer {V2_TOKEN}"):
                    return self._send(403, {"detail": "Invalid v1 token"})
                path = u.path.removeprefix("/api/").strip("/")
                if path not in fake.data:
                    return self._send(404, {"detail": "Not found."})
                q = parse_qs(u.query)
                offset, limit = int(q.pop("offset", ["0"])[0]), PAGE
                q.pop("limit", None)
                rows = [o for o in fake.data[path] if all(_match(o, k, v) for k, v in q.items())]
                nxt = None
                if offset + limit < len(rows):
                    # NetBox builds `next` from its own idea of the host (here: a wrong one).
                    nxt = f"http://netbox.internal{u.path}?limit={limit}&offset={offset + limit}"
                    nxt += "".join(f"&{k}={x}" for k, vs in q.items() for x in vs)
                self._send(200, {"count": len(rows), "next": nxt, "previous": None,
                                 "results": rows[offset:offset + limit]})

        self.server = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"


@pytest.fixture
def fake():
    f = FakeNetBox()
    yield f
    f.server.shutdown()


def test_netbox_inventory_matches_inventory_json(fake):
    inv = load_inventory(NetBox(fake.url, TOKEN), "evpn-dc")
    assert strip_intent(inv) == expected()
    assert inv["devices"]["leaf1"]["intended_vlans"] == {"Ethernet3": 10}
    assert inv["devices"]["leaf2"]["intended_vlans"] == {"Ethernet3": 10}
    assert "intended_vlans" not in inv["devices"]["spine1"]
    assert fake.calls and all(a == f"Token {TOKEN}" for _, a in fake.calls)


def test_inventory_drives_eoslab(fake, tmp_path):
    from agenticos.drivers.eos import EosLab
    p = tmp_path / "inv.json"
    p.write_text(json.dumps(load_inventory(NetBox(fake.url, TOKEN), "evpn-dc")))
    lab = EosLab(p)
    assert lab.commands("leaf2", {"interface": "Ethernet3", "access_vlan": 10}) == \
        ["interface Ethernet3", "switchport access vlan 10"]
    assert lab.tenant_of("host2") == "customer-a"


def test_v2_token_uses_bearer(fake):
    nb = NetBox(fake.url, V2_TOKEN)
    assert nb.auth == f"Bearer {V2_TOKEN}"
    assert strip_intent(load_inventory(nb, "evpn-dc")) == expected()


def test_bad_token_is_a_clear_error(fake):
    with pytest.raises(NetBoxError, match="rejected the API token"):
        load_inventory(NetBox(fake.url, "wrong"), "evpn-dc")


def test_requires_https_off_localhost():
    with pytest.raises(NetBoxError, match="https"):
        NetBox("http://netbox.example.com", TOKEN)
    with pytest.raises(NetBoxError, match="token"):
        NetBox("https://netbox.example.com", "")
    NetBox("https://netbox.example.com", TOKEN)
    NetBox("http://localhost:8000", TOKEN)


def _broken(mutate):
    data = netbox_data()
    mutate(data)
    return FakeNetBox(data)


def _iface(data, dev, name):
    return next(i for i in data["dcim/interfaces"]
                if i["device"]["name"] == dev and i["name"] == name)


@pytest.mark.parametrize("mutate,msg", [
    (lambda d: d["dcim/devices"].pop(0), "no device with role 'spine'"),
    (lambda d: _iface(d, "leaf2", "Ethernet3").update(untagged_vlan=None),
     "leaf2 Ethernet3 .*untagged VLAN"),
    (lambda d: _iface(d, "leaf1", "Ethernet3").update(mode=None), "mode=access"),
    (lambda d: d["dcim/devices"][1]["custom_fields"].update(asn=None), "leaf1: custom field 'asn'"),
    (lambda d: d["ipam/vlans"][0]["custom_fields"].update(vni=None), "custom field 'vni'"),
    (lambda d: d["ipam/vlans"].pop(0), "no VLAN named 'tenant-a'"),
    (lambda d: d["ipam/ip-addresses"].pop(1), "leaf1: no IP address on Loopback0"),
    (lambda d: d["dcim/devices"][3].update(tenant=None), "host1: no tenant"),
    (lambda d: d["dcim/devices"].pop(4), "need two devices with role 'server'"),
])
def test_missing_pieces_raise(mutate, msg):
    f = _broken(mutate)
    try:
        with pytest.raises(NetBoxError, match=msg):
            load_inventory(NetBox(f.url, TOKEN), "evpn-dc")
    finally:
        f.server.shutdown()


def test_unknown_site(fake):
    with pytest.raises(NetBoxError, match="site 'nope' not found"):
        load_inventory(NetBox(fake.url, TOKEN), "nope")


@pytest.mark.skipif(os.environ.get("AOS_NETBOX") != "1",
                    reason="live NetBox: set AOS_NETBOX=1 (labs/evpn-ceos/netbox/netbox.sh up)")
def test_live_netbox_matches_inventory_json():
    nb = NetBox(os.environ.get("NETBOX_URL", "http://127.0.0.1:8000"),
                os.environ["NETBOX_TOKEN"])
    inv = load_inventory(nb, "evpn-dc")
    assert strip_intent(inv) == expected()
    for leaf in ("leaf1", "leaf2"):
        assert inv["devices"][leaf]["intended_vlans"] == {"Ethernet3": 10}
