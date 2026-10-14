"""NetBox as the source of truth for the EVPN lab.

load_inventory() reads one site from NetBox and returns exactly the inventory schema that
EosLab consumes (labs/evpn-ceos/inventory.json), plus `intended_vlans` per leaf: the access
VLAN NetBox says each host port *should* carry. That intent is what the AI's fixes are
checked against — the fabric's live state is evidence, NetBox is the plan.

Data model (what has to exist in NetBox; labs/evpn-ceos/netbox/seed.py creates it):
    devices      at the site, role slug spine | leaf | server, tenant set (slug is used)
    asn          device custom field `asn` (integer). Chosen over config context: it is
                 typed, shows in the UI/filters, and needs no context-weighting rules.
    container    optional device custom field `container`; default = prefix + device name
    loopback     IP address assigned to the switch's Loopback0 interface
    links        cables between interfaces (link_peers; connected_endpoints as a fallback)
    uplinks      leaf interfaces cabled to a spine; host_ports = leaf interfaces cabled to
                 a server, which must be mode=access with an untagged VLAN
    host ip      the server's primary_ip4, else the IP on its leaf-facing interface
    vlans        the site's VLANs (vid -> name); the service VLAN is found by name and its
                 VNI comes from VLAN custom field `vni` (integer). Chosen over L2VPN
                 objects: one field, no extra termination objects for a two-leaf lab.
    probe        from the first server to the second, ordered by name

The client is read-only, stdlib only, and refuses plain http except to localhost.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
PAGE_SIZE = 250


class NetBoxError(RuntimeError):
    pass


class NetBox:
    def __init__(self, url: str, token: str, timeout: float = 10):
        u = urllib.parse.urlsplit(url or "")
        if u.scheme not in ("http", "https") or not u.hostname:
            raise NetBoxError(f"bad NetBox URL {url!r}")
        if u.scheme == "http" and u.hostname not in LOCAL_HOSTS:
            raise NetBoxError("NetBox URL must be https (plain http only to localhost) — "
                              "the API token travels in every request")
        if not token:
            raise NetBoxError("NetBox API token required (NETBOX_TOKEN)")
        self.base = f"{u.scheme}://{u.netloc}{u.path.rstrip('/')}"
        self.origin = f"{u.scheme}://{u.netloc}"
        # NetBox >= 4.5 v2 tokens ("nbt_<key>.<secret>") use Bearer; v1 tokens use "Token".
        self.auth = f"Bearer {token}" if token.startswith("nbt_") else f"Token {token}"
        self.timeout = timeout

    def _request(self, method: str, url: str, body=None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data, method=method, headers={
            "Authorization": self.auth, "Accept": "application/json",
            "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            detail = e.read()[:300].decode(errors="replace")
            if e.code in (401, 403):
                raise NetBoxError(f"NetBox rejected the API token (HTTP {e.code}): "
                                  f"{detail}") from e
            raise NetBoxError(f"NetBox {method} {url}: HTTP {e.code}: {detail}") from e
        except (urllib.error.URLError, OSError) as e:
            raise NetBoxError(f"NetBox unreachable at {self.base}: {e}") from e
        try:
            return json.loads(raw) if raw else {}
        except json.JSONDecodeError as e:
            raise NetBoxError(f"NetBox {method} {url}: response is not JSON") from e

    def _url(self, path: str, query: dict | None = None) -> str:
        url = f"{self.base}/api/{path.strip('/')}/"
        return url + ("?" + urllib.parse.urlencode(query, doseq=True) if query else "")

    def _get(self, path: str, **query) -> list[dict]:
        """All results of a list endpoint, following `next` links (pagination)."""
        url, out = self._url(path, {"limit": PAGE_SIZE, **query}), []
        while url:
            page = self._request("GET", url)
            if not isinstance(page, dict) or "results" not in page:
                raise NetBoxError(f"NetBox {path}: expected a paginated list")
            out.extend(page["results"])
            nxt = page.get("next")
            # `next` is absolute and built from the server's view of its own host (proxies
            # get this wrong); keep our origin so the token is never sent anywhere else.
            url = None
            if nxt:
                n = urllib.parse.urlsplit(nxt)
                url = f"{self.origin}{n.path}" + (f"?{n.query}" if n.query else "")
        return out

    def _send(self, method: str, path: str, body=None) -> dict:
        """Writes, used by the lab seeder only (load_inventory never writes)."""
        return self._request(method, self._url(path), body)


# -- inventory -----------------------------------------------------------------

def _slug(obj) -> str | None:
    return obj.get("slug") if isinstance(obj, dict) else None


def _peers(iface: dict) -> list[dict]:
    peers = iface.get("link_peers") or iface.get("connected_endpoints") or []
    return [p for p in peers if isinstance(p, dict) and p.get("device")]


def _host(address: str) -> str:
    return address.split("/")[0]


def load_inventory(nb: NetBox, site: str, service_vlan_name: str = "tenant-a",
                   container_prefix: str = "clab-evpn-dc-") -> dict:
    sites = nb._get("dcim/sites", slug=site) or nb._get("dcim/sites", name=site)
    if not sites:
        raise NetBoxError(f"site {site!r} not found in NetBox")
    site_id = sites[0]["id"]

    devs = {d["name"]: d for d in nb._get("dcim/devices", site_id=site_id)}
    role = {n: _slug(d.get("role") or d.get("device_role")) for n, d in devs.items()}
    spines = sorted(n for n, r in role.items() if r == "spine")
    leaves = sorted(n for n, r in role.items() if r == "leaf")
    servers = sorted(n for n, r in role.items() if r == "server")
    if not spines:
        raise NetBoxError(f"site {site}: no device with role 'spine'")
    if not leaves:
        raise NetBoxError(f"site {site}: no device with role 'leaf'")
    if len(servers) < 2:
        raise NetBoxError(f"site {site}: need two devices with role 'server' for the "
                          f"service probe, found {len(servers)}")
    for n in (*spines, *leaves, *servers):
        if not _slug(devs[n].get("tenant")):
            raise NetBoxError(f"device {n}: no tenant assigned")

    vlans = {v["vid"]: v for v in nb._get("ipam/vlans", site_id=site_id)}
    svc = next((v for v in vlans.values() if v["name"] == service_vlan_name), None)
    if svc is None:
        raise NetBoxError(f"site {site}: no VLAN named {service_vlan_name!r}")
    vni = (svc.get("custom_fields") or {}).get("vni")
    if not isinstance(vni, int):
        raise NetBoxError(f"VLAN {svc['vid']} ({service_vlan_name}): custom field 'vni' "
                          "is not set")

    ids = [d["id"] for n, d in devs.items() if role[n] in ("spine", "leaf", "server")]
    ifaces: dict[str, list[dict]] = {}
    for i in nb._get("dcim/interfaces", device_id=ids):
        ifaces.setdefault(i["device"]["name"], []).append(i)
    ips: dict[tuple[str, str], str] = {}                  # (device, interface) -> address
    for ip in nb._get("ipam/ip-addresses", device_id=ids):
        obj = ip.get("assigned_object") or {}
        if ip.get("assigned_object_type") == "dcim.interface" and obj.get("device"):
            ips.setdefault((obj["device"]["name"], obj["name"]), _host(ip["address"]))

    def base(n):
        d = devs[n]
        return {"container": (d.get("custom_fields") or {}).get("container")
                or container_prefix + n, "tenant": d["tenant"]["slug"]}

    devices, hosts = {}, {}
    for n in (*spines, *leaves):
        d = devs[n]
        asn = (d.get("custom_fields") or {}).get("asn")
        if not isinstance(asn, int):
            raise NetBoxError(f"device {n}: custom field 'asn' is not set")
        lo = ips.get((n, "Loopback0"))
        if not lo:
            raise NetBoxError(f"device {n}: no IP address on Loopback0")
        entry = {**base(n), "role": role[n], "asn": asn, "loopback": lo, "interfaces": {}}
        uplinks, host_ports, intended = [], {}, {}
        for i in ifaces.get(n, []):
            peers = _peers(i)
            if not peers:
                continue
            peer = peers[0]["device"]["name"]
            entry["interfaces"][i["name"]] = peer
            if role[n] != "leaf":
                continue
            if role.get(peer) == "spine":
                uplinks.append(i["name"])
            elif role.get(peer) == "server":
                host_ports[i["name"]] = peer
                mode = i.get("mode")
                mode = mode.get("value") if isinstance(mode, dict) else mode
                vid = (i.get("untagged_vlan") or {}).get("vid")
                if mode != "access" or vid is None:
                    raise NetBoxError(f"{n} {i['name']} (host port to {peer}): needs "
                                      "mode=access and an untagged VLAN")
                if vid not in vlans:
                    raise NetBoxError(f"{n} {i['name']}: untagged VLAN {vid} is not a "
                                      f"VLAN of site {site}")
                intended[i["name"]] = vid
                hosts[peer] = {"leaf": n, "port": i["name"]}
        if role[n] == "leaf":
            if not uplinks:
                raise NetBoxError(f"leaf {n}: no interface cabled to a spine")
            entry.update(uplinks=uplinks, host_ports=host_ports, intended_vlans=intended)
        devices[n] = entry

    for s in servers:
        if s not in hosts:
            raise NetBoxError(f"server {s}: not cabled to any leaf")
        ip = (devs[s].get("primary_ip4") or {}).get("address")
        ip = _host(ip) if ip else next((a for (dv, _), a in ips.items() if dv == s), None)
        if not ip:
            raise NetBoxError(f"server {s}: no primary IPv4 and no IP on its interfaces")
        hosts[s] = {**base(s), "ip": ip, **hosts[s]}

    src, dst = servers[0], servers[1]
    return {
        "service": {"name": service_vlan_name, "vlan": svc["vid"], "vni": vni,
                    "probe": {"from": src, "to": dst, "to_ip": hosts[dst]["ip"]}},
        "vlans": {str(vid): v["name"] for vid, v in sorted(vlans.items())},
        "devices": devices,
        "hosts": {s: hosts[s] for s in servers},
    }
