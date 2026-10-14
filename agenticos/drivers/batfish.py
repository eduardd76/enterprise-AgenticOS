"""Batfish twin: predict a change from the switches' *real* configurations.

The rule-based twin in eos.py knows three hand-written facts about one lab. This twin instead
takes the live running-config of every switch, writes the candidate change into the target's
config text, and asks Batfish (an open-source network configuration analyser) to compute the
control plane of both snapshots: BGP sessions (underlay and EVPN), interface state, VLAN
membership, VXLAN VNI bindings, and VTEP-to-VTEP underlay paths. The prediction is therefore
derived from the configuration, not from rules that already know the answer.

Service health is a conjunction of those Batfish facts (every leaf's BGP sessions up, host
ports active in the intended VLAN, the service VNI bound on every leaf, every VTEP reaching
every other). Batfish does not forward host packets across VXLAN, so "reachable" here means
"every control-plane precondition holds"; the independent verifier still pings afterwards.

Requires a Batfish service (`docker run -p 9996:9996 batfish/allinone`) and `pip install
pybatfish`. Both are optional: without them the kernel uses the rule-based twin.
"""

from __future__ import annotations

import hashlib
import re
import tempfile
import threading
from pathlib import Path

CHANGE_KEYS = ({"interface", "admin"}, {"interface", "access_vlan"})


def healthy(value: str) -> bool:
    """Shared by both twins: "up"/"reachable", or "vlan N" with no "(...)" qualifier."""
    return value in ("up", "reachable") or (value.startswith("vlan") and "(" not in value)


def _block(lines: list[str], iface: str) -> tuple[int, int] | None:
    """[start, end) of an `interface X` stanza in EOS running-config text."""
    for i, ln in enumerate(lines):
        if ln.rstrip() == f"interface {iface}":
            j = i + 1
            while j < len(lines) and lines[j].startswith(" "):
                j += 1
            return i, j
    return None


def interface_settings(cfg: str, iface: str) -> dict:
    """What the config says today: admin state and access VLAN (used for rollback)."""
    lines = cfg.splitlines()
    span = _block(lines, iface)
    body = lines[span[0] + 1:span[1]] if span else []
    vlan = next((int(m.group(1)) for ln in body
                 if (m := re.fullmatch(r"\s+switchport access vlan (\d+)", ln))), None)
    return {"admin": "down" if any(ln.strip() == "shutdown" for ln in body) else "up",
            "access_vlan": vlan if vlan is not None else 1}


def candidate_config(cfg: str, change: dict) -> str:
    """The running-config with one allowlisted change written in, as EOS would store it."""
    if set(change) not in CHANGE_KEYS:
        raise ValueError(f"unsupported change {change!r}")
    lines = cfg.splitlines()
    iface = change["interface"]
    span = _block(lines, iface)
    if span is None:                       # unconfigured interface: EOS defaults apply
        insert = next((i for i, ln in enumerate(lines) if ln.startswith("interface ")),
                      len(lines))
        lines[insert:insert] = [f"interface {iface}", "!"]
        span = (insert, insert + 1)
    start, end = span
    if "admin" in change:
        body = [ln for ln in lines[start + 1:end] if ln.strip() not in ("shutdown", "no shutdown")]
        if change["admin"] == "down":
            body.append("   shutdown")
    else:
        body = [ln for ln in lines[start + 1:end]
                if not re.fullmatch(r"\s+switchport access vlan \d+", ln)]
        body.append(f"   switchport access vlan {int(change['access_vlan'])}")
    lines[start + 1:end] = body
    return "\n".join(lines) + "\n"


class BatfishTwin:
    """Evaluates fabric health on Batfish snapshots built from config text."""

    def __init__(self, inventory: dict, host: str = "127.0.0.1", network: str = "agenticos"):
        from pybatfish.client.session import Session     # optional dependency
        from pybatfish.datamodel.flow import HeaderConstraints
        self._hc = HeaderConstraints
        self.inv, self.network = inventory, network
        self.bf = Session(host=host)
        self.bf.set_network(network)
        self.lock = threading.Lock()                     # one pybatfish session, many threads
        self._known: set[str] = set(self.bf.list_snapshots())
        self.kind = f"Batfish control-plane model ({host})"

    def _snapshot(self, configs: dict[str, str]) -> str:
        configs = {d: "!RANCID-CONTENT-TYPE: arista\n" + c for d, c in configs.items()}
        name = "s-" + hashlib.sha256(                   # content-addressed: cache by config
            "\0".join(f"{d}\0{c}" for d, c in sorted(configs.items())).encode()).hexdigest()[:16]
        if name not in self._known:
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "configs").mkdir()
                for dev, cfg in configs.items():       # the header pins the EOS dialect
                    (Path(tmp) / "configs" / f"{dev}.cfg").write_text(cfg)
                self.bf.init_snapshot(tmp, name=name, overwrite=True)
            self._known.add(name)
        return name

    def evaluate(self, configs: dict[str, str]) -> dict[str, str]:
        with self.lock:
            snap = self._snapshot(configs)
            self.bf.set_snapshot(snap)
            q = self.bf.q
            bgp = q.bgpSessionStatus().answer().frame()
            ifs = q.interfaceProperties(
                properties="Active,Access_VLAN,Switchport_Mode").answer().frame()
            vni = q.vxlanVniProperties().answer().frame()
            leaves = [d for d, v in self.inv["devices"].items() if v["role"] == "leaf"]
            paths = {}
            for a in leaves:
                for b in leaves:
                    if a != b:
                        hc = self._hc(srcIps=self.inv["devices"][a]["loopback"],
                                      dstIps=self.inv["devices"][b]["loopback"])
                        tr = q.traceroute(startLocation=a, headers=hc).answer().frame()
                        paths[(a, b)] = bool(len(tr)) and all(
                            t.disposition == "ACCEPTED" for t in tr.iloc[0]["Traces"])
        return self._health(leaves, bgp, ifs, vni, paths)

    def _health(self, leaves, bgp, ifs, vni, paths) -> dict[str, str]:
        svc = self.inv["service"]
        h: dict[str, str] = {}

        def session(leaf: str, family: str) -> str:
            rows = bgp[(bgp.Node == leaf) & bgp.Address_Families.apply(lambda f: family in f)]
            return "up" if len(rows) and (rows.Established_Status == "ESTABLISHED").all() \
                else "down"

        for leaf in leaves:
            dev = self.inv["devices"][leaf]
            h[f"{leaf}: underlay BGP"] = session(leaf, "IPV4_UNICAST")
            h[f"{leaf}: EVPN BGP"] = session(leaf, "EVPN")
            intended = dev.get("intended_vlans", {})
            for port, host in dev.get("host_ports", {}).items():
                row = ifs[ifs.Interface.apply(lambda i: i.hostname == leaf and
                                              i.interface == port)]
                want = int(intended.get(port, svc["vlan"]))
                if not len(row):
                    h[f"{leaf}:{port} ({host})"] = "missing (wrong)"
                    continue
                r = row.iloc[0]
                vlan = r.Access_VLAN
                note = "" if vlan == want else f" (wrong, intended {want})"
                if not r.Active:
                    note = " (inactive)"
                h[f"{leaf}:{port} ({host})"] = f"vlan {vlan}{note}"
            mine = vni[(vni.Node == leaf) & (vni.VNI == svc["vni"])]
            h[f"{leaf}: VNI {svc['vni']}"] = (f"vlan {mine.iloc[0].VLAN}" + (
                "" if mine.iloc[0].VLAN == svc["vlan"] else " (wrong)")) if len(mine) \
                else "missing (wrong)"
        for (a, b), ok in sorted(paths.items()):
            h[f"VTEP {a} -> {b}"] = "reachable" if ok else "unreachable"
        h[f"service:{svc['name']}"] = "reachable" if all(healthy(v) for v in h.values()) \
            else "unreachable"
        return h
