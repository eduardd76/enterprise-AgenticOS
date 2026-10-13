"""Arista EOS (cEOS) fabric driver for the EVPN/VXLAN lab.

Read capabilities collect evidence per device (interfaces, underlay BGP, EVPN, VXLAN, MAC
table) and probe the tenant service end to end (host-to-host ping). Writes are an allowlist
of two change shapes, each bound to one device:
    {"interface": "EthernetN", "admin": "up"|"down"}
    {"interface": "EthernetN", "access_vlan": <vlan in inventory>}   (host ports only)

The twin is a rule-based model of the fabric's *health elements* (leaf uplinks, host-port
VLAN membership, the tenant service). It predicts per-element effects, so a change that fixes
one fault while another remains shows "improves X, service still unreachable" — honest
about multi-fault incidents. It is not an emulated clone of EOS.
"""

from __future__ import annotations

import asyncio
import copy
import json
import subprocess
from pathlib import Path

from ..errors import SyscallError
from ..registry import CallContext, Capability, Provider, Registry
from ..store import sha256

CLI_TIMEOUT_S = 60
SHOW = ["show interfaces status", "show ip bgp summary", "show bgp evpn summary",
        "show vxlan vni", "show mac address-table", "show vxlan vtep"]


def _parse_json_stream(text: str) -> list:
    dec, out, i = json.JSONDecoder(), [], 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return out
        obj, i = dec.raw_decode(text, i)
        out.append(obj)


def _peers(doc: dict) -> dict:
    peers = doc.get("vrfs", {}).get("default", {}).get("peers", {})
    return {ip: p.get("peerState") for ip, p in peers.items()}


class EosLab:
    def __init__(self, inventory_path: str | Path):
        inv = json.loads(Path(inventory_path).read_text())
        self.service, self.vlans = inv["service"], {int(k): v for k, v in inv["vlans"].items()}
        self.devices, self.hosts = inv["devices"], inv["hosts"]
        self.inventory = {**self.devices, **self.hosts}     # tenant lookups for any target
        self.apply_count = 0

    # -- transport ---------------------------------------------------------
    def _exec(self, container: str, argv: list[str]) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(["docker", "exec", container, *argv], capture_output=True,
                                  text=True, timeout=CLI_TIMEOUT_S)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise SyscallError("PROVIDER_ERROR", f"{container}: unreachable ({e})") from e

    def _cli(self, device: str, text: str) -> str:
        r = self._exec(self.devices[device]["container"], ["Cli", "-p", "15", "-c", text])
        if r.returncode != 0:
            raise SyscallError("PROVIDER_ERROR", f"{device}: Cli failed: {r.stderr.strip()[:200]}")
        return r.stdout

    def _show(self, device: str, commands: list[str]) -> list[dict]:
        out = self._cli(device, "\n".join(f"{c} | json" for c in commands))
        try:
            docs = _parse_json_stream(out)
        except json.JSONDecodeError as e:
            raise SyscallError("PROVIDER_ERROR", f"{device}: bad JSON from EOS") from e
        if len(docs) != len(commands):
            raise SyscallError("PROVIDER_ERROR", f"{device}: expected {len(commands)} JSON "
                                                 f"documents, got {len(docs)}")
        return docs

    # -- inventory / state ---------------------------------------------------
    def tenant_of(self, target: str) -> str | None:
        d = self.inventory.get(target)
        return d["tenant"] if d else None

    def running_config(self, device: str) -> str:
        return "\n".join(x for x in self._cli(device, "show running-config").splitlines()
                         if not x.startswith("! Command:") and "! Startup-config" not in x)

    def state_hash(self, device: str) -> str:
        return sha256(self.running_config(device))

    def inspect(self, device: str) -> dict:
        """Compact, model-friendly evidence for one device."""
        st, ipv4, evpn, vni, mac, vtep = self._show(device, SHOW)
        dev = self.devices[device]
        ifaces = {}
        for name in dev["interfaces"]:
            s = st.get("interfaceStatuses", {}).get(name, {})
            vinfo = s.get("vlanInformation", {})
            ifaces[name] = {"link": s.get("linkStatus", "unknown"),
                            "admin": "down" if s.get("linkStatus") == "disabled" else "up",
                            "mode": vinfo.get("interfaceMode"), "vlan": vinfo.get("vlanId"),
                            "peer": dev["interfaces"][name]}
        bindings = {}
        for intf in vni.get("vxlanIntfs", {}).values():
            for v, b in intf.get("vniBindings", {}).items():
                bindings[str(v)] = b.get("vlan")
        macs = [{"vlan": e.get("vlanId"), "mac": e.get("macAddress"),
                 "interface": e.get("interface"), "type": e.get("entryType")}
                for e in mac.get("unicastTable", {}).get("tableEntries", [])]
        return {"device": device, "role": dev["role"], "interfaces": ifaces,
                "underlay_bgp": _peers(ipv4), "evpn_bgp": _peers(evpn),
                "vni_to_vlan": bindings,
                "remote_vteps": sorted({v for i in vtep.get("interfaces", {}).values()
                                        for v in i.get("vteps", [])}),
                "mac_table": macs[:20],
                "host_ports": dev.get("host_ports", {}), "snapshot": self.state_hash(device)[:12]}

    def probe(self, host: str | None = None) -> dict:
        p = self.service["probe"]
        src = self.hosts[host or p["from"]]
        r = self._exec(src["container"], ["ping", "-c", "3", "-W", "1", p["to_ip"]])
        loss = next((ln.split("%")[0].split()[-1] for ln in r.stdout.splitlines()
                     if "packet loss" in ln), "100")
        return {"service": self.service["name"], "from": p["from"], "to": p["to"],
                "to_ip": p["to_ip"], "reachable": r.returncode == 0, "packet_loss_pct": loss}

    # -- changes -------------------------------------------------------------
    def commands(self, device: str, change) -> list[str]:
        dev = self.devices.get(device)
        if dev is None:
            raise ValueError(f"unknown device {device!r}")
        if not isinstance(change, dict) or change.get("interface") not in dev["interfaces"]:
            raise ValueError(f"unsupported change {change!r}")
        iface = change["interface"]
        if set(change) == {"interface", "admin"} and change["admin"] in ("up", "down"):
            return [f"interface {iface}", "no shutdown" if change["admin"] == "up" else "shutdown"]
        if set(change) == {"interface", "access_vlan"} and iface in dev.get("host_ports", {}) \
                and isinstance(change["access_vlan"], int) and change["access_vlan"] in self.vlans:
            return [f"interface {iface}", f"switchport access vlan {change['access_vlan']}"]
        raise ValueError(f"unsupported change {change!r}")

    def model(self) -> dict:
        """Live snapshot of the health-relevant fabric state."""
        m = {}
        for name, dev in self.devices.items():
            if dev["role"] != "leaf":
                continue
            ev = self.inspect(name)
            m[name] = {"uplinks": {u: ev["interfaces"][u]["admin"] for u in dev["uplinks"]},
                       "host_ports": {p: ev["interfaces"][p]["vlan"] for p in dev["host_ports"]},
                       "admin": {i: v["admin"] for i, v in ev["interfaces"].items()},
                       "vni": ev["vni_to_vlan"]}
        return m

    def health(self, m: dict) -> dict:
        svc_vlan, svc_vni = self.service["vlan"], str(self.service["vni"])
        h, ok = {}, True
        for leaf, s in m.items():
            for u, adm in s["uplinks"].items():
                h[f"{leaf}:{u} (uplink)"] = "up" if adm == "up" else "down"
                ok &= adm == "up"
            for p, vlan in s["host_ports"].items():
                good = vlan == svc_vlan and s["admin"].get(p) == "up"
                h[f"{leaf}:{p} ({self.devices[leaf]['host_ports'][p]})"] = \
                    f"vlan {vlan}" + ("" if good else " (wrong)")
                ok &= good
            ok &= s["vni"].get(svc_vni) == svc_vlan
        h[f"service:{self.service['name']}"] = "reachable" if ok else "unreachable"
        return h

    def simulate(self, device: str, change) -> dict:
        cmds = self.commands(device, change)
        live = self.model()
        twin = copy.deepcopy(live)
        s = twin[device]
        iface = change["interface"]
        if "admin" in change:
            rollback = {"interface": iface, "admin": s["admin"][iface]}
            s["admin"][iface] = change["admin"]
            if iface in s["uplinks"]:
                s["uplinks"][iface] = change["admin"]
        else:
            rollback = {"interface": iface, "access_vlan": s["host_ports"][iface]}
            s["host_ports"][iface] = change["access_vlan"]
        before, after = self.health(live), self.health(twin)
        healthy = lambda v: v in ("up", "reachable") or (v.startswith("vlan") and "wrong" not in v)
        return {"before": before, "predicted": after, "rollback": rollback,
                "regressions": [k for k in before if healthy(before[k]) and not healthy(after[k])],
                "improves": [k for k in before if not healthy(before[k]) and healthy(after[k])],
                "diff": [f"+ {c}" for c in cmds], "twin_kind": "rule-based fabric health model"}

    def apply(self, device: str, change) -> dict:
        cmds = self.commands(device, change)
        rollback = self.simulate(device, change)["rollback"]
        out = self._cli(device, "\n".join(["configure", *cmds, "end"]))
        if "%" in out:
            raise SyscallError("PROVIDER_ERROR", f"{device}: config rejected: {out.strip()[:200]}")
        self.apply_count += 1
        return {"applied": True, "rollback": rollback, "commands": cmds,
                "snapshot_version": self.state_hash(device)[:12]}

    def inject(self, device: str, change: dict) -> None:
        """Lab fault injection (operator-side, outside the kernel)."""
        self._cli(device, "\n".join(["configure", *self.commands(device, change), "end"]))

    # -- capability registration ---------------------------------------------
    def register(self, reg: Registry) -> None:
        lab = self

        def wrap(fn):
            async def provider(ctx: CallContext, target: str, args: dict) -> dict:
                if target not in lab.inventory:
                    raise SyscallError("INVALID_REQUEST", f"unknown target {target}")
                try:
                    return await asyncio.to_thread(fn, target, args)
                except (ValueError, KeyError, TypeError) as e:
                    raise SyscallError("INVALID_REQUEST", str(e)) from e
            return provider

        def device_only(fn):
            def f(target, args):
                if target not in lab.devices:
                    raise ValueError(f"{target} is not a switch")
                return fn(target, args)
            return f

        p = lambda pid, f: [Provider(pid, wrap(f), on_prem=True, trust=0.95, reliability=0.99,
                                     timeout_s=90)]
        reg.register(Capability(
            "network.fabric.inspect", "Interfaces, BGP, EVPN, VXLAN and MACs of one switch",
            "none", True, "device", (), ("interfaces", "evpn_bgp"),
            p("eos-cli", device_only(lambda d, a: lab.inspect(d)))))
        reg.register(Capability(
            "network.service.probe", "End-to-end tenant reachability (host ping)", "none", True,
            "device", (), ("reachable",),
            p("host-ping", lambda h, a: lab.probe(h if h in lab.hosts else None))))
        reg.register(Capability(
            "network.config.diff", "EOS commands a change would apply", "none", True, "device",
            ("change",), ("diff",),
            p("eos-cli", device_only(lambda d, a: {"diff": lab.simulate(d, a["change"])["diff"]}))))
        reg.register(Capability(
            "twin.simulate", "Predict a change on the fabric health model", "none", True,
            "device", ("change",), ("predicted", "regressions"),
            p("fabric-twin", device_only(lambda d, a: {
                k: v for k, v in lab.simulate(d, a["change"]).items()
                if k in ("before", "predicted", "regressions", "improves", "twin_kind")}))))
        reg.register(Capability(
            "network.config.apply", "Apply a change to an EOS switch", "external-write", False,
            "device", ("change",), ("applied", "rollback"),
            p("eos-cli", device_only(lambda d, a: lab.apply(d, a["change"]))), reversible=True))
