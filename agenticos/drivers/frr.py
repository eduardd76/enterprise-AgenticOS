"""Real FRRouting driver: talks to FRR routers (here, Docker containers) through vtysh.

It implements the same capability contracts as the simulator (network.bgp.inspect,
network.interface.inspect, network.config.get/diff/apply, twin.simulate), so agents,
gateway, approvals and audit are unchanged — only the provider behind the name differs.
Only the kernel process can reach Docker; sandboxed agents have no network or socket access.

The digital twin here is a rule-based model of the live state (interface admin state and
BGP hold timer). It is not a full emulation clone; Batfish/Containerlab-backed twins are
roadmap work.
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
from .netsim import NetSim

VTYSH_TIMEOUT_S = 15


class FrrLab:
    """Inventory-driven access to FRR devices (the inventory stands in for Nautobot/NetBox)."""

    def __init__(self, inventory_path: str | Path):
        self.inventory = json.loads(Path(inventory_path).read_text())["devices"]
        self.apply_count = 0

    # -- transport -------------------------------------------------------
    def _vtysh(self, device: str, *commands: str) -> str:
        argv = ["docker", "exec", self.inventory[device]["container"], "vtysh"]
        for c in commands:
            argv += ["-c", c]
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=VTYSH_TIMEOUT_S)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise SyscallError("PROVIDER_ERROR", f"{device}: vtysh unreachable ({e})") from e
        if r.returncode != 0:
            raise SyscallError("PROVIDER_ERROR", f"{device}: vtysh failed: {r.stderr.strip()[:200]}")
        return r.stdout

    def _json(self, device: str, command: str) -> dict:
        try:
            return json.loads(self._vtysh(device, command) or "{}")
        except json.JSONDecodeError as e:
            raise SyscallError("PROVIDER_ERROR", f"{device}: bad JSON from '{command}'") from e

    # -- inventory / state -----------------------------------------------
    def tenant_of(self, device: str) -> str | None:
        d = self.inventory.get(device)
        return d["tenant"] if d else None

    def running_config(self, device: str) -> str:
        # Drop the volatile header line ("Building configuration...") so the hash is stable.
        lines = self._vtysh(device, "show running-config").splitlines()
        return "\n".join(x for x in lines if not x.startswith(("Building", "Current configuration")))

    def state_hash(self, device: str) -> str:
        return sha256(self.running_config(device))

    def neighbor(self, device: str, ip: str) -> dict:
        n = self._json(device, f"show bgp neighbors {ip} json").get(ip)
        iface = self.inventory[device]["neighbors"].get(ip)
        if not n:
            return {"neighbor": ip, "state": "NotConfigured", "interface": iface}
        return {"neighbor": ip, "state": n.get("bgpState"), "remote_as": n.get("remoteAs"),
                "interface": iface,
                "hold_time": int(n.get("bgpTimerConfiguredHoldTimeMsecs", 0)) // 1000,
                "last_reset": n.get("lastResetDueTo")}

    def interface(self, device: str, name: str) -> dict:
        i = self._json(device, f"show interface {name} json").get(name, {})
        admin = i.get("administrativeStatus") or "unknown"
        return {"interface": name, "admin": admin, "oper": i.get("operationalStatus") or "down"}

    def live_model(self, device: str) -> dict:
        """Snapshot in the simulator's shape, so the twin can reuse its prediction rules."""
        inv = self.inventory[device]
        ifaces = {name: {"admin": self.interface(device, name)["admin"], "oper": "?"}
                  for name in set(inv["neighbors"].values())}
        bgp = {}
        for ip in inv["neighbors"]:
            n = self.neighbor(device, ip)
            bgp[ip] = {"remote_as": n.get("remote_as"), "interface": n["interface"],
                       "hold_time": n.get("hold_time", 0) or 180, "state": n["state"],
                       "last_reset": n.get("last_reset")}
        return {"tenant": inv["tenant"], "asn": inv["asn"], "interfaces": ifaces, "bgp": bgp}

    # -- change handling ---------------------------------------------------
    def commands(self, device: str, change) -> list[str]:
        """Translate a validated change object into vtysh configuration commands."""
        inv = self.inventory[device]
        if not isinstance(change, dict):
            raise ValueError("change must be an object")
        if set(change) == {"interface", "admin"} and change["admin"] in ("up", "down") \
                and change["interface"] in set(inv["neighbors"].values()):
            return [f"interface {change['interface']}",
                    "no shutdown" if change["admin"] == "up" else "shutdown"]
        if set(change) == {"neighbor", "hold_time"} and change["neighbor"] in inv["neighbors"] \
                and isinstance(change["hold_time"], int) and 3 <= change["hold_time"] <= 65535:
            keepalive = max(1, change["hold_time"] // 3)
            return [f"router bgp {inv['asn']}",
                    f"neighbor {change['neighbor']} timers {keepalive} {change['hold_time']}"]
        raise ValueError(f"unsupported change {change!r}")

    def simulate(self, device: str, change) -> dict:
        cmds = self.commands(device, change)               # validates
        live = self.live_model(device)
        twin = copy.deepcopy(live)
        rollback = NetSim._apply_change(twin, change)
        NetSim._recompute(twin)
        before = {ip: n["state"] for ip, n in live["bgp"].items()}
        after = {ip: n["state"] for ip, n in twin["bgp"].items()}
        return {"before": before, "predicted": after, "rollback": rollback,
                "regressions": [ip for ip in before if before[ip] == "Established" != after[ip]],
                "diff": [f"+ {c}" for c in cmds], "twin_kind": "rule-based model of live state"}

    def apply(self, device: str, change) -> dict:
        cmds = self.commands(device, change)
        rollback = self.simulate(device, change)["rollback"]
        out = self._vtysh(device, "configure terminal", *cmds, "end")
        if "%" in out:                                     # vtysh reports errors as "% ..."
            raise SyscallError("PROVIDER_ERROR", f"{device}: config rejected: {out.strip()[:200]}")
        self.apply_count += 1
        return {"applied": True, "rollback": rollback, "commands": cmds,
                "snapshot_version": self.state_hash(device)[:12]}

    # -- fault injection for the lab --------------------------------------
    def inject_interface_shutdown(self, device: str, interface: str) -> None:
        self._vtysh(device, "configure terminal", f"interface {interface}", "shutdown", "end")

    # -- capability registration ------------------------------------------
    def register(self, reg: Registry) -> None:
        lab = self

        def wrap(fn):
            async def provider(ctx: CallContext, target: str, args: dict) -> dict:
                if target not in lab.inventory:
                    raise SyscallError("INVALID_REQUEST", f"unknown device {target}")
                try:
                    return await asyncio.to_thread(fn, target, args)
                except (ValueError, KeyError, TypeError) as e:
                    raise SyscallError("INVALID_REQUEST", str(e)) from e
            return provider

        snap = lambda d: lab.state_hash(d)[:12]
        bgp = lambda d, a: {**lab.neighbor(d, a["neighbor"]), "snapshot_version": snap(d)}
        iface = lambda d, a: {**lab.interface(d, a["interface"]), "snapshot_version": snap(d)}
        cfg = lambda d, a: {"config": lab.running_config(d), "state_hash": lab.state_hash(d),
                            "snapshot_version": snap(d)}
        diff = lambda d, a: {"diff": lab.simulate(d, a["change"])["diff"]}
        twin = lambda d, a: {k: v for k, v in lab.simulate(d, a["change"]).items()
                             if k in ("before", "predicted", "regressions", "twin_kind")}
        apply = lambda d, a: lab.apply(d, a["change"])

        p = lambda pid, f: [Provider(pid, wrap(f), on_prem=True, trust=0.95, reliability=0.99)]
        reg.register(Capability("network.bgp.inspect", "Read BGP neighbor state (FRR)", "none",
                                True, "device", ("neighbor",), ("state",), p("frr-vtysh", bgp)))
        reg.register(Capability("network.interface.inspect", "Read interface state (FRR)", "none",
                                True, "device", ("interface",), ("admin", "oper"),
                                p("frr-vtysh", iface)))
        reg.register(Capability("network.config.get", "Read running config (FRR)", "none", True,
                                "device", (), ("config", "state_hash"), p("frr-vtysh", cfg)))
        reg.register(Capability("network.config.diff", "Commands a change would apply", "none",
                                True, "device", ("change",), ("diff",), p("frr-vtysh", diff)))
        reg.register(Capability("twin.simulate", "Predict a change on a model of live state",
                                "none", True, "device", ("change",), ("predicted", "regressions"),
                                p("frr-twin", twin)))
        reg.register(Capability("network.config.apply", "Apply a change to an FRR router",
                                "external-write", False, "device", ("change",),
                                ("applied", "rollback"), p("frr-vtysh", apply), reversible=True))
