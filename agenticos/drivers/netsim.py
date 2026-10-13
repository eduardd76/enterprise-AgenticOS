"""Simulated FRR-style network + digital twin — the 'device drivers' of the MVP.

Stands in for Containerlab/FRR (vExpertAI Phase 3). Drivers live only in the kernel
process; agents reach them exclusively through the syscall gateway.
"""

from __future__ import annotations

import copy

from ..errors import SyscallError
from ..registry import CallContext, Capability, Provider, Registry
from ..store import sha256


def _router(tenant: str, asn: int, neighbors: dict[str, tuple[int, str]]) -> dict:
    ifaces = {iface: {"admin": "up", "oper": "up"} for _, iface in neighbors.values()}
    return {"tenant": tenant, "asn": asn, "interfaces": ifaces,
            "bgp": {ip: {"remote_as": ras, "interface": iface, "hold_time": 90,
                         "state": "Established", "last_reset": None}
                    for ip, (ras, iface) in neighbors.items()}}


class NetSim:
    def __init__(self) -> None:
        self.devices = {
            "router-edge-01": _router("customer-a", 65001, {"192.0.2.1": (65002, "Gi0/0/0/1"),
                                                            "198.51.100.1": (65003, "Gi0/0/0/2")}),
            "router-core-01": _router("customer-a", 65001, {"10.0.0.1": (65001, "Gi0/0/0/0")}),
            "router-b-01": _router("customer-b", 65100, {"203.0.113.1": (65101, "Gi0/0/0/1")}),
        }
        self.version = 1
        self.apply_count = 0          # how many times a production write actually executed

    # -- inventory -------------------------------------------------------
    def tenant_of(self, device: str) -> str | None:
        d = self.devices.get(device)
        return d["tenant"] if d else None

    def state_hash(self, device: str) -> str:
        return sha256(self.devices[device])

    # -- fault injection -------------------------------------------------
    def inject(self, fault: str, device: str, **kw) -> None:
        dev = self.devices[device]
        if fault == "interface_shutdown":
            dev["interfaces"][kw["interface"]]["admin"] = "down"
        elif fault == "hold_timer_mismatch":
            dev["bgp"][kw["neighbor"]]["hold_time"] = 0
        else:
            raise ValueError(fault)
        self._recompute(dev)
        self.version += 1

    @staticmethod
    def _recompute(dev: dict) -> None:
        for n in dev["bgp"].values():
            iface = dev["interfaces"][n["interface"]]
            iface["oper"] = iface["admin"]
            if iface["admin"] != "up":
                n["state"], n["last_reset"] = "Idle", "Interface flap"
            elif n["hold_time"] == 0:
                n["state"], n["last_reset"] = "Active", "Hold timer expired"
            else:
                n["state"], n["last_reset"] = "Established", n["last_reset"]

    @staticmethod
    def _apply_change(dev: dict, change: dict) -> dict:
        """Returns the rollback change. Supported: interface admin state, neighbor hold time."""
        if "interface" in change:
            iface = dev["interfaces"][change["interface"]]
            rollback = {"interface": change["interface"], "admin": iface["admin"]}
            iface["admin"] = change["admin"]
        elif "neighbor" in change:
            n = dev["bgp"][change["neighbor"]]
            rollback = {"neighbor": change["neighbor"], "hold_time": n["hold_time"]}
            n["hold_time"] = int(change["hold_time"])
        else:
            raise ValueError(f"unsupported change {change}")
        NetSim._recompute(dev)
        return rollback

    def simulate(self, device: str, change: dict) -> dict:
        """Digital twin: predict a change's effect without touching the live device."""
        twin = copy.deepcopy(self)
        rollback = NetSim._apply_change(twin.devices[device], change)
        before = {ip: n["state"] for ip, n in self.devices[device]["bgp"].items()}
        after = {ip: n["state"] for ip, n in twin.devices[device]["bgp"].items()}
        old, new = self.config_text(device).splitlines(), twin.config_text(device).splitlines()
        return {"before": before, "predicted": after, "rollback": rollback,
                "regressions": [ip for ip in before if before[ip] == "Established" != after[ip]],
                "diff": [f"- {x}" for x in old if x not in new] + [f"+ {x}" for x in new if x not in old]}

    def config_text(self, device: str) -> str:
        dev = self.devices[device]
        lines = [f"hostname {device}"]
        for name, i in sorted(dev["interfaces"].items()):
            lines += [f"interface {name}", " shutdown" if i["admin"] == "down" else " no shutdown"]
        lines.append(f"router bgp {dev['asn']}")
        for ip, n in sorted(dev["bgp"].items()):
            lines += [f" neighbor {ip} remote-as {n['remote_as']}",
                      f" neighbor {ip} timers 30 {n['hold_time']}"]
        return "\n".join(lines)


def register(reg: Registry, sim: NetSim) -> None:
    def dev(target: str) -> dict:
        return sim.devices[target]

    async def bgp_inspect(ctx: CallContext, target: str, args: dict) -> dict:
        n = dev(target)["bgp"].get(args["neighbor"])
        if n is None:
            return {"neighbor": args["neighbor"], "state": "NotConfigured",
                    "snapshot_version": sim.version}
        return {"neighbor": args["neighbor"], **copy.deepcopy(n), "snapshot_version": sim.version}

    async def iface_inspect(ctx: CallContext, target: str, args: dict) -> dict:
        i = dev(target)["interfaces"][args["interface"]]
        return {"interface": args["interface"], **i, "snapshot_version": sim.version}

    async def config_get(ctx: CallContext, target: str, args: dict) -> dict:
        return {"config": sim.config_text(target), "state_hash": sim.state_hash(target),
                "snapshot_version": sim.version}

    async def config_diff(ctx: CallContext, target: str, args: dict) -> dict:
        return {"diff": _sim(target, args["change"])["diff"]}

    async def twin_simulate(ctx: CallContext, target: str, args: dict) -> dict:
        r = _sim(target, args["change"])
        return {k: r[k] for k in ("before", "predicted", "regressions")}

    def _sim(target: str, change) -> dict:
        try:
            return sim.simulate(target, change)
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            raise SyscallError("INVALID_REQUEST", f"unsupported change {change!r}") from e

    async def config_apply(ctx: CallContext, target: str, args: dict) -> dict:
        _sim(target, args["change"])           # validate on the twin first: drivers fail atomically
        rollback = NetSim._apply_change(dev(target), args["change"])
        sim.apply_count += 1
        sim.version += 1
        return {"applied": True, "rollback": rollback, "snapshot_version": sim.version}

    local = lambda pid, fn: [Provider(pid, fn, on_prem=True, trust=0.95, reliability=0.99)]
    reg.register(Capability("network.bgp.inspect", "Read BGP neighbor state", "none", True,
                            "device", ("neighbor",), ("state",), local("frr-sim", bgp_inspect)))
    reg.register(Capability("network.interface.inspect", "Read interface state", "none", True,
                            "device", ("interface",), ("admin", "oper"),
                            local("frr-sim", iface_inspect)))
    reg.register(Capability("network.config.get", "Read running config", "none", True,
                            "device", (), ("config", "state_hash"), local("frr-sim", config_get)))
    reg.register(Capability("network.config.diff", "Diff a proposed change", "none", True,
                            "device", ("change",), ("diff",), local("frr-sim", config_diff)))
    reg.register(Capability("twin.simulate", "Predict a change's effect on a digital twin", "none",
                            True, "device", ("change",), ("predicted", "regressions"),
                            local("twin-sim", twin_simulate)))
    reg.register(Capability("network.config.apply", "Apply a change to a production device",
                            "external-write", False, "device", ("change",), ("applied", "rollback"),
                            local("frr-sim", config_apply), reversible=True))
