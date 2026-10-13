"""Event-driven operation: watch the network, open an incident when a BGP link breaks, let
the agents work it (human approval still required), and return to watching when they exit.

The watcher is deliberately not an AI. It is cheap, deterministic kernel-side monitoring
that turns a symptom into an intent (vExpertAI §4 step 1: "Event arrives. AOS allocates an
incident ID and starts a coordinator."). It runs as the system principal `noc-monitor`;
approvals must come from a human with an approver role (`agenticos approve`).
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

from .delegation import Grant
from .gateway import TERMINAL
from .kernel import Kernel

MONITOR_CAPS = ["agent.spawn", "checkpoint.*", "ipc.*", "memory.*", "network.*",
                "twin.simulate", "model.infer", "confidence.evaluate", "approval.request"]


class Link:
    """One BGP peering, seen from both ends. Correlating both ends into one link means one
    outage opens one incident, not two."""

    def __init__(self, ends: list[tuple[str, str, str]]):
        self.ends = ends                                    # (device, neighbor_ip, local_iface)
        self.key = " <-> ".join(sorted(d for d, _, _ in ends))

    def states(self, net) -> dict[str, str]:
        return {d: net.neighbor(d, ip)["state"] for d, ip, _ in self.ends}

    def culprit(self, net) -> tuple[str, str]:
        """Root-cause localisation: prefer the end whose own interface is admin-down."""
        for d, ip, iface in self.ends:
            if net.interface(d, iface)["admin"] == "down":
                return d, ip
        d, ip, _ = self.ends[0]
        return d, ip


def discover_links(net, tenant: str) -> list[Link]:
    owner = {dev["address"]: name for name, dev in net.inventory.items() if "address" in dev}
    seen: dict[frozenset, list] = {}
    for name, dev in net.inventory.items():
        if dev["tenant"] != tenant:
            continue
        for ip, iface in dev["neighbors"].items():
            key = frozenset({name, owner.get(ip, ip)})
            seen.setdefault(key, []).append((name, ip, iface))
    return [Link(ends) for ends in seen.values()]


async def watch(db: str, model: str | None = None, interval: float = 3.0, once: bool = False,
                approval_timeout_s: int = 600, debounce: int = 2, cooldown_s: float = 120.0,
                tenant: str = "customer-a", slack_channel: str | None = None,
                approvers_file: str | None = None, slack_api: str | None = None) -> int:
    from .cli import LAB_INVENTORY, TENANT_A, _c, _ollama_ready, _printer, setup_principals
    from .drivers.frr import FrrLab

    net = FrrLab(LAB_INVENTORY)
    links = discover_links(net, tenant)
    try:
        for link in links:
            link.states(net)
    except Exception as e:
        print(f"FRR lab not reachable ({e}).\nStart it with: labs/frr-bgp/lab.sh up")
        return 2
    url = os.environ.get("AOS_MODEL_URL", "http://localhost:11434")
    if model and _ollama_ready(url, model):
        os.environ.update(AOS_MODEL_URL=url, AOS_MODEL_NAME=model)
        reasoning = f"local model {model}"
    else:
        os.environ.pop("AOS_MODEL_URL", None)
        reasoning = "scripted reasoner"

    slack = None
    if slack_channel:
        from .channels import SlackApprovalChannel, load_approvers
        if not approvers_file:
            print("--slack-channel needs --approvers (maps Slack user ids to principals)")
            return 2
        try:
            slack = SlackApprovalChannel(os.environ.get("SLACK_BOT_TOKEN", ""), slack_channel,
                                         load_approvers(approvers_file),
                                         **({"api_base": slack_api} if slack_api else {}))
        except (ValueError, OSError) as e:
            print(f"Slack not configured: {e}")
            return 2

    Path(db).unlink(missing_ok=True)
    k = Kernel(db, slots=3, log_dir=Path(db).parent / "logs", netsim=net)
    setup_principals(k)
    k.add_principal("noc-monitor", tenant, ["system-monitor"], Grant(
        capabilities=MONITOR_CAPS, targets=["lab-*"], memory_paths=[TENANT_A],
        production_write=True, budget_calls=100_000, budget_tokens=10_000_000, ttl_s=30 * 86400))
    k.on_event = _printer(time.monotonic())

    def on_approval(aid: str, pkg: dict) -> None:
        print(_c("1", f"\n  ┌─ APPROVAL REQUIRED {aid} ── {pkg['op']} on {pkg['target']}"))
        print(f"  │ rationale : {pkg['rationale']}")
        print(f"  │ commands  : {' ; '.join(x.lstrip('+- ') for x in pkg['diff'])}"
              f"   rollback: {pkg['rollback']}")
        print(f"  │ twin      : {pkg['predicted']}  (computed by the kernel)")
        print(f"  │ confidence: {pkg['confidence']['aggregate']} -> {pkg['confidence']['decision']}")
        if slack:
            print(f"  │ slack     : posted to {slack.channel} — react ✅ approve / ❌ deny")
            asyncio.get_running_loop().create_task(_post_safe(slack, k, aid, pkg))
        print(f"  │ approve   : python3 -m agenticos approve {aid} --as bob --db {db}")
        print(f"  └ deny      : python3 -m agenticos approve {aid} --as bob --deny --db {db}"
              f"   (expires in {approval_timeout_s}s)\n")
    k.approval_handler = on_approval

    print(_c("1", "\n== AgenticOS watch =="))
    print(f"  watching {len(links)} BGP link(s) every {interval:g}s: "
          f"{', '.join(link.key for link in links)}")
    where = f"Slack {slack_channel} or CLI" if slack else "CLI"
    print(f"  diagnosis: {reasoning} · approvals: human (role noc-lead) via {where}"
          f" · Ctrl-C to stop\n")
    slack_task = asyncio.create_task(slack.run(k)) if slack else None

    active: dict[str, tuple[str, str]] = {}          # link key -> (incident, coordinator)
    down_count: dict[str, int] = {}
    cooldown: dict[str, float] = {}
    handled = 0
    try:
        while True:
            for link in links:
                states = await asyncio.to_thread(link.states, net)
                healthy = all(s == "Established" for s in states.values())
                if link.key in active:
                    inc, coord = active[link.key]
                    row = k.agent(coord)
                    if row["state"] in TERMINAL:
                        res = json.loads(row["result"] or "{}")
                        live = sum(1 for rt in k.runtimes.values()
                                   if rt.proc and rt.proc.returncode is None)
                        print(_c("1", f"\n  {inc} closed: {row['state']} — "
                                      f"{res.get('outcome', res.get('error', 'see audit'))}"))
                        print(f"  agent processes still running: {live}  · report "
                              f"{res.get('report_ref')}  · link now {states}\n")
                        del active[link.key]
                        handled += 1
                        if not healthy:
                            print(_c("33", f"  {link.key} still down after {inc}: "
                                           f"needs a human (no auto-retry for {cooldown_s:g}s)\n"))
                        cooldown[link.key] = time.time() + cooldown_s
                    continue
                if healthy:
                    down_count[link.key] = 0
                    continue
                down_count[link.key] = down_count.get(link.key, 0) + 1
                if down_count[link.key] < debounce or time.time() < cooldown.get(link.key, 0):
                    continue                          # flap protection / recent incident
                device, neighbor = await asyncio.to_thread(link.culprit, net)
                inc = k.store.next_id("INC")
                print(_c("31;1", f"  ALERT {link.key}: {states} -> opening {inc} on {device}"))
                _, coord = k.submit_intent(
                    "noc-monitor", f"Restore BGP {device} <-> {neighbor}", "noc.coordinator",
                    Grant(capabilities=MONITOR_CAPS, targets=[device], memory_paths=[TENANT_A],
                          production_write=True, budget_calls=200, budget_tokens=20_000,
                          ttl_s=approval_timeout_s + 900),
                    priority="critical", deadline_s=approval_timeout_s + 900,
                    params={"device": device, "neighbor": neighbor, "incident_id": inc,
                            "approval_timeout_s": approval_timeout_s})
                active[link.key] = (inc, coord)
            if once and handled and not active:
                return 0
            await asyncio.sleep(interval)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n  watch stopped")
        return 0
    finally:
        if slack_task:
            slack_task.cancel()
        await k.shutdown()


async def _post_safe(slack, k, aid: str, pkg: dict) -> None:
    """HTTP in a worker thread; audit writes back on the kernel thread (SQLite affinity)."""
    try:
        await asyncio.to_thread(slack.post, aid, pkg)
        k.store.audit("approval.posted", approval_id=aid, channel="slack", to=slack.channel)
    except Exception as e:                       # CLI approval still works if Slack is down
        k.store.audit("approval.channel_error", approval_id=aid, channel="slack",
                      error=str(e)[:200])
        hint = ""
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            hint = ("\n    Python has no CA certificates. On macOS run: "
                    "\"/Applications/Python 3.12/Install Certificates.command\"")
        print(f"  ! Slack post failed for {aid} ({e}); approve via CLI instead{hint}")


def approve(db: str, approval_id: str, principal: str, deny: bool, note: str) -> int:
    """The second-terminal half of watch mode: a human decision written to the shared store."""
    from .cli import setup_principals
    from .errors import SyscallError
    k = Kernel(db)
    setup_principals(k)
    try:
        k.approvals.decide(approval_id, principal, not deny, note or "cli")
    except SyscallError as e:
        print(f"refused: {e}")
        return 1
    print(f"{approval_id}: {'denied' if deny else 'approved'} by {principal}")
    return 0


def pending(db: str) -> int:
    k = Kernel(db)
    rows = k.store.all("SELECT * FROM approvals WHERE status='pending' ORDER BY ts")
    for r in rows:
        pkg = json.loads(r["package"])
        print(f"{r['approval_id']}  {r['op']} on {r['target']}  change={pkg['change']}"
              f"  confidence={pkg['confidence']['decision']}  by {r['agent_id']}")
    if not rows:
        print("no pending approvals")
    return 0
