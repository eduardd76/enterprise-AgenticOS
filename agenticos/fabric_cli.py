"""`agenticos fabric`: the two-fault EVPN/VXLAN incident on real Arista cEOS switches."""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

from .delegation import Grant
from .kernel import Kernel

INVENTORY = Path(__file__).resolve().parent.parent / "labs" / "evpn-ceos" / "inventory.json"
FAULTS = [("leaf2", {"interface": "Ethernet1", "admin": "down"}),        # obvious
          ("leaf2", {"interface": "Ethernet3", "access_vlan": 20})]      # subtle drift
CAPS = ["agent.spawn", "checkpoint.*", "ipc.*", "memory.*", "network.*", "twin.simulate",
        "model.infer", "confidence.evaluate", "approval.request"]


def _source_of_truth(sot: str, site: str):
    """The inventory and intent: the lab's JSON file, or NetBox (NETBOX_URL, NETBOX_TOKEN)."""
    if sot == "file":
        return INVENTORY, f"file {INVENTORY.name}"
    from .sot.netbox import NetBox, load_inventory
    url = os.environ.get("NETBOX_URL", "http://127.0.0.1:8000")
    return load_inventory(NetBox(url, os.environ.get("NETBOX_TOKEN", "")), site), \
        f"NetBox {url} (site {site})"


def _approval_channel(servicenow: bool, slack_channel: str | None, approvers_file: str | None):
    """Where humans decide: ServiceNow change requests, Slack, or this terminal (None)."""
    if not (servicenow or slack_channel):
        return None, None
    if not approvers_file:
        raise ValueError("--approvers is required (maps Slack/ServiceNow users to principals)")
    if servicenow:
        from .servicenow import ServiceNowApprovalChannel, load_servicenow_approvers
        ch = ServiceNowApprovalChannel(
            os.environ.get("SNOW_INSTANCE", ""), load_servicenow_approvers(approvers_file),
            user=os.environ.get("SNOW_USER"), password=os.environ.get("SNOW_PASSWORD"),
            token=os.environ.get("SNOW_TOKEN"),
            assignment_group=os.environ.get("SNOW_ASSIGNMENT_GROUP"))
        return ch, f"ServiceNow change request ({ch.instance_url})"
    from .channels import SlackApprovalChannel, load_approvers
    ch = SlackApprovalChannel(os.environ.get("SLACK_BOT_TOKEN", ""), slack_channel,
                              load_approvers(approvers_file),
                              **({"api_base": os.environ["AOS_SLACK_API"]}
                                 if os.environ.get("AOS_SLACK_API") else {}))
    return ch, f"Slack {slack_channel}"


async def fabric(db: str, model: str | None, interactive: bool, inject: bool = True,
                 max_rounds: int = 3, approval_timeout_s: int = 300, twin: str = "rules",
                 sot: str = "file", site: str = "evpn-dc", servicenow: bool = False,
                 slack_channel: str | None = None, approvers_file: str | None = None) -> int:
    from .cli import TENANT_A, _c, _ollama_ready, _printer, setup_principals
    from .drivers.eos import EosLab
    from .watch import _post_safe

    try:
        inventory, sot_label = _source_of_truth(sot, site)
        lab = EosLab(inventory, twin=twin, batfish_host=os.environ.get("BATFISH_HOST",
                                                                         "127.0.0.1"))
        channel, where = _approval_channel(servicenow, slack_channel, approvers_file)
    except ImportError as e:
        print(f"missing optional dependency: {e} (pip install pybatfish)")
        return 2
    except Exception as e:
        print(f"setup failed: {e}")
        return 2
    try:
        await asyncio.to_thread(lab.probe)
    except Exception as e:
        print(f"EVPN lab not reachable ({e}).\nStart it with: labs/evpn-ceos/lab.sh up")
        return 2
    url = os.environ.get("AOS_MODEL_URL", "http://localhost:11434")
    if model and _ollama_ready(url, model):
        os.environ.update(AOS_MODEL_URL=url, AOS_MODEL_NAME=model)
        reasoning = f"local LLM {model}"
    else:
        os.environ.pop("AOS_MODEL_URL", None)
        reasoning = "scripted rules (baseline)"

    Path(db).unlink(missing_ok=True)
    k = Kernel(db, slots=3, log_dir=Path(db).parent / "logs", netsim=lab)
    setup_principals(k)
    devices, hosts = list(lab.devices), list(lab.hosts)
    k.add_principal("alice", "customer-a", ["noc-operator"], Grant(
        capabilities=["*"], targets=devices + hosts, memory_paths=[TENANT_A],
        production_write=True, budget_calls=2000, budget_tokens=500_000, ttl_s=7200))
    k.on_event = _printer(time.monotonic())

    def on_approval(aid: str, pkg: dict) -> None:
        print(_c("1", f"\n  ┌─ APPROVAL REQUIRED {aid} ── {pkg['op']} on {pkg['target']}"))
        print(f"  │ rationale : {pkg['rationale']}  (agent, unverified)")
        print(f"  │ commands  : {' ; '.join(x.lstrip('+- ') for x in pkg['diff'])}"
              f"   rollback: {pkg['rollback']}")
        print(f"  │ twin      : {pkg['predicted']}")
        print(f"  │ confidence: {pkg['confidence']['aggregate']} -> {pkg['confidence']['decision']}")
        print(f"  │ twin kind : {pkg.get('twin_kind', 'rules')}")
        if channel:
            print(f"  └─ waiting for a human decision in {where} "
                  f"(or: python3 -m agenticos approve {aid} --as bob --db {db})\n")
            asyncio.get_running_loop().create_task(
                _post_safe(channel, k, aid, pkg, label="servicenow" if servicenow else "slack"))
            return

        def decide() -> None:
            ok = True
            if interactive:
                ok = input("  └─ bob (noc-lead), approve? [y/N] ").strip().lower() == "y"
            else:
                print("  └─ bob (noc-lead) approves (--interactive to decide yourself)\n")
            k.approvals.decide(aid, "bob", ok, "fabric demo")
        asyncio.get_running_loop().call_later(0.3, decide)
    k.approval_handler = on_approval

    print(_c("1", "\n== AgenticOS — two-fault EVPN/VXLAN incident on Arista cEOS =="))
    svc = lab.service
    print(f"  fabric: {', '.join(devices)} · {svc['name']} = VLAN {svc['vlan']} / VNI {svc['vni']}"
          f" · diagnosis: {reasoning}")
    print(f"  source of truth: {sot_label} · twin: {lab.twin.kind if lab.twin else 'rules'}"
          f" · approvals: {where or ('this terminal' if interactive else 'auto (demo)')}")
    if inject:
        for dev, ch in FAULTS:
            await asyncio.to_thread(lab.inject, dev, ch)
        print(_c("31", "  faults injected: leaf2 Ethernet1 shutdown (uplink) + "
                       "leaf2 Ethernet3 moved to VLAN 20 (host2 port drift)"))
    probe = await asyncio.to_thread(lab.probe)
    print(f"  probe host1 -> host2: {'REACHABLE' if probe['reachable'] else 'UNREACHABLE'}"
          f" ({probe['packet_loss_pct']}% loss)\n")

    _, coord = k.submit_intent(
        "alice", "Restore tenant-a reachability host1 <-> host2", "fabric.coordinator",
        Grant(capabilities=CAPS, targets=devices + hosts, memory_paths=[TENANT_A],
              production_write=True, budget_calls=400, budget_tokens=200_000, ttl_s=3600),
        priority="critical", deadline_s=3600,
        params={"incident_id": "INC-EVPN-1", "devices": devices, "hosts": hosts,
                "max_rounds": max_rounds, "approval_timeout_s": approval_timeout_s})
    channel_task = asyncio.create_task(channel.run(k)) if channel else None
    state = await k.wait(coord, 3000)
    if channel_task:
        channel_task.cancel()
    res = json.loads(k.agent(coord)["result"] or "{}")
    final = await asyncio.to_thread(lab.probe)

    print(_c("1", "\n== Outcome =="))
    print(f"  incident: {state} — {res.get('outcome', res.get('error'))}")
    for f in res.get("fixes", []):
        print(f"  round {f['round']}: {f['device']} {f['interface']} "
              f"{'admin ' + f['admin'] if 'admin' in f else 'access vlan ' + str(f.get('access_vlan'))}"
              f"  ← {f['claim']}")
    print(f"  tenant-a host1 -> host2 now: "
          f"{_c('32', 'REACHABLE') if final['reachable'] else _c('31', 'UNREACHABLE')}")
    diags = [json.loads(r["result"] or "{}") for r in k.store.all(
        "SELECT result FROM agents WHERE agent_type='fabric.diag' ORDER BY created_at")]
    print(f"  diagnosis rounds: {len(diags)} · reasoner: "
          f"{', '.join(sorted({d.get('model_provider') or '-' for d in diags}))}"
          f" · model overreach: {[d.get('model_overreach') for d in diags if d.get('model_overreach')]}")
    print(f"  production changes applied: {lab.apply_count} · audit chain: "
          f"{'intact' if k.store.verify_audit()[0] else 'BROKEN'}")
    if servicenow and channel:
        outcome = f"{state}: {res.get('outcome', res.get('error'))}"
        for aid in list(channel.changes):
            ok = await asyncio.to_thread(channel.close, aid, outcome, final["reachable"])
            print(f"  ServiceNow {channel.changes[aid][1]}: "
                  f"{'closed ' + ('successful' if final['reachable'] else 'unsuccessful') if ok else 'close failed'}")
    await k.shutdown()
    return 0 if final["reachable"] else 1
