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


async def fabric(db: str, model: str | None, interactive: bool, inject: bool = True,
                 max_rounds: int = 3, approval_timeout_s: int = 300) -> int:
    from .cli import TENANT_A, _c, _ollama_ready, _printer, setup_principals
    from .drivers.eos import EosLab

    lab = EosLab(INVENTORY)
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
    print(f"  fabric: spine1, leaf1, leaf2 · tenant-a = VLAN 10 / VNI 10010 · diagnosis: {reasoning}")
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
    state = await k.wait(coord, 3000)
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
    await k.shutdown()
    return 0 if final["reachable"] else 1
