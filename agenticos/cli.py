"""`python -m agenticos <command>` — demo and operator tools.

  demo        AI NOC scenario end-to-end (fault -> diagnose -> approve -> fix -> verify),
              with crash injection, an over-reaching model, and a cross-tenant probe.
  lifecycle   Phase-1 exit test: start, suspend, resume and cancel an agent.
  ps          List agents and their states.
  audit       Verify the hash chain; --lineage DEL shows everything done under a delegation.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path

from .delegation import Grant
from .kernel import Kernel

DEFAULT_DB = "var/aos.db"
TENANT_A = "/aos/tenants/customer-a/*"


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def setup_principals(k: Kernel) -> None:
    k.add_principal("alice", "customer-a", ["noc-operator"], Grant(
        capabilities=["*"], targets=["router-edge-*", "router-core-*"], memory_paths=[TENANT_A],
        production_write=True, budget_calls=500, budget_tokens=100_000, ttl_s=3600))
    k.add_principal("bob", "customer-a", ["noc-lead"], Grant(capabilities=[]))
    k.add_principal("mallory", "customer-b", ["noc-operator"], Grant(
        capabilities=["*"], targets=["router-b-*"], memory_paths=["/aos/tenants/customer-b/*"],
        budget_calls=50, budget_tokens=1000, ttl_s=600))


def _printer(t0: float):
    def on_event(kind: str, d: dict) -> None:
        ts = f"{time.monotonic() - t0:6.2f}s"
        if kind == "state":
            color = {"RUNNING": "32", "WAITING": "33", "SUSPENDED": "35", "COMPLETED": "36",
                     "FAILED": "31", "TERMINATED": "31", "READY": "37"}.get(d["to"], "0")
            print(f"  {ts}  {d['agent_id']:<16} {d['from']:>9} -> {_c(color, d['to']):<20}"
                  f" {d['reason']}")
        elif kind == "crash":
            print(f"  {ts}  {_c('31;1', 'CRASH')} {d['agent_id']} killed (restart #{d['restarts']})")
    return on_event


async def demo(db: str, interactive: bool) -> int:
    Path(db).unlink(missing_ok=True)
    k = Kernel(db, slots=3, log_dir=Path(db).parent / "logs")
    setup_principals(k)
    t0 = time.monotonic()
    printer = _printer(t0)
    crashed: set[str] = set()

    def on_event(kind: str, d: dict) -> None:
        printer(kind, d)
        # Fault injection: kill each worker once, at the most awkward moment.
        if kind == "state" and d["to"] == "RUNNING" and d["agent_id"] not in crashed:
            aid = d["agent_id"]
            if aid.startswith("bgp-diag"):
                crashed.add(aid)
                k.inject_crash(aid, "network.interface.inspect")
            elif aid.startswith("change"):
                crashed.add(aid)
                k.inject_crash(aid, "network.config.apply")
    k.on_event = on_event

    def on_approval(aid: str, pkg: dict) -> None:
        print(_c("1", f"\n  ┌─ APPROVAL REQUIRED {aid} ── {pkg['op']} on {pkg['target']}"))
        print(f"  │ rationale : {pkg['rationale']}")
        print(f"  │ change    : {pkg['change']}   rollback: {pkg['rollback']}")
        print(f"  │ twin      : {pkg['predicted']}")
        print(f"  │ confidence: {pkg['confidence']['aggregate']} -> {pkg['confidence']['decision']}")
        print(f"  │ evidence  : {', '.join(pkg['evidence_refs'])}")

        def decide() -> None:
            ok = True
            if interactive:
                ok = input("  └─ bob (noc-lead), approve? [y/N] ").strip().lower() == "y"
            else:
                print("  └─ bob (noc-lead) approves (pass --interactive to decide yourself)\n")
            k.approvals.decide(aid, "bob", ok, "demo")
        asyncio.get_running_loop().call_later(0.3, decide)
    k.approval_handler = on_approval

    print(_c("1", "\n== AOS Kernel v0.1 — AI NOC demo =="))
    k.netsim.inject("interface_shutdown", "router-edge-01", interface="Gi0/0/0/1")
    n = k.netsim.devices["router-edge-01"]["bgp"]["192.0.2.1"]
    print(f"Fault injected: router-edge-01 BGP 192.0.2.1 is {_c('31', n['state'])}"
          f" ({n['last_reset']})\n")

    intent, coord = k.submit_intent(
        "alice", "Restore BGP session 192.0.2.1 on router-edge-01", "noc.coordinator",
        Grant(capabilities=["agent.spawn", "checkpoint.*", "ipc.*", "memory.*", "network.*",
                            "twin.simulate", "model.infer", "confidence.evaluate",
                            "approval.request"],
              targets=["router-edge-01"], memory_paths=[TENANT_A], production_write=True,
              budget_calls=150, budget_tokens=20_000, ttl_s=600),
        priority="critical", deadline_s=300,
        params={"device": "router-edge-01", "neighbor": "192.0.2.1", "incident_id": "INC-4821"})
    state = await k.wait(coord, 120)
    result = json.loads(k.agent(coord)["result"] or "{}")

    # A tenant-b agent probes tenant-a's incident report: must be denied.
    _, probe = k.submit_intent("mallory", "probe", "test.script", Grant(
        capabilities=["memory.read", "network.bgp.inspect", "checkpoint.*"],
        targets=["router-b-*"], memory_paths=["/aos/tenants/customer-b/*"], budget_calls=10,
        budget_tokens=0),
        params={"checkpoint_each": False, "script": [
            {"op": "memory.read", "target": "/aos/tenants/customer-a/incidents/INC-4821"},
            {"op": "network.bgp.inspect", "target": "router-edge-01",
             "args": {"neighbor": "192.0.2.1"}}]})
    await k.wait(probe, 30)
    probe_res = json.loads(k.agent(probe)["result"])["results"]

    diag = k.store.one("SELECT agent_id, result FROM agents WHERE agent_type='noc.bgp_diag'")
    diag_res = json.loads(diag["result"] or "{}")
    ok_chain, n_rec, msg = k.store.verify_audit()
    after = k.netsim.devices["router-edge-01"]["bgp"]["192.0.2.1"]["state"]

    print(_c("1", "\n== Outcome =="))
    print(f"  coordinator {coord}: {state} — {result.get('outcome')}  (report {result.get('report_ref')})")
    print(f"  BGP 192.0.2.1 now: {_c('32' if after == 'Established' else '31', after)}")
    print(_c("1", "\n== What the kernel proved =="))
    checks = [
        ("Model-suggested production write by diagnosis agent denied",
         diag_res.get("overreach") in ("UNAUTHORIZED", "POLICY_DENIED"), diag_res.get("overreach")),
        ("Crashed agents recovered from checkpoint",
         k.store.one("SELECT COUNT(*) c FROM audit WHERE event='agent.crashed'")["c"] == 2, "2 crashes"),
        ("Non-idempotent change executed exactly once despite crash+retry",
         k.netsim.apply_count == 1 and k.gateway.stats["replayed"] == 1,
         f"apply_count={k.netsim.apply_count}, replayed={k.gateway.stats['replayed']}"),
        ("Production write gated by human approval + confidence + state revalidation",
         k.store.one("SELECT COUNT(*) c FROM approvals WHERE status='used'")["c"] == 1, "apr used"),
        ("Cross-tenant memory read denied", probe_res[0].get("code") == "UNAUTHORIZED",
         probe_res[0].get("code")),
        ("Cross-tenant device access denied", probe_res[1].get("code") == "UNAUTHORIZED",
         probe_res[1].get("code")),
        ("Service restored and independently verified", after == "Established", after),
        ("Audit hash chain intact", ok_chain, f"{n_rec} records"),
    ]
    for name, ok, detail in checks:
        print(f"  {_c('32', 'PASS') if ok else _c('31', 'FAIL')}  {name}  [{detail}]")
    print(f"\n  gateway: {k.gateway.stats}")
    print(f"  inspect: python -m agenticos ps --db {db}  |  python -m agenticos audit --db {db}"
          f" --lineage del-0001")
    await k.shutdown()
    return 0 if all(ok for _, ok, _ in checks) else 1


async def lifecycle(db: str) -> int:
    """vExpertAI Phase-1 exit test: start, suspend, resume, cancel."""
    Path(db).unlink(missing_ok=True)
    k = Kernel(db, slots=2)
    setup_principals(k)
    k.on_event = _printer(time.monotonic())
    grant = Grant(capabilities=["network.bgp.inspect", "checkpoint.*"],
                  targets=["router-edge-01"], memory_paths=[TENANT_A], budget_calls=100)
    step = {"op": "network.bgp.inspect", "target": "router-edge-01", "args": {"neighbor": "192.0.2.1"}}
    script = [step, {"sleep": 0.2}] * 15
    print(_c("1", "\n== Phase-1 exit test: start / suspend / resume / cancel =="))
    _, a = k.submit_intent("alice", "poll BGP", "test.script", grant, params={"script": script})
    _, b = k.submit_intent("alice", "poll BGP", "test.script", grant, params={"script": script})
    await asyncio.sleep(0.6)
    k.suspend(a)
    await asyncio.sleep(0.3)                      # let an in-flight step reach the boundary
    frozen_at = k.runtimes[a].syscalls
    await asyncio.sleep(1.0)
    progressed_while_suspended = k.runtimes[a].syscalls - frozen_at
    k.resume(a)
    await asyncio.sleep(0.3)
    victims = k.cancel(b, "operator cancel")
    sa = await k.wait(a, 30)
    sb = await k.wait(b, 30)
    print(f"\n  {a}: {sa}   {b}: {sb} (cancelled: {victims})")
    print(f"  syscalls made by {a} while suspended: {progressed_while_suspended}")
    ok = sa == "COMPLETED" and sb == "TERMINATED" and progressed_while_suspended == 0
    print(f"  {_c('32', 'PASS') if ok else _c('31', 'FAIL')}  lifecycle exit test")
    await k.shutdown()
    return 0 if ok else 1


def ps(db: str) -> int:
    k = Kernel(db)
    print(f"{'AGENT':<16} {'TYPE':<16} {'TENANT':<11} {'STATE':<10} {'PRIO':<8} {'RST':<3} DELEGATION")
    for r in k.store.all("SELECT * FROM agents ORDER BY created_at"):
        print(f"{r['agent_id']:<16} {r['agent_type']:<16} {r['tenant']:<11} {r['state']:<10} "
              f"{r['priority']:<8} {r['restarts']:<3} {r['delegation_id']}")
    return 0


def audit(db: str, lineage: str | None) -> int:
    k = Kernel(db)
    ok, n, msg = k.store.verify_audit()
    print(f"{'OK' if ok else 'TAMPERED'}: {msg} ({n} records)")
    if lineage:
        ids = [lineage] + [r["delegation_id"] for r in k.store.all(
            "WITH RECURSIVE t(id) AS (SELECT ?1 UNION SELECT d.delegation_id FROM delegations d"
            " JOIN t ON d.parent_id=t.id) SELECT id AS delegation_id FROM t WHERE id<>?1",
            (lineage,))]
        print(f"\nActions under delegation {lineage} and its descendants {ids[1:]}:")
        q = ",".join("?" * len(ids))
        for r in k.store.all(f"SELECT * FROM audit WHERE delegation_id IN ({q}) AND event IN "
                             "('syscall.allowed','syscall.denied','syscall.replayed',"
                             "'delegation.created') ORDER BY seq", tuple(ids)):
            d = json.loads(r["data"])
            what = d.get("op") or d.get("delegatee")
            extra = d.get("code") or d.get("provider") or ""
            print(f"  #{r['seq']:<4} {r['delegation_id']:<9} {r['agent_id'] or '':<15} "
                  f"{r['event']:<19} {what} {d.get('target', '')} {extra}")
    return 0 if ok else 1


def main() -> None:
    ap = argparse.ArgumentParser(prog="agenticos", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["demo", "lifecycle", "ps", "audit"])
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--interactive", action="store_true")
    ap.add_argument("--lineage")
    a = ap.parse_args()
    if a.command == "demo":
        raise SystemExit(asyncio.run(demo(a.db, a.interactive)))
    if a.command == "lifecycle":
        raise SystemExit(asyncio.run(lifecycle(a.db)))
    if a.command == "ps":
        raise SystemExit(ps(a.db))
    raise SystemExit(audit(a.db, a.lineage))
