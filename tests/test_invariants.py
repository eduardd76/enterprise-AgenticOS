"""Conformance tests: one or more tests per kernel invariant (AOS-0001 App. C; vExpertAI §7).
In-process: agents are A-PCB rows without processes; frames go straight to the gateway."""

import asyncio
import json

import pytest

from agenticos.delegation import Grant, covers
from agenticos.errors import SyscallError
from conftest import agent, make_kernel


async def call(k, aid, op, target="", args=None, key=None):
    return await k.gateway.dispatch(aid, op, target, args or {}, key)


async def code_of(k, aid, op, target="", args=None, key=None):
    try:
        await call(k, aid, op, target, args, key)
        return "OK"
    except SyscallError as e:
        return e.code


async def approved_change(k, aid, change, approver="bob"):
    """Drive confidence -> approval.request -> human decision; returns approval id."""
    from agenticos.confidence import COMPONENTS
    ev = await call(k, aid, "network.bgp.inspect", "router-edge-01", {"neighbor": "192.0.2.1"})
    c = (await call(k, aid, "confidence.evaluate", args={
        "components": {n: .95 for n in COMPONENTS}, "evidence_refs": [ev["evidence_ref"]],
        "for_op": "network.config.apply"}))["result"]
    req = asyncio.create_task(call(k, aid, "approval.request", "router-edge-01",
                                   {"op": "network.config.apply", "change": change,
                                    "confidence_ref": c["confidence_id"], "timeout_s": 5}))
    await asyncio.sleep(0.05)
    aid_ = k.store.one("SELECT approval_id FROM approvals ORDER BY ts DESC LIMIT 1")["approval_id"]
    k.approvals.decide(aid_, approver, True)
    return (await req)["result"]["approval_id"]


FIX = {"interface": "Gi0/0/0/1", "admin": "up"}


# --- INV-003 / vExpertAI: no tool execution without a validated capability -------------
def test_unknown_capability_is_denied_and_counted(run):
    async def t():
        k = make_kernel()
        a = agent(k)
        assert await code_of(k, a, "network.shell.exec", "router-edge-01") == "UNKNOWN_CAPABILITY"
        assert k.gateway.stats["unknown_capability"] == 1
    run(t())


def test_ungranted_capability_and_target_denied(run):
    async def t():
        k = make_kernel()
        a = agent(k, caps=["network.bgp.inspect"])
        assert await code_of(k, a, "network.interface.inspect", "router-edge-01",
                             {"interface": "Gi0/0/0/1"}) == "UNAUTHORIZED"
        assert await code_of(k, a, "network.bgp.inspect", "router-core-01",
                             {"neighbor": "10.0.0.1"}) == "UNAUTHORIZED"
        assert await code_of(k, a, "network.bgp.inspect", "router-edge-01",
                             {"neighbor": "192.0.2.1"}) == "OK"
    run(t())


# --- INV-004: delegation is monotonically non-expanding ---------------------------------
def test_pattern_cover_semantics():
    assert covers("*", "network.bgp.inspect")
    assert covers("network.*", "network.bgp.*")
    assert not covers("network.bgp.*", "network.*")
    assert not covers("network.bgp.inspect", "network.bgp.*")
    assert not covers("network.config.get", "network.config.apply")


@pytest.mark.parametrize("grant, code", [
    ({"capabilities": ["network.config.apply"]}, "UNAUTHORIZED"),          # capability
    ({"capabilities": ["ipc.send"], "targets": ["router-*"]}, "UNAUTHORIZED"),   # target
    ({"capabilities": ["ipc.send"], "production_write": True}, "UNAUTHORIZED"),  # privilege
    ({"capabilities": ["ipc.send"], "memory_paths": ["/aos/tenants/*"]}, "UNAUTHORIZED"),
    ({"capabilities": ["ipc.send"], "budget_calls": 10_000}, "BUDGET_EXHAUSTED"),  # budget
])
def test_child_cannot_exceed_parent(run, grant, code):
    async def t():
        k = make_kernel()
        parent = agent(k, caps=["agent.spawn", "ipc.send", "network.bgp.inspect"], calls=50)
        assert await code_of(k, parent, "agent.spawn", "test.script", {"grant": grant}) == code
    run(t())


def test_child_budgets_reserved_atomically_and_expiry_clamped(run):
    async def t():
        k = make_kernel()
        parent = agent(k, caps=["agent.spawn", "ipc.send"], calls=30)
        g = {"capabilities": ["ipc.send"], "budget_calls": 12, "budget_tokens": 0, "ttl_s": 10**9}
        c1 = (await call(k, parent, "agent.spawn", "test.script", {"grant": g}))["result"]
        await call(k, parent, "agent.spawn", "test.script", {"grant": g})
        # 30 - (1 call + 12 reserved) * 2 = 4 left: a third child of 12 must not fit
        assert await code_of(k, parent, "agent.spawn", "test.script", {"grant": g}) == \
            "BUDGET_EXHAUSTED"
        pd = k.delegations.get(k.agent(parent)["delegation_id"])
        cd = k.delegations.get(c1["delegation_id"])
        assert cd["valid_until"] <= pd["valid_until"]
    run(t())


def test_revocation_cascades_to_descendants(run):
    async def t():
        k = make_kernel()
        parent = agent(k, caps=["agent.spawn", "agent.*", "network.bgp.inspect"], calls=50)
        g = {"capabilities": ["agent.spawn", "network.bgp.inspect"], "targets": ["router-edge-01"],
             "budget_calls": 20}
        child = (await call(k, parent, "agent.spawn", "test.script", {"grant": g}))["result"]
        grandchild = (await call(k, child["agent_id"], "agent.spawn", "test.script",
                                 {"grant": {"capabilities": ["network.bgp.inspect"],
                                            "targets": ["router-edge-01"], "budget_calls": 5}})
                      )["result"]
        victims = k.cancel(parent, "test")
        assert set(victims) == {parent, child["agent_id"], grandchild["agent_id"]}
        assert await code_of(k, grandchild["agent_id"], "network.bgp.inspect", "router-edge-01",
                             {"neighbor": "192.0.2.1"}) == "UNAUTHORIZED"   # terminated
    run(t())


# --- vExpertAI: no cross-tenant access ------------------------------------------------
def test_cross_tenant_device_memory_and_ipc_denied(run):
    async def t():
        k = make_kernel()
        a, b = agent(k), agent(k, principal="mallory", targets=["router-*"])
        w = await call(k, a, "memory.write", "/aos/tenants/customer-a/incidents/x", {"data": {"s": 1}})
        assert await code_of(k, b, "network.bgp.inspect", "router-edge-01",
                             {"neighbor": "192.0.2.1"}) == "POLICY_DENIED"
        assert await code_of(k, b, "memory.read", "/aos/tenants/customer-a/incidents/x") == \
            "UNAUTHORIZED"
        assert await code_of(k, b, "memory.read", "/aos/tenants/customer-a/nope") == "UNAUTHORIZED"
        assert await code_of(k, b, "memory.read", w["result"]["evidence_id"]) == "NOT_FOUND"
        assert await code_of(k, b, "memory.read",
                             "/aos/tenants/customer-b/../customer-a/incidents/x") == "INVALID_REQUEST"
        assert await code_of(k, b, "ipc.send", a, {"type": "HELLO"}) == "UNAUTHORIZED"
        b2 = (await call(k, b, "agent.spawn", "test.script", {"grant": {
            "capabilities": ["ipc.*"], "budget_calls": 5}}))["result"]["agent_id"]
        assert await code_of(k, b, "ipc.send", b2, {
            "type": "HELLO", "evidence_refs": [w["result"]["evidence_id"]]}) == "UNAUTHORIZED"
    run(t())


# --- vExpertAI: no production write without approval + current-state validation --------
def test_production_write_requires_grant_approval_and_key(run):
    async def t():
        k = make_kernel()
        ro = agent(k)                       # no production_write
        rw = agent(k, prod=True)
        assert await code_of(k, ro, "network.config.apply", "router-edge-01",
                             {"change": FIX}, "k1") == "POLICY_DENIED"
        assert await code_of(k, rw, "network.config.apply", "router-edge-01",
                             {"change": FIX}, "k1") == "APPROVAL_REQUIRED"
        assert await code_of(k, rw, "network.config.apply", "router-edge-01",
                             {"change": FIX, "approval_id": "apr-9999"}) == "INVALID_REQUEST"
        assert await code_of(k, rw, "network.config.apply", "router-edge-01",
                             {"change": FIX, "approval_id": "apr-9999"}, "k1") == "APPROVAL_REQUIRED"
        assert k.netsim.apply_count == 0
    run(t())


def test_approval_needs_actionable_confidence_and_approver_role(run):
    async def t():
        k = make_kernel()
        rw = agent(k, prod=True)
        assert await code_of(k, rw, "approval.request", "router-edge-01", {
            "op": "network.config.apply", "change": FIX, "confidence_ref": "conf-9"}) == \
            "CONFIDENCE_INSUFFICIENT"
        low = (await call(k, rw, "confidence.evaluate", args={
            "components": {"model": 0.3, "data": 0.9}, "for_op": "network.config.apply"}))
        assert low["result"]["decision"] == "ESCALATE"
        # an agent can't self-declare a production write as low impact
        lowball = await call(k, rw, "confidence.evaluate", args={
            "components": {"model": 0.7, "data": 0.7}, "impact": "low",
            "for_op": "network.config.apply"})
        assert lowball["result"]["impact"] == "high" and lowball["result"]["decision"] == "ESCALATE"
        # a record evaluated for something else can't justify a production write
        other = await call(k, rw, "confidence.evaluate", args={"components": {"model": 0.99}})
        assert await code_of(k, rw, "approval.request", "router-edge-01", {
            "op": "network.config.apply", "change": FIX,
            "confidence_ref": other["result"]["confidence_id"]}) == "CONFIDENCE_INSUFFICIENT"
        assert await code_of(k, rw, "approval.request", "router-edge-01", {
            "op": "network.config.apply", "change": FIX,
            "confidence_ref": low["result"]["confidence_id"]}) == "CONFIDENCE_INSUFFICIENT"
        with pytest.raises(SyscallError):        # carol is an operator, not an approver
            await approved_change(k, rw, FIX, approver="carol")
    run(t())


def test_approved_change_runs_once_is_single_use_and_bound(run):
    async def t():
        k = make_kernel()
        k.netsim.inject("interface_shutdown", "router-edge-01", interface="Gi0/0/0/1")
        rw = agent(k, prod=True)
        apr = await approved_change(k, rw, FIX)
        other = {"interface": "Gi0/0/0/2", "admin": "down"}
        assert await code_of(k, rw, "network.config.apply", "router-edge-01",
                             {"change": other, "approval_id": apr}, "k1") == "POLICY_DENIED"
        r1 = await call(k, rw, "network.config.apply", "router-edge-01",
                        {"change": FIX, "approval_id": apr}, "k1")
        r2 = await call(k, rw, "network.config.apply", "router-edge-01",   # retry, same key
                        {"change": FIX, "approval_id": apr}, "k1")
        assert r2["replayed"] and r2["result"] == r1["result"]
        assert k.netsim.apply_count == 1
        assert await code_of(k, rw, "network.config.apply", "router-edge-01",   # new key
                             {"change": FIX, "approval_id": apr}, "k2") == "APPROVAL_REQUIRED"
    run(t())


def test_stale_state_after_approval_is_rejected(run):
    async def t():
        k = make_kernel()
        k.netsim.inject("interface_shutdown", "router-edge-01", interface="Gi0/0/0/1")
        rw = agent(k, prod=True)
        apr = await approved_change(k, rw, FIX)
        k.netsim.inject("hold_timer_mismatch", "router-edge-01", neighbor="198.51.100.1")
        assert await code_of(k, rw, "network.config.apply", "router-edge-01",
                             {"change": FIX, "approval_id": apr}, "k1") == "STALE_STATE"
        assert k.netsim.apply_count == 0
    run(t())


def test_started_but_unfinished_write_escalates_instead_of_repeating(run):
    async def t():
        k = make_kernel()
        rw = agent(k, prod=True)
        row = k.agent(rw)
        key = k.gateway.idem_key(row, "network.config.apply", "k1", "router-edge-01",
                                 {"change": FIX})
        k.store.exec("INSERT INTO idempotency(key, agent_id, op, target, status) "
                     "VALUES (?,?,?,?, 'started')", (key, rw, "network.config.apply", "router-edge-01"))
        apr = await approved_change(k, rw, FIX)
        assert await code_of(k, rw, "network.config.apply", "router-edge-01",
                             {"change": FIX, "approval_id": apr}, "k1") == "PARTIAL_SIDE_EFFECT"
        assert k.netsim.apply_count == 0
    run(t())


# --- LLM output can't modify enforcement rules; audit is tamper-evident ----------------
def test_protected_namespaces_unwritable(run):
    async def t():
        k = make_kernel()
        k.add_principal("root", "customer-a", [], Grant(capabilities=["*"], memory_paths=["/aos/*"]))
        _, a = k.submit_intent("root", "x", "test.script",
                               Grant(capabilities=["memory.write"], memory_paths=["/aos/*"]))
        for p in ("/aos/policies/p1", "/aos/audit/x", "/aos/agents/registry"):
            assert await code_of(k, a, "memory.write", p, {"data": {}}) == "POLICY_DENIED"
    run(t())


def test_audit_chain_detects_tampering(run):
    async def t():
        k = make_kernel()
        a = agent(k)
        await call(k, a, "network.bgp.inspect", "router-edge-01", {"neighbor": "192.0.2.1"})
        assert k.store.verify_audit()[0]
        k.store.exec("UPDATE audit SET data=? WHERE event='syscall.allowed'", (json.dumps({}),))
        assert not k.store.verify_audit()[0]
    run(t())


def test_modified_intent_blocks_execution(run):
    async def t():
        k = make_kernel()
        a = agent(k)
        k.store.exec("UPDATE intents SET body=replace(body, 'test', 'drop all routes')")
        assert await code_of(k, a, "network.bgp.inspect", "router-edge-01",
                             {"neighbor": "192.0.2.1"}) == "UNAUTHORIZED"
    run(t())


# --- Feasibility before optimisation; budgets ------------------------------------------
def test_sovereign_profile_rejects_offprem_provider(run):
    async def t():
        k = make_kernel()
        a = agent(k)
        r = await call(k, a, "model.infer", args={"task": "x", "evidence": {}})
        assert r["provider"] == "mock-local"
        ev = json.loads(k.store.one("SELECT data FROM audit WHERE event='syscall.allowed' "
                                    "ORDER BY seq DESC LIMIT 1")["data"])
        reasons = {x["provider"]: x["reason"] for x in ev["rejected_providers"]}
        assert reasons["cloud-llm"].startswith("sovereignty")
    run(t())


def test_call_and_token_budgets_enforced(run):
    async def t():
        k = make_kernel()
        a = agent(k, calls=2)
        for _ in range(2):
            await call(k, a, "network.bgp.inspect", "router-edge-01", {"neighbor": "192.0.2.1"})
        assert await code_of(k, a, "network.bgp.inspect", "router-edge-01",
                             {"neighbor": "192.0.2.1"}) == "BUDGET_EXHAUSTED"
        b = agent(k, tokens=5)
        assert await code_of(k, b, "model.infer", args={"task": "x", "evidence": {}}) == \
            "BUDGET_EXHAUSTED"
    run(t())


# --- IPC, locks, scheduler ---------------------------------------------------------------
def test_ipc_typed_deduplicated_and_acked_on_checkpoint(run):
    async def t():
        k = make_kernel()
        a = agent(k)
        b = (await call(k, a, "agent.spawn", "test.script", {"grant": {
            "capabilities": ["ipc.*", "checkpoint.*"], "budget_calls": 20}}))["result"]["agent_id"]
        other_intent = agent(k)
        assert await code_of(k, a, "ipc.send", other_intent, {"type": "HELLO"}) == "UNAUTHORIZED"
        args = {"type": "VALIDATION_REQUEST", "payload": {"h": 1}, "message_id": "m1"}
        assert (await call(k, a, "ipc.send", b, args))["result"]["duplicate"] is False
        assert (await call(k, a, "ipc.send", b, args))["result"]["duplicate"] is True
        assert await code_of(k, a, "ipc.send", b, {"type": "lowercase"}) == "INVALID_REQUEST"
        m = (await call(k, b, "ipc.recv", args={"timeout_s": 1}))["result"]
        assert m["source"] == a and m["payload"] == {"h": 1}
        assert await code_of(k, b, "ipc.recv", args={"timeout_s": 0.2}) == "DEADLINE_EXCEEDED"
        await call(k, b, "checkpoint.save", args={"state": {}})
        assert k.store.one("SELECT status FROM messages WHERE client_id='m1'")["status"] == "acked"
    run(t())


def test_lock_deadlock_detected_not_hung(run):
    async def t():
        k = make_kernel()
        a, b = agent(k), agent(k)
        await call(k, a, "lock.acquire", "/locks/twin-slot", {"lease_s": 30})
        await call(k, b, "lock.acquire", "/locks/maint-window", {"lease_s": 30})
        a_waits = asyncio.create_task(call(k, a, "lock.acquire", "/locks/maint-window",
                                           {"timeout_s": 5}))
        await asyncio.sleep(0.05)
        assert await code_of(k, b, "lock.acquire", "/locks/twin-slot", {"timeout_s": 5}) == "DEADLOCK"
        await call(k, b, "lock.release", "/locks/maint-window")
        assert (await a_waits)["result"]["resource"] == "/locks/maint-window"
    run(t())


def test_scheduler_priority_then_aging_prevents_starvation(run):
    from agenticos.scheduler import Scheduler

    async def t():
        s = Scheduler(slots=1, aging_per_s=1000.0, aging_quantum_s=0.1)
        await s.acquire("holder", "normal", None)
        low = asyncio.create_task(s.acquire("doc-agent", "low", None))
        await asyncio.sleep(0.4)               # low ages by ~400 points > critical base 300
        crit = asyncio.create_task(s.acquire("bgp-outage", "critical", None))
        await asyncio.sleep(0)
        s.release("holder")
        await asyncio.sleep(0)
        assert s.dispatch_log[-1] == "doc-agent"     # aged past critical's 300
        s.release("doc-agent")
        await asyncio.gather(low, crit)
        s2 = Scheduler(slots=1, aging_per_s=0.0)
        await s2.acquire("holder", "normal", None)
        tasks = [asyncio.create_task(s2.acquire(n, p, d)) for n, p, d in
                 [("doc", "low", None), ("soc", "high", 50.0), ("bgp", "critical", 100.0),
                  ("bgp-urgent", "critical", 10.0)]]
        await asyncio.sleep(0)
        for _ in range(4):
            s2.release(s2.dispatch_log[-1])
            await asyncio.sleep(0)
        assert s2.dispatch_log[1:] == ["bgp-urgent", "bgp", "soc", "doc"]
        await asyncio.gather(*tasks)
    run(t())


def test_confidence_actions():
    from agenticos.confidence import evaluate
    assert evaluate({"model": .95, "data": .95}, "high", True)["decision"] == "PROCEED"
    assert evaluate({"model": .4, "data": .95}, "high", False)["decision"] == "TERMINATE"
    assert evaluate({"model": .4, "data": .95}, "high", True)["decision"] == "ESCALATE"
    assert evaluate({"model": .5, "data": .5}, "low", True)["decision"] == "RETRY"
    with pytest.raises(ValueError):
        evaluate({"vibes": 1.0}, "low", True)


def test_child_priority_clamped_and_locks_tenant_scoped(run):
    async def t():
        k = make_kernel()
        _, low = k.submit_intent("alice", "docs", "test.script",
                                 Grant(capabilities=["agent.spawn", "lock.*"], budget_calls=20),
                                 priority="low")
        c = (await call(k, low, "agent.spawn", "test.script", {
            "grant": {"capabilities": ["lock.*"], "budget_calls": 5}, "priority": "critical"}))
        assert k.agent(c["result"]["agent_id"])["priority"] == "low"
        b = agent(k, principal="mallory")
        await call(k, low, "lock.acquire", "/locks/twin-slot", {"lease_s": 30})
        r = await call(k, b, "lock.acquire", "/locks/twin-slot", {"timeout_s": 0.2})
        assert r["result"]["resource"] == "/locks/twin-slot"     # no cross-tenant contention
    run(t())


def test_settle_order_cannot_inflate_root_budget(run):
    """Reviewer bug #1: grandchild usage must reach the root even if the parent settles first."""
    async def t():
        k = make_kernel()
        root = agent(k, caps=["agent.spawn", "network.bgp.inspect"], calls=100)
        g = {"capabilities": ["network.bgp.inspect"], "targets": ["router-edge-01"],
             "budget_calls": 40}
        child = (await call(k, root, "agent.spawn", "test.script", {"grant": g}))["result"]
        for _ in range(40):
            await call(k, child["agent_id"], "network.bgp.inspect", "router-edge-01",
                       {"neighbor": "192.0.2.1"})
        k.cancel(root, "test")
        d = k.delegations.get(k.agent(root)["delegation_id"])
        assert d["used_calls"] == 41 and d["reserved_calls"] == 0
    run(t())


def test_edf_breaks_ties_within_priority(run):
    from agenticos.scheduler import Scheduler

    async def t():
        s = Scheduler(slots=1)
        await s.acquire("occupant", "normal", None)
        late = asyncio.create_task(s.acquire("late-deadline", "normal", 100.0))
        early = asyncio.create_task(s.acquire("early-deadline", "normal", 1.0))
        await asyncio.sleep(0)
        s.release("occupant")
        await asyncio.sleep(0)
        assert s.dispatch_log[-1] == "early-deadline"
        s.release("early-deadline")
        await asyncio.gather(late, early)
    run(t())


# --- Operator-configurable risk appetite ---------------------------------------------------
def test_confidence_policy_is_per_tenant_versioned_and_validated(run, tmp_path):
    from agenticos.confidence import COMPONENTS, ConfidencePolicy

    async def t():
        k = make_kernel()
        a, b = agent(k), agent(k, principal="mallory", targets=["router-b-01"])
        comps = {n: .92 for n in COMPONENTS}
        comps["model"] = .85                       # aggregate ~0.91, weakest 0.85

        async def decide(aid):
            ev = await call(k, aid, "network.bgp.inspect",
                            "router-edge-01" if aid == a else "router-b-01",
                            {"neighbor": "192.0.2.1" if aid == a else "203.0.113.1"})
            r = await call(k, aid, "confidence.evaluate", args={
                "components": comps, "for_op": "network.config.apply",
                "evidence_refs": [ev["evidence_ref"]]})
            return r["result"]

        default = await decide(a)
        assert default["decision"] == "PROCEED"
        assert default["policy_version"] == ConfidencePolicy().version
        v = k.set_confidence_policy("customer-b", {"high_proceed": .95, "high_floor": .90,
                                                    "allow_warning": False})
        strict = await decide(b)
        assert strict["decision"] == "ESCALATE" and strict["policy_version"] == v
        assert (await decide(a))["decision"] == "PROCEED"        # tenant A unaffected
        ev = json.loads(k.store.one("SELECT data FROM audit WHERE event='policy.confidence.set'")
                        ["data"])
        assert ev["tenant"] == "customer-b" and ev["version"] == v

        for bad in ({"high_proceed": 1.5}, {"hard_floor": .9, "high_floor": .8},
                    {"allow_warning": "yes"}, {"high_proceed": True}, {"no_such": .5}):
            with pytest.raises((ValueError, TypeError)):
                k.set_confidence_policy("customer-a", bad)

        f = tmp_path / "policy.json"
        f.write_text(json.dumps({"confidence": {
            "default": {"high_proceed": .92},
            "tenants": {"customer-b": {"high_floor": .9}}}}))
        applied = k.load_policy_file(f)
        assert k.confidence_policy("customer-b").high_proceed == .92      # default inherited
        assert k.confidence_policy("customer-b").high_floor == .9         # tenant override
        assert set(applied) == {"customer-a", "customer-b"}
    run(t())


def test_agents_cannot_reach_policy_configuration(run):
    async def t():
        k = make_kernel()
        a = agent(k)
        for op in ("policy.set", "confidence.policy.set", "kernel.set_confidence_policy"):
            assert await code_of(k, a, op, args={"high_proceed": 0.0}) == "UNKNOWN_CAPABILITY"
        assert await code_of(k, a, "memory.write", "/aos/policies/confidence",
                             {"data": {"high_proceed": 0.0}}) in ("POLICY_DENIED", "UNAUTHORIZED")
    run(t())
