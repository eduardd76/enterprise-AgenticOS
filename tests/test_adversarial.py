"""Adversarial (red-team) tests: an untrusted / prompt-injected agent sends arbitrary frames.

Every test asserts the SECURE behaviour, so a test that FAILS on the current code marks a
real, reproducible vulnerability. Tests in the "held" section are regression guards for
attacks that the kernel already resists.

In-process tests drive `k.gateway.dispatch` directly (that is exactly what `_serve` does with
an agent's frame). The two E2E tests use real agent subprocesses because the bug is in the
pipe/serve loop itself.
"""

import asyncio
import json

import pytest

from agenticos.delegation import Grant
from agenticos.errors import SyscallError
from conftest import agent, make_kernel


async def call(k, aid, op, target="", args=None, key=None):
    return await k.gateway.dispatch(aid, op, target, args if args is not None else {}, key)


async def code_of(k, aid, op, target="", args=None, key=None):
    try:
        await call(k, aid, op, target, args, key)
        return "OK"
    except SyscallError as e:
        return e.code


def spawn_args(**grant):
    g = {"capabilities": ["ipc.*", "checkpoint.*"], "budget_calls": 5, "budget_tokens": 100,
         "ttl_s": 60}
    g.update(grant)
    return {"grant": g}


async def confidence(k, aid, components=None):
    from agenticos.confidence import COMPONENTS
    ev = await call(k, aid, "network.bgp.inspect", "router-edge-01", {"neighbor": "192.0.2.1"})
    c = await call(k, aid, "confidence.evaluate", args={
        "components": components or {n: .95 for n in COMPONENTS},
        "for_op": "network.config.apply", "evidence_refs": [ev["evidence_ref"]]})
    return c["result"]


# =========================================================================================
# V1  Negative budgets in agent.spawn inflate the parent's budget  (invariant 2)
# =========================================================================================
@pytest.mark.parametrize("field", ["budget_calls", "budget_tokens"])
def test_v1_negative_child_budget_cannot_inflate_parent(run, field):
    async def t():
        k = make_kernel()
        p = agent(k, calls=20, tokens=1000)
        neg = await code_of(k, p, "agent.spawn", "test.script", spawn_args(**{field: -100_000}))
        # The parent only ever had 20 calls / 1000 tokens. A child with 50x that must be refused.
        big = await code_of(k, p, "agent.spawn", "test.script",
                            spawn_args(**{field: 50_000}))
        assert neg != "OK", "negative budget accepted (reserved_* goes negative)"
        assert big == "BUDGET_EXHAUSTED", "child received more budget than parent ever had"
    run(t())


# =========================================================================================
# V2  Global, agent-choosable message_id namespace  (invariants 4 and 7)
# =========================================================================================
def test_v2a_other_tenant_can_suppress_messages_by_preclaiming_ids(run):
    async def t():
        k = make_kernel()
        m = agent(k, "mallory", targets=("router-b-01",))
        # mallory pre-claims the predictable kernel-assigned ids in her own mailbox
        for i in range(1, 4):
            await call(k, m, "ipc.send", m, {"type": "NOISE", "message_id": f"msg-{i:04d}"})
        a1 = agent(k)
        a2 = (await call(k, a1, "agent.spawn", "test.script", spawn_args()))["result"]["agent_id"]
        r = await call(k, a1, "ipc.send", a2, {"type": "DIAGNOSIS_REQUEST", "payload": {"x": 1}})
        assert r["result"]["duplicate"] is False, "tenant-a message silently dropped as 'duplicate'"
        got = await call(k, a2, "ipc.recv", args={"timeout_s": 0.2})
        assert got["result"]["type"] == "DIAGNOSIS_REQUEST"
    run(t())


def test_v2b_message_id_is_a_cross_tenant_existence_oracle(run):
    async def t():
        k = make_kernel()
        a1 = agent(k)
        a2 = (await call(k, a1, "agent.spawn", "test.script", spawn_args()))["result"]["agent_id"]
        sent = await call(k, a1, "ipc.send", a2, {"type": "SECRET_PING"})
        mid = sent["result"]["message_id"]
        m = agent(k, "mallory", targets=("router-b-01",))
        probe = await call(k, m, "ipc.send", m, {"type": "NOISE", "message_id": mid})
        assert probe["result"]["duplicate"] is False, \
            "mallory learns that tenant-a message id exists (and her own message is dropped)"
    run(t())


def test_v2c_preclaimed_id_breaks_cancel_cascade(run):
    """Any agent (even another tenant) pre-claims the next msg id; the kernel's own
    CHILD_EXITED insert then raises IntegrityError inside cancel(), aborting the cascade."""
    async def t():
        k = make_kernel()
        p = agent(k)
        c = (await call(k, p, "agent.spawn", "test.script", spawn_args(
            capabilities=["ipc.*", "agent.spawn", "checkpoint.*"], budget_calls=20)))["result"]["agent_id"]
        g = (await call(k, c, "agent.spawn", "test.script", spawn_args()))["result"]["agent_id"]
        m = agent(k, "mallory", targets=("router-b-01",))
        for i in range(1, 6):
            await call(k, m, "ipc.send", m, {"type": "NOISE", "message_id": f"msg-{i:04d}"})
        k.cancel(c, "operator")          # must not raise
        assert k.agent(c)["state"] == "TERMINATED"
        assert k.agent(g)["state"] == "TERMINATED", "grandchild survived parent cancellation"
    run(t())


# =========================================================================================
# V3  Agents can forge kernel-originated CHILD_EXITED (SIGCHLD) messages
# =========================================================================================
def test_v3_agent_cannot_forge_kernel_message_types(run):
    async def t():
        k = make_kernel()
        p = agent(k)
        c = (await call(k, p, "agent.spawn", "test.script", spawn_args()))["result"]["agent_id"]
        code = await code_of(k, c, "ipc.send", p, {
            "type": "CHILD_EXITED", "payload": {"child": "verifier-0001", "state": "FAILED",
                                                "reason": "forged"}})
        assert code != "OK", "kernel-reserved message type accepted from an agent"
    run(t())


# =========================================================================================
# V5  memory.write can forge records in the kernel evidence namespace
# =========================================================================================
def test_v5_agent_cannot_write_kernel_evidence_namespace(run):
    async def t():
        k = make_kernel()
        a = agent(k)
        path = "/aos/tenants/customer-a/evidence/network.bgp.inspect/router-edge-01"
        code = await code_of(k, a, "memory.write", path,
                             {"data": {"neighbor": "192.0.2.1", "state": "Established"}})
        assert code == "POLICY_DENIED", "agent overwrote 'latest' device evidence"
    run(t())


# =========================================================================================
# V6  Approval package is agent-asserted (confidence + twin prediction)  (invariant 3)
# =========================================================================================
def test_v6a_single_self_reported_component_cannot_gate_production_write(run):
    async def t():
        k = make_kernel()
        a = agent(k, prod=True)
        c = await confidence(k, a, components={"intent": 1.0})   # one self-reported number
        code = await code_of(k, a, "approval.request", "router-edge-01", {
            "op": "network.config.apply", "change": {"interface": "Gi0/0/0/1", "admin": "up"},
            "confidence_ref": c["confidence_id"], "timeout_s": 0.05})
        assert code == "CONFIDENCE_INSUFFICIENT", \
            f"approval created from a 1-component self-reported confidence (got {code})"
    run(t())


def test_v6b_approval_package_shows_kernel_twin_prediction_not_agent_claim(run):
    async def t():
        k = make_kernel()
        seen = []
        k.approval_handler = lambda aid, pkg: seen.append(pkg)
        a = agent(k, prod=True)
        c = await confidence(k, a)
        bad = {"interface": "Gi0/0/0/2", "admin": "down"}   # really drops 198.51.100.1
        await code_of(k, a, "approval.request", "router-edge-01", {
            "op": "network.config.apply", "change": bad, "confidence_ref": c["confidence_id"],
            "predicted": {"regressions": []}, "rationale": "harmless, no regressions",
            "timeout_s": 0.05})
        if seen:
            assert "198.51.100.1" in json.dumps(seen[0]), \
                "human shown fabricated twin prediction; real regression hidden"
    run(t())


# =========================================================================================
# V7  Malformed agent.spawn args: priority escalation + reservation leak on crash
# =========================================================================================
def test_v7a_child_priority_cannot_exceed_parent(run):
    async def t():
        k = make_kernel()
        p = agent(k)     # priority "normal"
        r = await call(k, p, "agent.spawn", "test.script", {**spawn_args(), "priority": "critical"})
        assert k.agent(r["result"]["agent_id"])["priority"] != "critical"
    run(t())


def test_v7b_bad_role_type_does_not_leak_parent_reservation(run):
    async def t():
        k = make_kernel()
        p = agent(k, calls=20)
        try:   # attenuate() reserves budget, then create_agent() INSERT fails on a list 'role'
            await call(k, p, "agent.spawn", "test.script", {**spawn_args(), "role": ["x"]})
        except Exception:
            pass
        d = k.delegations.get(k.agent(p)["delegation_id"])
        assert d["reserved_calls"] == 0, "budget reserved for a child that was never created"
    run(t())


# =========================================================================================
# V8  Token budget overrun is never billed -> unbounded model consumption (LLM10)
# =========================================================================================
def test_v8_over_budget_tokens_are_billed(run):
    async def t():
        k = make_kernel()
        a = agent(k, tokens=10)
        args = {"task": "diagnose", "evidence": {"bgp": {"hold_time": 0, "neighbor": "x"}}}
        for _ in range(3):
            await code_of(k, a, "model.infer", args=args)
        d = k.delegations.get(k.agent(a)["delegation_id"])
        assert d["used_tokens"] >= 10, \
            f"model invoked 3x on a 10-token budget but used_tokens={d['used_tokens']}"
    run(t())


# =========================================================================================
# V9  Kernel serve loop dies on agent-controlled input -> agent stuck non-terminal,
#     no audit record, locks/reservations not released (fail-inconsistent)
# =========================================================================================
def test_v9a_oversized_frame_does_not_wedge_agent(run):
    async def t():
        k = make_kernel(autostart=True)
        a = agent(k, caps=["memory.read", "checkpoint.*"], params={"checkpoint_each": False,
                  "script": [{"op": "memory.read", "target": "/aos/tenants/customer-a/x",
                              "args": {"blob": "x" * 200_000}}]})
        try:
            state = await k.wait(a, 20)
        finally:
            await k.shutdown()
        assert state in ("COMPLETED", "FAILED", "TERMINATED"), \
            f"agent left in {state} after a >64KiB frame killed the kernel serve loop"
    run(t())


def test_v9b_exit_with_nonstring_reason_is_audited_and_cleans_up(run):
    async def t():
        k = make_kernel(autostart=True)
        a = agent(k, caps=["lock.*", "checkpoint.*"], params={"checkpoint_each": False, "script": [
            {"op": "lock.acquire", "target": "router-edge-01", "args": {"lease_s": 3600}},
            {"op": "agent.exit", "args": {"status": "completed", "reason": {"x": 1}}}]})
        try:
            await asyncio.wait_for(asyncio.shield(k.runtimes[a].done), 20)
            ev = [json.loads(r["data"]) for r in k.store.all(
                "SELECT data FROM audit WHERE event='agent.state' AND agent_id=?", (a,))]
            assert any(e["to"] in ("COMPLETED", "FAILED") for e in ev), \
                "terminal state change has no audit record"
            assert "router-edge-01" not in k.locks.holders, \
                "lock held by exited agent not released"
        finally:
            await k.shutdown()
    run(t())


# =========================================================================================
# Operator-side (not agent-reachable, but break the stated invariants)
# =========================================================================================
def test_o1_approver_must_be_same_tenant(run):
    async def t():
        k = make_kernel()
        k.add_principal("trent", "customer-b", ["noc-lead"], Grant(capabilities=[]))
        a = agent(k, prod=True)
        c = await confidence(k, a)
        req = asyncio.create_task(call(k, a, "approval.request", "router-edge-01", {
            "op": "network.config.apply", "change": {"interface": "Gi0/0/0/1", "admin": "up"},
            "confidence_ref": c["confidence_id"], "timeout_s": 2}))
        await asyncio.sleep(0.05)
        aid = k.store.one("SELECT approval_id FROM approvals")["approval_id"]
        with pytest.raises(SyscallError):
            k.approvals.decide(aid, "trent", True)     # customer-b lead approving customer-a change
        k.approvals.decide(aid, "bob", False)
        await asyncio.gather(req, return_exceptions=True)
    run(t())


def test_o2_root_grant_cannot_exceed_principal_budget_or_ttl(run):
    async def t():
        k = make_kernel()
        k.add_principal("dave", "customer-a", ["noc-operator"], Grant(
            capabilities=["*"], targets=["router-edge-01"], budget_calls=10, budget_tokens=100,
            ttl_s=60))
        with pytest.raises(SyscallError):
            k.submit_intent("dave", "x", "test.script", Grant(
                capabilities=["ipc.send"], budget_calls=1_000_000, budget_tokens=10**9,
                ttl_s=10**7))
    run(t())


# =========================================================================================
# Held: attacks the kernel resisted (regression guards; these pass today)
# =========================================================================================
@pytest.mark.parametrize("grant", [
    {"capabilities": ["*"]},
    {"capabilities": ["network.config.appl*"]},
    {"capabilities": [""]},
    {"capabilities": ["ipc.send"], "targets": ["*"]},
    {"capabilities": ["ipc.send"], "targets": ["router-*"]},
    {"capabilities": ["ipc.send"], "memory_paths": ["/aos/tenants/customer-a/../customer-b/*",
                                                    "/aos/*"]},
    {"capabilities": ["ipc.send"], "production_write": "yes"},
    {"capabilities": "ipc.send"},          # string -> list of chars
    {"capabilities": [123]},
])
def test_held_spawn_cannot_widen_scope(run, grant):
    async def t():
        k = make_kernel()
        p = agent(k, caps=["agent.spawn", "ipc.send", "checkpoint.*"])
        g = {"budget_calls": 1, "budget_tokens": 1, "ttl_s": 5, **grant}
        try:
            r = await call(k, p, "agent.spawn", "test.script", {"grant": g})
        except Exception:
            return
        d = k.delegations.get(r["result"]["delegation_id"])
        # if accepted, it must not carry anything the parent didn't have
        assert d["production_write"] == 0
        assert all(t_ == "router-edge-01" for t_ in d["targets"])
    run(t())


@pytest.mark.parametrize("ttl", [-1, float("inf"), float("nan"), 1e308])
def test_held_child_expiry_never_exceeds_parent(run, ttl):
    async def t():
        k = make_kernel()
        p = agent(k)
        pd = k.delegations.get(k.agent(p)["delegation_id"])
        try:
            r = await call(k, p, "agent.spawn", "test.script", spawn_args(ttl_s=ttl))
        except Exception:
            return
        cd = k.delegations.get(r["result"]["delegation_id"])
        assert cd["valid_until"] <= pd["valid_until"]
    run(t())


def test_held_lock_contention_is_tenant_isolated(run):
    async def t():
        k = make_kernel()
        a = agent(k)
        await call(k, a, "lock.acquire", "router-edge-01", {"lease_s": 30})
        m = agent(k, "mallory", targets=("router-b-01",))
        try:
            await call(k, m, "lock.acquire", "router-edge-01", {"timeout_s": 0.1})
        except SyscallError as e:
            assert e.code != "DEADLINE_EXCEEDED" and a not in e.message, e.message
    run(t())


@pytest.mark.parametrize("path", [
    "/aos/tenants/customer-b/x", "/aos/tenants/customer-a/../customer-b/x",
    "/aos/tenants/customer-a//x", "/aos/tenants/customer-a/./x", "/aos/policies/p",
    "aos/tenants/customer-a/x", "/aos/tenants/customer-ab/x"])
def test_held_memory_path_tricks(run, path):
    async def t():
        k = make_kernel()
        a = agent(k)
        assert await code_of(k, a, "memory.write", path, {"data": 1}) != "OK"
    run(t())


def test_held_cross_tenant_evidence_read_is_not_an_oracle(run):
    async def t():
        k = make_kernel()
        a = agent(k)
        r = await call(k, a, "network.bgp.inspect", "router-edge-01", {"neighbor": "192.0.2.1"})
        m = agent(k, "mallory", targets=("router-b-01",))
        assert await code_of(k, m, "memory.read", r["evidence_ref"]) == "NOT_FOUND"
        assert await code_of(k, m, "memory.read", "ev-9999") == "NOT_FOUND"
        assert await code_of(k, m, "ipc.send", m, {"type": "X_MSG",
                                                    "evidence_refs": [r["evidence_ref"]]}) \
            == "UNAUTHORIZED"
    run(t())


def test_held_cannot_use_other_agents_approval(run):
    async def t():
        k = make_kernel()
        a, b = agent(k, prod=True), agent(k, prod=True)
        c = await confidence(k, a)
        change = {"interface": "Gi0/0/0/1", "admin": "up"}
        req = asyncio.create_task(call(k, a, "approval.request", "router-edge-01", {
            "op": "network.config.apply", "change": change, "confidence_ref": c["confidence_id"],
            "timeout_s": 2}))
        await asyncio.sleep(0.05)
        aid = k.store.one("SELECT approval_id FROM approvals")["approval_id"]
        k.approvals.decide(aid, "bob", True)
        await req
        assert await code_of(k, b, "network.config.apply", "router-edge-01",
                             {"change": change, "approval_id": aid}, key="k1") == "POLICY_DENIED"
        assert await code_of(k, a, "network.config.apply", "router-edge-01",
                             {"change": {**change, "x": 1}, "approval_id": aid}, key="k1") \
            == "POLICY_DENIED"
        assert k.netsim.apply_count == 0
    run(t())


@pytest.mark.parametrize("frame", [
    ("network.bgp.inspect", "router-edge-01", ["neighbor"]),
    ("network.bgp.inspect", ["router-edge-01"], {"neighbor": "x"}),
    (["memory.read"], "", {}),
    ("agent.spawn", "noc.evil", {"grant": {}}),
    ("agent.spawn", "test.script", {"grant": "all"}),
])
def test_held_malformed_frames_fail_closed(run, frame):
    async def t():
        k = make_kernel()
        a = agent(k)
        op, target, args = frame
        with pytest.raises(Exception):
            await k.gateway.dispatch(a, op, target, args, None)
        assert k.netsim.apply_count == 0
    run(t())
