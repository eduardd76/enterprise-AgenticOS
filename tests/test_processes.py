"""End-to-end tests with real agent subprocesses: isolation, crash recovery, kernel restart."""

import asyncio
import json

from agenticos.cli import demo, lifecycle
from conftest import agent, make_kernel

STEP = {"op": "network.bgp.inspect", "target": "router-edge-01", "args": {"neighbor": "192.0.2.1"}}
CAPS = ["network.bgp.inspect", "checkpoint.*", "memory.read"]


def test_agent_process_has_no_ambient_credentials(run, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret")
    monkeypatch.setenv("ROUTER_PASSWORD", "hunter2")

    async def t():
        k = make_kernel(autostart=True)
        k.agent_types["test.envprobe"] = "tests.envprobe:EnvProbe"
        a = agent(k, caps=CAPS, agent_type="test.envprobe")
        assert await k.wait(a, 20) == "COMPLETED"
        seen = json.loads(k.agent(a)["result"])
        assert "ANTHROPIC_API_KEY" not in seen["env"] and "ROUTER_PASSWORD" not in seen["env"]
        assert set(seen["env"]) <= {"PATH", "PYTHONPATH", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE", "__CF_USER_TEXT_ENCODING",
                                    "LC_CTYPE", "PWD"}
        await k.shutdown()
    run(t())


def test_crashed_agent_restarts_from_checkpoint(run):
    async def t():
        k = make_kernel(autostart=True)
        a = agent(k, caps=CAPS, params={"script": [STEP, {"crash_once": True}, STEP]})
        assert await k.wait(a, 30) == "COMPLETED"
        res = json.loads(k.agent(a)["result"])["results"]
        assert [r.get("ok", r.get("recovered")) for r in res] == [True, True, True]
        assert k.agent(a)["restarts"] == 1
        await k.shutdown()
    run(t())


def test_retry_budget_exhaustion_fails_agent(run):
    async def t():
        k = make_kernel(autostart=True)
        a = agent(k, caps=CAPS, params={"script": [STEP], "checkpoint_each": True})
        k.runtimes[a].crash_plan = {"op": "network.bgp.inspect", "nth": 1, "seen": 0}
        # crash on every attempt: re-arm the plan whenever the agent is re-admitted
        def rearm(kind, d):
            if kind == "state" and d["agent_id"] == a and d["to"] == "RUNNING":
                k.inject_crash(a, "network.bgp.inspect")
        k.on_event = rearm
        assert await k.wait(a, 30) == "FAILED"
        assert k.agent(a)["restarts"] == 3          # retry_budget=2 -> third crash is final
        await k.shutdown()
    run(t())


def test_kernel_restart_recovers_agents(run, tmp_path):
    db = tmp_path / "agenticos.db"

    async def phase1():
        k = make_kernel(db, autostart=True)
        a = agent(k, caps=CAPS, params={"script": [STEP, {"sleep": 0.2}] * 8})
        await asyncio.sleep(0.8)
        await k.shutdown()                           # simulated kernel crash mid-run
        return a

    async def phase2(a):
        k = make_kernel(db, autostart=True)
        assert k.agent(a)["state"] in ("RUNNING", "WAITING", "READY")
        assert a in await k.recover()
        assert await k.wait(a, 30) == "COMPLETED"
        assert len(json.loads(k.agent(a)["result"])["results"]) == 16
        assert k.store.verify_audit()[0]
        await k.shutdown()

    a = asyncio.run(phase1())
    asyncio.run(phase2(a))


def test_demo_end_to_end(tmp_path):
    assert asyncio.run(demo(str(tmp_path / "demo.db"), interactive=False)) == 0


def test_phase1_lifecycle_exit_test(tmp_path):
    assert asyncio.run(lifecycle(str(tmp_path / "lc.db"))) == 0


def test_sandbox_blocks_direct_access_around_the_gateway(run, tmp_path):
    import sys
    from pathlib import Path

    import pytest
    from agenticos.kernel import detect_isolation
    if detect_isolation() == "process":
        pytest.skip("no sandbox available on this host (needs sandbox-exec or bwrap)")
    db = tmp_path / "state" / "agenticos.db"

    async def t():
        k = make_kernel(db, autostart=True)
        assert k.isolation in ("seatbelt", "bwrap")
        k.agent_types["test.escape"] = "tests.escape:Escape"
        a = agent(k, caps=CAPS, agent_type="test.escape",
                  params={"db": str(db), "project": str(Path(__file__).resolve().parent.parent)})
        assert await k.wait(a, 30) == "COMPLETED"
        out = json.loads(k.agent(a)["result"])
        assert "ESCAPED" not in out.values(), out
        assert out["cwd_listing"] == []
        await k.shutdown()
    run(t())


def test_suspend_frees_slot_immediately_and_freezes_process(run):
    """Reviewer bug #8: suspension is SIGSTOP + slot release, not 'at the next syscall'."""
    async def t():
        k = make_kernel(autostart=True, slots=1)
        a = agent(k, caps=CAPS, params={"script": [STEP, {"sleep": 3}, STEP]})
        await asyncio.sleep(0.6)                       # a is inside its 3 s step
        k.suspend(a)
        b = agent(k, caps=CAPS, params={"script": [STEP]})
        assert await k.wait(b, 2) == "COMPLETED"      # b got the only slot while a is frozen
        k.resume(a)
        assert await k.wait(a, 10) == "COMPLETED"
        await k.shutdown()
    run(t())


def test_death_during_blocking_wait_detected_promptly(run):
    """Reviewer bug #7: a SIGKILL while parked in ipc.recv is noticed at once, not at timeout."""
    import time

    async def t():
        k = make_kernel(autostart=True)
        a = agent(k, caps=CAPS + ["ipc.*"], params={"script": [
            {"op": "ipc.recv", "args": {"timeout_s": 20}}], "checkpoint_each": False})
        await asyncio.sleep(0.6)
        assert k.agent(a)["state"] == "WAITING"
        t0 = time.monotonic()
        k.runtimes[a].proc.kill()
        while k.agent(a)["restarts"] == 0 and time.monotonic() - t0 < 5:
            await asyncio.sleep(0.05)
        assert time.monotonic() - t0 < 2
        await k.shutdown()
    run(t())
