import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agenticos.delegation import Grant  # noqa: E402
from agenticos.kernel import Kernel  # noqa: E402

TENANT_A = "/aos/tenants/customer-a/*"
FULL = ["agent.spawn", "checkpoint.*", "ipc.*", "memory.*", "network.*", "twin.simulate",
        "model.infer", "confidence.evaluate", "approval.request", "lock.*"]


def make_kernel(db=":memory:", autostart=False, slots=3) -> Kernel:
    k = Kernel(db, slots=slots)
    k.autostart = autostart
    # alice's standing authority deliberately spans *all* routers so that tenant checks,
    # not target patterns, are what stops cross-tenant access.
    k.add_principal("alice", "customer-a", ["noc-operator"], Grant(
        capabilities=["*"], targets=["router-*"], memory_paths=[TENANT_A],
        production_write=True, budget_calls=500, budget_tokens=100_000, ttl_s=3600))
    k.add_principal("bob", "customer-a", ["noc-lead"], Grant(capabilities=[]))
    k.add_principal("carol", "customer-a", ["noc-operator"], Grant(capabilities=[]))
    k.add_principal("mallory", "customer-b", ["noc-operator"], Grant(
        capabilities=["*"], targets=["router-*"], memory_paths=["/aos/tenants/customer-b/*"],
        production_write=True, budget_calls=100, budget_tokens=10_000, ttl_s=600))
    return k


def agent(k: Kernel, principal="alice", caps=None, targets=("router-edge-01",),
          prod=False, calls=100, tokens=10_000, agent_type="test.script", params=None) -> str:
    _, aid = k.submit_intent(principal, "test", agent_type, Grant(
        capabilities=list(caps or FULL), targets=list(targets),
        memory_paths=[TENANT_A if principal != "mallory" else "/aos/tenants/customer-b/*"],
        production_write=prod, budget_calls=calls, budget_tokens=tokens), params=params)
    return aid


@pytest.fixture
def run():
    return lambda coro: asyncio.run(coro)
