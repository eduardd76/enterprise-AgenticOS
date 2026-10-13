"""The syscall gateway — the only path from an agent to any capability (vExpertAI §3.E).

    1. authenticate        agent id is bound to the kernel-owned pipe, never self-asserted
    2. lifecycle + intent  agent live; originating intent exists and is unmodified (INV-001)
    3. capability          op is a declared capability contract (INV-003)
    4. authority           delegation chain valid; op/target inside the grant (INV-004)
    5. policy + budget     deterministic decision before any optimisation (INV-005)
    6. provider selection  feasibility first, then ranking, with bounded fallback
    7. invoke + evidence   idempotency guard, output validation, evidence + audit (INV-006/007)
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

from . import policy
from .delegation import matches
from .errors import SyscallError
from .registry import CallContext
from .store import sha256

if TYPE_CHECKING:
    from .kernel import Kernel

TERMINAL = {"COMPLETED", "FAILED", "TERMINATED"}
PROVIDER_TIMEOUT_S = 30.0


class Gateway:
    def __init__(self, kernel: "Kernel"):
        self.k = kernel
        self.stats = {"allowed": 0, "denied": 0, "unknown_capability": 0, "replayed": 0}

    async def dispatch(self, agent_id: str, op: str, target: Any = "", args: Any = None,
                       idempotency_key: str | None = None) -> dict:
        k = self.k
        agent = k.agent(agent_id)                                        # 1
        audit_ids = dict(agent_id=agent_id, intent_id=agent["intent_id"],
                         delegation_id=agent["delegation_id"])
        args = {} if args is None else args
        idem, invoked = None, False   # invoked: a provider returned, so side effects may exist
        try:
            if not isinstance(op, str) or not isinstance(target, str) or not isinstance(args, dict):
                raise SyscallError("INVALID_REQUEST", "op/target must be strings, args an object")
            if agent["state"] in TERMINAL:                               # 2
                raise SyscallError("UNAUTHORIZED", f"agent is {agent['state']}")
            k.check_intent(agent["intent_id"])
            cap = k.registry.get(op)                                     # 3
            missing = [a for a in cap.required_args if a not in args]
            if missing:
                raise SyscallError("INVALID_REQUEST", f"{op} missing args {missing}")

            d = k.delegations.validate_chain(agent["delegation_id"])     # 4
            if d["tenant"] != agent["tenant"]:
                raise SyscallError("UNAUTHORIZED", "delegation tenant mismatch")
            if not any(matches(p, op) for p in d["capabilities"]):
                raise SyscallError("UNAUTHORIZED", f"capability '{op}' not granted")
            if cap.target_kind == "device" and not any(matches(p, target) for p in d["targets"]):
                raise SyscallError("UNAUTHORIZED", f"target '{target}' not granted")

            target_tenant = k.netsim.tenant_of(target) if cap.target_kind == "device" else None
            decision = policy.evaluate(cap, agent, d, target, args, target_tenant)   # 5
            k.store.audit("policy.evaluated", op=op, target=target, **decision.to_dict(),
                          **audit_ids)
            if decision.outcome == "deny":
                raise SyscallError("POLICY_DENIED", f"[{decision.rule}] {decision.rationale}")
            if decision.outcome == "approve":
                raise SyscallError("APPROVAL_REQUIRED", f"[{decision.rule}] {decision.rationale}")

            if not cap.idempotent:
                if not idempotency_key:
                    raise SyscallError("INVALID_REQUEST", f"{op} is non-idempotent: idempotency_key required")
                if not isinstance(idempotency_key, str) or len(idempotency_key) > 128:
                    raise SyscallError("INVALID_REQUEST", "idempotency_key must be a short string")
                idem = self.idem_key(agent, op, idempotency_key, target, args)
                prior = k.store.one("SELECT * FROM idempotency WHERE key=?", (idem,))
                if prior is not None:
                    return self._replay(prior, op, target, audit_ids)
            k.delegations.charge(agent["delegation_id"], calls=1, tokens=0)
            if cap.consequential:      # after charging, so a budget failure can't burn approval
                k.approvals.consume(args["approval_id"], agent, op, target, args)
            if op == "model.infer" and k.delegations.remaining(
                    k.delegations.get(agent["delegation_id"]))[1] <= 0:
                raise SyscallError("BUDGET_EXHAUSTED", "no token budget left for inference")
            if idem:
                k.store.exec("INSERT INTO idempotency(key, agent_id, op, target, status, ts)"
                             " VALUES (?,?,?,?, 'started', strftime('%s','now'))",
                             (idem, agent_id, op, target))

            providers, rejected = k.registry.select(cap, policy.REQUIRE_ON_PREM)     # 6
            ctx = CallContext(kernel=k, agent=agent, delegation=d, op=op)
            result, used, failures = None, None, []
            for p in providers:
                try:
                    timeout = None if p.id == "kernel" else p.timeout_s
                    result = await asyncio.wait_for(p.fn(ctx, target, args), timeout)
                    used, invoked = p.id, True
                    break
                except SyscallError as e:
                    if e.code != "PROVIDER_ERROR":
                        raise
                    failures.append({"provider": p.id, "error": e.message})
                except asyncio.TimeoutError:
                    failures.append({"provider": p.id, "error": "timeout"})
                    if not cap.idempotent:   # may have committed: never fall back or retry
                        invoked = True
                        raise SyscallError("PARTIAL_SIDE_EFFECT",
                                           f"{op} on {target} timed out; outcome unknown")
            if used is None:
                raise SyscallError("PROVIDER_ERROR", f"all providers failed: {failures}")

            tokens = int(result.pop("_tokens", 0))                       # 7
            if tokens:
                k.delegations.charge(agent["delegation_id"], calls=0, tokens=tokens,
                                     bill_overrun=True)
            absent = [key for key in cap.output_keys if key not in result]
            if absent:
                raise SyscallError("PROVIDER_ERROR", f"{used} output missing {absent}")

            evidence_ref = None
            if used != "kernel":   # kernel services are not external evidence
                evidence_ref = k.memory.record_evidence(
                    agent["tenant"], f"/aos/tenants/{agent['tenant']}/evidence/{op}/{target or '_'}",
                    result, {"op": op, "target": target, "provider": used, "agent": agent_id,
                             "intent_id": agent["intent_id"], "delegation_id": agent["delegation_id"],
                             "policy_version": decision.version, "args_hash": sha256(args)})
            response = {"result": result, "evidence_ref": evidence_ref, "provider": used,
                        "policy": decision.to_dict()}
            if idem:
                k.store.exec("UPDATE idempotency SET status='done', result=? WHERE key=?",
                             (json.dumps(response, default=str), idem))
            self.stats["allowed"] += 1
            k.store.audit("syscall.allowed", op=op, target=target, provider=used,
                          rejected_providers=rejected, provider_failures=failures,
                          evidence_ref=evidence_ref, tokens=tokens,
                          consequential=cap.consequential, args_hash=sha256(args), **audit_ids)
            return response
        except SyscallError as e:
            if idem and not invoked and e.code != "PARTIAL_SIDE_EFFECT":
                # Driver contract: providers fail atomically, so an error before any provider
                # returned means no side effect happened and a retry is safe. After a provider
                # returned, the 'started' record stays and any retry escalates instead.
                k.store.exec("DELETE FROM idempotency WHERE key=? AND status='started'", (idem,))
            self.stats["denied"] += 1
            if e.code == "UNKNOWN_CAPABILITY":
                self.stats["unknown_capability"] += 1
            k.store.audit("syscall.denied", op=op if isinstance(op, str) else repr(op),
                          target=target if isinstance(target, str) else repr(target),
                          code=e.code, reason=e.message, **audit_ids)
            raise
        except Exception:
            if idem and not invoked:                   # provider bug before any side effect
                k.store.exec("DELETE FROM idempotency WHERE key=? AND status='started'", (idem,))
            raise

    @staticmethod
    def idem_key(agent: dict, op: str, key: str, target: str, args: dict) -> str:
        """Scoped to intent+agent+op and bound to the exact target/change it was issued for."""
        bound = sha256({"target": target, "change": args.get("change")})[:16]
        return f"{agent['intent_id']}:{agent['agent_id']}:{op}:{key}:{bound}"

    def _replay(self, prior, op: str, target: str, audit_ids: dict) -> dict:
        if prior["status"] == "done":
            self.stats["replayed"] += 1
            self.k.store.audit("syscall.replayed", op=op, target=target, key=prior["key"],
                               **audit_ids)
            response = json.loads(prior["result"])
            response["replayed"] = True
            return response
        # 'started' with no completion: the kernel died mid-call. Never guess — escalate.
        raise SyscallError("PARTIAL_SIDE_EFFECT",
                           f"{op} on {target} may have executed (key {prior['key']}); "
                           "human reconciliation required")
