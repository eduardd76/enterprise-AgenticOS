# AOS-0001 Conformance Statement

```
Implementation:    aos 0.1.0 (this repository)
AOS-0001 version:  draft-0.8
Profile:           Embedded Control (experimental) + Sovereign provider rule
Test results:      81 passed (python -m pytest -q) on macOS 26 and on Linux (Debian, Docker,
                   bubblewrap) — repeated runs, Python 3.12
External deps:     Python 3.12 stdlib, SQLite; agent confinement via macOS sandbox-exec
                   or Linux bubblewrap (AOS_REQUIRE_SANDBOX=1 makes it mandatory)
```

## Invariants (AOS-0001 Appendix C)

| ID | Status | Enforced in | Remaining gap |
|---|---|---|---|
| INV-001 intent precedes execution | ✅ | `kernel.submit_intent`, `check_intent` (hash-checked per syscall) | No "system objective" actor type; hash lives beside body (unkeyed) |
| INV-002 authority chain + policy | ✅ | `delegation.validate_chain`, `policy.evaluate` every call | Principals in memory, not persisted |
| INV-003 declared capability contract | ✅ | `registry.get`, required args, output keys | Contracts are key-level, no schemas/versions |
| INV-004 non-expanding delegation | ✅ | `delegation.attenuate` (+ type validation), priority clamp, root clamp to principal, settle forwarding | `retry_budget` not attenuated |
| INV-005 hard constraints before utility | ✅ | gateway: policy → `registry.select` feasibility → ranking | — |
| INV-006 decisions vs actions traceable | ◐ | separate `policy.evaluated` / `syscall.*` audit events with shared ids | No `decision_id` join key, no persisted ExecutionDirective |
| INV-007 monotonic history | ✅ | hash-chained `audit`, `agent_history`, failed attempts retained | Chain unkeyed; no external anchor |
| INV-008 confidence → control action | ◐ | kernel derives impact/reversibility from manifest; full vector + evidence required for consequential ops; bound to op+agent | ESCALATE/TERMINATE advisory except at the approval gate; FALLBACK never emitted |
| INV-009 obligations never dropped | ❌ | obligations emitted + audited only | No obligation tracking (e.g. post-change verification is done by user-space verifier, not enforced) |
| INV-010 declare unsupported | ✅ | this file | — |

## vExpertAI kernel invariants (§7)

| Invariant | Status | Test |
|---|---|---|
| No tool execution without validated capability | ✅ | `test_unknown_capability_*`, `test_ungranted_*` |
| No delegated task gets more authority | ✅ | `test_child_cannot_exceed_parent[*]`, `test_v1_*`, `test_child_priority_clamped_*` |
| No production write without approval + current-state validation | ✅ | `test_production_write_*`, `test_stale_state_*`, `test_approved_change_*` |
| No cross-tenant memory access | ✅ | `test_cross_tenant_*`, `test_v2*`, `test_o1_*` |
| Every consequential action has identity + evidence chain | ✅ | approval package (kernel-computed twin/diff/rollback), `test_audit_chain_*` |
| Retry never silently repeats non-idempotent change | ✅ | `test_started_but_unfinished_*`, demo crash-after-apply, timeout → `PARTIAL_SIDE_EFFECT` |
| LLM output can't modify enforcement rules | ✅ | `test_protected_namespaces_*`, `test_sandbox_blocks_direct_access_*` |

## Lifecycle mapping (Table 17)

The A-PCB is a **process** lifecycle (vExpertAI §3.A): CREATED, READY, RUNNING, WAITING(reason),
SUSPENDED, COMPLETED, FAILED, TERMINATED. Table 17 is an **intent/work** lifecycle. The two are
orthogonal layers. v0.1 implements the process layer only, so **COMPLETED means the agent
declared success. It does not mean the kernel checked the success criteria.**

## How this was hardened

Three specialist reviews ran against v0.1-rc. Each confirmed finding became a regression test:
- **Security red-team (15 exploits):** negative-budget inflation, global message-id suppression,
  forged kernel messages, forged evidence, an agent-asserted approval package, cross-tenant
  approvers, and serve-loop wedging, among others. All of these now fail closed
  (`tests/test_adversarial.py`).
- **Concurrency review (13 bugs):** budget loss when a parent settles before its children,
  write timeouts treated as "no side effect", approvals burned before the budget charge,
  agent death during a wait going undetected, lazy suspension, channel desync, the EDF
  tie-break, and recovering an agent stuck in CREATED. All are fixed; regressions are in
  `test_invariants.py` and `test_processes.py`.
- **Architecture conformance review:** source of the tables above.

## Unsupported / not yet implemented

- **Intent lifecycle (Table 17).** No success-criteria evaluation and no reconciliation task for
  `PARTIAL_SIDE_EFFECT`.
- **Obligation tracking (INV-009) and persisted ExecutionDirective with `decision_id` (INV-006).**
- **Keyed (HMAC) audit chain with external anchoring.**
- **Syscall filtering and resource limits.** Linux confinement uses bubblewrap namespaces
  only: no seccomp filter and no cgroup or rlimit caps yet. Hosts without a sandbox fall back to
  process isolation (recorded as `isolation="process"`) unless `AOS_REQUIRE_SANDBOX` is set.
- **IPC/approval waits in the deadlock wait-for graph.** Lock leases have no fencing tokens.
- **TrustDecision and CapabilityQuery objects.** No federation, cross-region scheduling or HA.
- **Real FRR/Containerlab drivers (vExpertAI Phase 3).** The local-LLM provider exists but is
  untested against a live server.
- **Comparative benchmark against a plain LangGraph implementation (vExpertAI §9).** Not done.
  It is the experiment that decides whether the OS abstraction pays for itself.

## Recommended v0.2 order

1. HMAC the audit chain; add seccomp and cgroup limits to the Linux sandbox.
2. Obligation tracking, plus a persisted directive and `decision_id`.
3. Intent lifecycle with kernel-checked success criteria.
4. The LangGraph comparative benchmark, using the fault-injection harness that already exists.
5. Real FRR drivers.
