# AOS Kernel v0.1 — MVP Design

Sources: *AOS-0001, The Agent Operating System* (arXiv 2608.03214, draft 0.8), and a vExpertAI
design note that maps Tanenbaum's *Modern Operating Systems* onto agents. That note is not
published; its relevant content is reproduced in the appendix below. Code comments cite it as
"vExpertAI §N". This MVP is the note's "Kernel v0.1 with a BGP troubleshooting agent"
milestone, built against the AOS-0001 invariants (Appendix C) under the **Embedded Control**
conformance profile (Appendix E).

## 1. What the MVP must prove

| # | Claim | Source |
|---|-------|--------|
| 1 | Agents are isolated processes that cannot touch the world except through syscalls | vExpertAI §9.1, §3.H |
| 2 | Every tool call passes a deterministic 7-step gateway; unauthorized calls are denied | vExpertAI §3.E, INV-002/003 |
| 3 | Delegation never expands authority (scope, budget, lifetime) | INV-004, eq. (6)–(8) |
| 4 | Shared evidence memory is permissioned per tenant | vExpertAI §3.C/D, §9.3 |
| 5 | A crashed agent is recovered from checkpoint without repeating non-idempotent changes | vExpertAI §9.4, kernel invariants |
| 6 | Production writes need approval + confidence + current-state revalidation | vExpertAI §4.6, §7 invariants |
| 7 | Every action is reconstructable from a tamper-evident audit chain, per delegation | INV-006/007, §14.9 |
| 8 | Phase-1 exit test: start / suspend / resume / cancel a NOC agent | vExpertAI §6 Phase 1 |

## 2. Architecture (logical OS on Linux/macOS, not a kernel replacement)

```
 USER SPACE (untrusted, one OS process per agent, scrubbed env, no credentials)
   noc.coordinator   noc.bgp_diag   noc.change   noc.verifier
          │  JSON-lines syscalls over stdin/stdout (identity bound to the pipe)
 ─────────┼──────────────────────────────────────────────────────────────────
 AOS KERNEL (trusted, deterministic)                       agenticos/kernel.py
   Control & Governance plane          Runtime & Coordination plane
   ├─ intents (immutable, hashed)      ├─ lifecycle state machine (A-PCB)
   ├─ delegation (attenuation,         ├─ scheduler (priority + deadline + aging)
   │   budgets, revocation)            ├─ IPC (typed, deduped, deadlines, acks)
   ├─ policy engine (versioned rules)  ├─ lock manager (leases, cycle detection)
   ├─ confidence → control action      ├─ checkpoints + crash recovery
   ├─ approvals (single-use, bound)    └─ evidence store /aos/tenants/<t>/...
   └─ hash-chained audit log
   SYSCALL GATEWAY  (agenticos/gateway.py) — the only path to any capability provider
 ─────────┼──────────────────────────────────────────────────────────────────
 PLATFORM (external): SQLite, drivers (simulated FRR network + digital twin),
                      model providers (mock-local, optional OpenAI-compatible local LLM)
```

Both planes run in one process (Embedded profile, AOS-0001 §13.2): the separation is logical —
`PolicyDecision`, directive and observed `ExecutionEvent` are separate audit records.

## 3. The syscall gateway (vExpertAI §3.E → code)

`gateway.dispatch(agent, op, target, args, idempotency_key)`:

1. **Authenticate** — agent id comes from the pipe the kernel created, never from the message.
2. **Lifecycle + intent** — agent must be live; its intent must exist and hash-match (INV-001).
3. **Capability** — `op` must be a registered capability (INV-003); unknown ops are counted as hallucinated tool requests.
4. **Authority** — delegation chain valid (not expired/revoked); op and target within scope; tenant match.
5. **Policy + budget** — versioned deterministic rules → allow / deny / require-approval + obligations; budget charged atomically.
6. **Feasibility, then ranking** — infeasible providers removed before utility ranking (INV-005); fallback on provider failure.
7. **Idempotency + invoke + evidence** — non-idempotent ops need an idempotency key; a key whose previous attempt
   never completed returns `PARTIAL_SIDE_EFFECT` instead of re-executing. Results are stored as versioned evidence with provenance.

## 4. Agent lifecycle (A-PCB)

```
CREATED → READY ⇄ RUNNING ⇄ WAITING(reason: ipc | approval | lock)
            ↑   ↘    ↓         ↓
            └── SUSPENDED ←────┘
RUNNING → COMPLETED | FAILED ;  any non-terminal → TERMINATED (cancel/revoke)
RUNNING/WAITING → READY on crash (restart from checkpoint while retry_budget > 0)
```
Suspension is real: the process gets SIGSTOP and gives up its scheduler slot immediately. On
resume it gets SIGCONT and has to be rescheduled before its next syscall is served. When an agent
finishes, any of its descendants still running are terminated, deepest first, so no orphan keeps
spending.

## 4b. Confinement (macOS Seatbelt / Linux bubblewrap)

Agent processes run under a Seatbelt profile (macOS) or bubblewrap (Linux: read-only root,
tmpfs over kernel state, no network namespace, own PID namespace) with no network, no file writes, and no read access
to the kernel's state directory. Their working directory is empty and their environment is
scrubbed. The syscall channel lives on a dup'd fd, so stray writes to stdout cannot inject frames.
The kernel pipe is the only way out.

## 5. Kernel invariants → enforcement points

| Invariant | Enforced in |
|-----------|-------------|
| No tool execution without a validated capability | `gateway` steps 3–4 |
| No delegated task receives more authority than granted | `delegation.attenuate` |
| No production write without approval + current-state validation | `policy` + `approvals.consume` + driver `state_hash` |
| No cross-tenant memory access | `memory` path check + IPC evidence-ref check |
| Every consequential action has identity + evidence chain | `audit` (hash-chained) + approval package |
| Retry never silently repeats a non-idempotent change | `gateway` idempotency table |
| LLM output may propose but not modify enforcement rules | policy is code/data loaded at boot; no capability writes `/aos/policies` |

## 5b. Risk appetite is operator policy

`ConfidencePolicy` (agenticos/confidence.py) holds the thresholds that turn a confidence
vector into an action. The operator sets them per tenant, via `Kernel.set_confidence_policy`
or a JSON file (`--policy`); no syscall exists to change them. Each policy has a
content-hash version, and every confidence record and `policy.confidence.set` audit event
carries it, so any decision can be replayed against the exact rules that produced it.

## 6. Explicit non-goals for v0.1 (declared per INV-010)

Federation, cross-region scheduling, kernel-level assurance (seccomp/cgroups), containers/microVMs,
real FRR/Containerlab, Temporal/NATS/OPA integration, multi-host HA, and the LangGraph comparative
benchmark (vExpertAI §9). See `CONFORMANCE.md`.

## Appendix: the Tanenbaum mapping (vExpertAI design note, reproduced)

| Traditional OS | Agentic OS equivalent | Here |
|---|---|---|
| Process | Autonomous agent execution | sandboxed subprocess + A-PCB (`agents` table) |
| CPU scheduler | Agent and inference scheduler | `scheduler.py` (priority, aging, EDF) |
| Virtual memory | Isolated context and memory space | tenant/grant-scoped `memory.*` |
| File system | Persistent knowledge and artifacts | `/aos/tenants/<t>/...` namespace, versioned evidence |
| Device drivers | Connectors and tool adapters | `drivers/` behind capability providers |
| System calls | Controlled agent action API | `gateway.py` |
| IPC | Typed agent-to-agent messaging | `ipc.*` (typed, deduped, deadlines, acks) |
| Process isolation | Sandbox and capability boundaries | Seatbelt / bubblewrap + delegation |
| Deadlock management | Dependency and lock manager | `locks.py` (leases, cycle detection) |
| Kernel security | Identity, authorization, policy | pipe-bound identity, `policy.py`, approvals |

Note sections cited in code: §3.A process management, §3.B scheduling, §3.C memory levels
(L1 context, L2 working/checkpoints, L3 persistent knowledge, L4 authoritative sources),
§3.D namespace, §3.E syscalls (the 7-step dispatcher), §3.F IPC, §3.G deadlock, §3.H
microkernel-style security, §4 AI NOC scenario, §6 phased build plan, §7 kernel invariants
(table in §5 above), §9 first milestone and the baseline-benchmark requirement.
