# Enterprise AgenticOS

**An operating-system kernel for governing AI agents in production infrastructure.**

LLM agents are good at reasoning and bad at being trusted. Enterprise AgenticOS keeps them
apart. Agents run as **sandboxed OS processes** with no credentials, no network and no
filesystem access. Their only channel to the world is a **syscall pipe** into a small,
deterministic kernel. The kernel owns identity, authority, policy, scheduling, memory,
evidence and recovery. Models *propose*; the kernel decides what actually happens, and
records why.

> **Status: v0.1 design-partner preview.** The architecture works end to end and has been
> red-teamed, but it is not production-hardened yet. See [SECURITY.md](SECURITY.md) and
> [CONFORMANCE.md](CONFORMANCE.md). If you operate regulated or sovereign infrastructure and
> want to shape the roadmap, open a discussion.

## Why an OS, not another agent framework

Agent frameworks run the reasoning loop. They don't answer the questions that block
production use:

| Question your CISO asks | AgenticOS answer |
|---|---|
| Can a prompt-injected agent touch production? | Only through granted capabilities. Writes need a single-use human approval bound to the exact change, plus a device state re-check. |
| Can a sub-agent get more power than its parent? | No. Delegation narrows scope, budget, lifetime and priority, and every syscall checks it. |
| Can tenant A's agent see tenant B's data? | No. Memory, IPC, evidence, devices and locks are all tenant-scoped. There is no existence oracle. |
| What if an agent crashes mid-change? | It restarts from its checkpoint. Non-idempotent changes never run twice; an unknown outcome escalates to a human. |
| Can we prove what happened? | Yes. A hash-chained audit log, and per-delegation reconstruction of every action. |
| Does the LLM decide its own confidence? | No. The kernel derives impact from the capability manifest and maps evidence to an action. |

## Quick start

```bash
git clone https://github.com/eduardd76/enterprise-AgenticOS && cd enterprise-AgenticOS
python3 -m pip install -e '.[dev]'          # Python >= 3.12, zero runtime dependencies
python3 -m agenticos demo                   # AI NOC: BGP down -> diagnose -> approve -> fix -> verify
python3 -m agenticos demo --interactive     # you are the approving NOC lead
python3 -m agenticos lifecycle              # start / suspend / resume / cancel
python3 -m agenticos ps                     # process table of the last run
python3 -m agenticos audit --lineage del-0001   # verify audit chain + actions under a delegation
python3 -m pytest -q                        # 81 conformance, red-team and process tests
```

Sandboxing is automatic on macOS (`sandbox-exec`) and on Linux with `bubblewrap` installed.
Set `AOS_REQUIRE_SANDBOX=1` to refuse to run agents unsandboxed.

## What the demo shows

1. A fault is injected: `router-edge-01` loses BGP neighbor `192.0.2.1`.
2. Operator *alice* submits an **immutable intent**. The kernel creates a root **delegation**
   and starts a coordinator agent.
3. The coordinator spawns a diagnosis agent with a **narrower grant** (read-only, one device).
   The kernel **kills it mid-investigation**; it restarts from its **checkpoint**.
4. The model suggests "just apply the fix". The agent tries, and the kernel returns
   `UNAUTHORIZED`.
5. A change agent runs the fix on a **digital twin**, gets a kernel-computed **confidence
   decision**, and requests **approval**. The review package shows the kernel's own twin
   prediction, diff and rollback, not the agent's claims.
6. *bob* (`noc-lead`, a different person from the requester) approves. The kernel re-checks
   device state and applies the change, then **kills the agent before the reply arrives**. The
   retry gets the recorded result, so the change runs **exactly once**.
7. An independent verifier confirms recovery; the incident report is written to tenant memory.
8. A tenant-B agent probes tenant A's report and router: both are denied. The audit chain
   verifies.

## Architecture

```
 USER SPACE (untrusted)   one sandboxed process per agent, no credentials
        │ JSON syscalls over a kernel-owned pipe (caller identity = the pipe)
 KERNEL (trusted, deterministic)
   Control & Governance        Runtime & Coordination
   intents · delegation        lifecycle · scheduler · IPC · locks
   policy · confidence         checkpoints · crash/kernel-restart recovery
   approvals · audit chain     tenant-scoped evidence memory
   ── 7-step syscall gateway: the only path to any capability ──
 PLATFORM   drivers (network, digital twin) · model providers · SQLite
```

It implements the two-plane reference architecture of **AOS-0001** (*The Agent Operating
System*, Sharma & Shah, [arXiv:2608.03214](https://arxiv.org/abs/2608.03214)), with OS
mechanisms modelled on Tanenbaum's *Modern Operating Systems*. This is an independent
implementation, not affiliated with the spec authors. Details:
[docs/DESIGN.md](docs/DESIGN.md); conformance and gaps: [CONFORMANCE.md](CONFORMANCE.md).

```
agenticos/kernel.py      process manager, lifecycle state machine, sandboxing, recovery
agenticos/gateway.py     the syscall gateway (single enforcement path)
agenticos/delegation.py  attenuation, atomic budgets, cascading revocation
agenticos/policy.py      deterministic, versioned policy rules
agenticos/confidence.py  confidence vector -> control action
agenticos/services.py    kernel services: memory, IPC, checkpoints, spawn, approvals, locks
agenticos/scheduler.py   priority + aging + EDF over reasoning slots
agenticos/registry.py    capability contracts, feasibility-then-ranking provider selection
agenticos/store.py       durable state + hash-chained audit
agenticos/drivers/       simulated network + digital twin, model providers
agenticos/agents/        example NOC agents (user space)
```

## Roadmap to 1.0

These are the enterprise-adoption priorities; see `CONFORMANCE.md` for detail.

1. **Run on your stack:** PostgreSQL store, container image + Helm, seccomp/cgroup limits.
2. **Integrate, don't replace:** OPA policy adapter, OpenTelemetry export, Vault/SPIFFE
   identity, SSO approvers.
3. **Approvals where people work:** Slack, Teams, ServiceNow.
4. **Compliance evidence:** keyed audit chain; mappings to NIST AI RMF, ISO/IEC 42001 and the
   EU AI Act (Art. 12, Art. 14).
5. **Proof:** an open benchmark against a plain agent-framework baseline, using the built-in
   fault injection.
6. **Stability:** versioned SDK API, semver, LTS.

## Limits of v0.1 (honest list)

- The network is simulated (FRR/Containerlab drivers are planned).
- The model is a deterministic mock; the OpenAI-compatible local-LLM provider is untested
  against a live server.
- Single process: no HA or federation.
- The audit chain is not keyed yet.
- The baseline benchmark has not been run.

## Contributing and license

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities
privately via [SECURITY.md](SECURITY.md). Licensed under [Apache-2.0](LICENSE).
Copyright 2026 vExpertAI. Commercial drivers, agents and support are available from vExpertAI.
