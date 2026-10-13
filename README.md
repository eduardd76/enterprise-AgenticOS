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

## How it helps enterprises

**In one sentence:** AgenticOS lets an enterprise use AI agents on its real production systems
(networks, servers, security tools) without the AI being able to cause damage, and with proof
of everything it did.

### The problem enterprises have today

Companies want AI agents to do real operations work: fix a network outage at 3am, investigate a
security alert, change a configuration. The AI is often good enough. But the security officer,
the compliance team and the network manager all say **no**, for four reasons:

1. **"What if it does something stupid?"** Models sometimes invent answers or get manipulated by
   malicious input (prompt injection). If the agent holds the router passwords, one bad answer
   can take down the network.
2. **"Who allowed this?"** Auditors and regulators ask who authorised a production change, why,
   and based on what evidence. Most agent tools keep chat logs, not proof.
3. **"Can customer A's AI see customer B's data?"** Service providers and large companies run many
   customers or business units on shared systems.
4. **"What happens when it fails halfway?"** If the agent crashes mid-change, did the change happen
   once, twice, or not at all?

So most AI agents stay read-only assistants, and the real value, automated operations, stays
locked up.

### What AgenticOS does about it

It sits **between the AI agents and the production systems** as a control layer:

| Enterprise concern | What AgenticOS does |
|---|---|
| AI doing something stupid | Agents never hold passwords or direct access. Every action is checked against what that agent is allowed to do, and an unapproved action is simply refused. |
| Risky changes | A production change must be tested on a simulated copy of the network, pass a confidence check, and be approved by a named human. The device is re-checked right before the change. |
| Who allowed this? | Every action is recorded with who requested it, who approved it, what evidence was used and what happened, in a tamper-evident log. |
| Customer separation | One customer's agents can't see or touch another customer's devices, data or messages. |
| Crashes mid-change | A crashed agent restarts where it stopped; a change is never applied twice. |
| Different risk tolerance | Each customer sets how cautious the system must be: strict for a bank, relaxed for a lab. |

### A concrete example

At 3am, a BGP session (the link between the company network and an internet provider) goes down.

- **Without AI:** an engineer is woken up and spends 40 minutes diagnosing and fixing it.
- **With an uncontrolled AI agent:** it might fix it in 2 minutes, or change the wrong thing and
  cause a bigger outage. No bank or telco can approve that.
- **With AgenticOS:** the agent diagnoses the cause in seconds using read-only access. It
  proposes a fix and tests it on the simulated network. The on-call engineer gets one message:
  *"BGP down, cause found, here's the fix; the simulation shows it restores the link without
  breaking anything else; approve?"* The engineer taps **approve**, the fix is applied exactly
  once and verified automatically, and the auditor later sees the full record.

The engineer goes from 40 minutes of work to a 1-minute approval, with no extra risk.

### The business value

- **Faster incident resolution:** less downtime, fewer engineers woken at night.
- **AI that is allowed into production:** the security officer can say yes, because the controls
  can be inspected and tested.
- **Compliance readiness:** regulations such as the EU AI Act require record-keeping and human
  oversight for this kind of system, and AgenticOS produces both by design.
- **No vendor lock-in:** it works with local, on-premises models, which matters for banks, telcos
  and governments that can't send data to the cloud.

**Who it's for:** telecom operators, banks, internet exchanges, large enterprises and government
networks: organisations with critical infrastructure and strict regulators. The control layer
is open source so their security teams can inspect it. vExpertAI provides production agents
(AI NOC, Cairn), connectors to real Cisco/Juniper/Arista equipment, network simulation,
deployment and support.

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
| Can we set our own risk appetite? | Yes. Confidence thresholds are operator policy, per tenant ([examples/policy.json](examples/policy.json)), versioned, and recorded in every decision. Agents cannot change them. |

## Quick start

```bash
git clone https://github.com/eduardd76/enterprise-AgenticOS && cd enterprise-AgenticOS
python3 -m pip install -e '.[dev]'          # Python >= 3.12, zero runtime dependencies
python3 -m agenticos demo                   # AI NOC: BGP down -> diagnose -> approve -> fix -> verify
python3 -m agenticos demo --interactive     # you are the approving NOC lead
python3 -m agenticos demo --policy examples/policy.json   # per-tenant risk appetite
python3 -m agenticos lifecycle              # start / suspend / resume / cancel
python3 -m agenticos ps                     # process table of the last run
python3 -m agenticos audit --lineage del-0001   # verify audit chain + actions under a delegation
python3 -m pytest -q                        # 81 conformance, red-team and process tests
```

### Real routers + local LLM

```bash
labs/frr-bgp/lab.sh up                                          # 2 real FRR routers, eBGP
python3 -m agenticos demo --lab --model qwen2.5:7b-instruct     # local model via Ollama
```

This runs a real outage on real FRR routers in Docker, diagnosed by a local LLM, and fixed
through the kernel with approval, exactly-once execution and verification.

**Two faults, real Arista switches:** [labs/evpn-ceos](labs/evpn-ceos/README.md) is a small
EVPN/VXLAN data center on cEOS with a multi-fault incident: an uplink shut down plus a host
port that drifted into the wrong VLAN. With scripted rules, AgenticOS fixes 1 of 2 faults and
escalates. With a local Qwen model, it fixes both in two approved rounds, and the tenant
service is restored. Run it with `python3 -m agenticos fabric --model qwen2.5:7b-instruct`.

**Always-on mode:** `python3 -m agenticos watch` monitors the routers and opens an incident by
itself when a BGP link breaks. Agents start and ask a human to approve, either in **Slack**
(react ✅/❌; outbound-only, no public URL) or with `agenticos approve apr-0001 --as bob`.
Then they fix, verify and exit. See
[labs/frr-bgp](labs/frr-bgp/README.md).

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

## A real run, step by step

This is an actual run on real FRR routers with Slack approvals (`agenticos watch`), recorded
on a MacBook. Times are seconds from the moment the network broke.

> **Where the LLM was:** this run used the built-in *scripted reasoner* for diagnosis (no
> `--model` flag). Add `--model qwen2.5:7b-instruct` and the same flow uses a local LLM
> through Ollama. In a separate run, Qwen identified the same root cause in about 5 seconds.
> The LLM only ever *proposes* hypotheses; detection, evidence, simulation, permission,
> approval, execution and verification are deterministic, as described in
> [where the LLM sits](#where-the-llm-sits).

### The setup

- **Two real routers** (FRR in Docker), `lab-r1` and `lab-r2`, connected with BGP, the
  protocol internet providers use to exchange routes.
- **The AgenticOS watcher**: a small, deterministic program (not an AI) that checks the BGP
  session every 3 seconds.
- **Slack**, where the on-call engineer, *bob* (role `noc-lead`), approves changes.

### What happened

1. **The network broke (0 s).** `lab-r1`'s interface was shut down, which is like
   unplugging the cable. The BGP session dropped and the routers stopped exchanging routes:
   the classic 3am outage.
2. **The watcher noticed (about 4 s).** Both routers reported a problem (`Active`,
   `Connect`), but it is one broken link, so the watcher opened **one** incident, INC-0001.
   It assigned it to `lab-r1`, because that router's own interface was the one switched off.
3. **A team of agents started.** A *coordinator* agent started a *diagnosis* agent with
   **read-only** permission on `lab-r1` only. It read the BGP and interface state and, using
   the reasoner (scripted in this run; a local LLM with `--model`), concluded "the interface
   is administratively down", in under half a second.
4. **A second agent prepared the fix but could not apply it.** A *change* agent worked out
   the fix (`interface eth0 ; no shutdown`) and had the kernel simulate it on a twin. The
   kernel predicted the session comes back with nothing else breaking. A production change
   needs a human, so the agent requested approval and **went to sleep**, using no compute
   while waiting.
5. **The request reached Slack (4.8 s).** The kernel posted the review package: what is
   wrong, the exact commands, how to undo them, the simulation result, and the confidence
   (0.95, PROCEED). The agent's explanation is labelled *unverified*; the simulation is the
   kernel's own.
6. **The engineer approved (71 s).** Bob reacted ✅. The kernel checked:
   - Is this Slack user mapped to a real approver? Yes: bob.
   - Does bob have the approver role? Yes: `noc-lead`.
   - Is bob the person who requested the change? No, so separation of duties holds.
   - Has the router changed since the request? No, so the plan is still valid.
7. **The fix was applied, exactly once (71.3 s).** The change agent woke up and the kernel
   ran `no shutdown` on `lab-r1` a single time.
8. **Someone else checked the work (73 s).** A separate *verifier* agent checked the router
   until the session was `Established` **and** routes were flowing again. The agent that
   makes a change never gets to declare it a success.
9. **Everything shut down.** The coordinator wrote the incident report and all four agents
   exited. Only the lightweight watcher kept running, waiting for the next problem.

### Behind the scenes

- **The agents never touched the router themselves.** Each one ran as a sandboxed process
  with no network access, no passwords, and no way to reach the routers. Every action was a
  request to the kernel, checked every time.
- **Each agent got only the permissions it needed.** The diagnosis agent could only read. If
  it tries to change something (and the model does suggest it), the kernel refuses.
- **Everything was recorded.** A hash-linked audit log (149 records in this run) shows
  `apr-0001 approved by bob, via Slack user U0… (✅)` and that the change executed exactly
  once. Routers were checked independently afterwards with plain `vtysh`: the session was
  Established, and `lab-r2` had re-learned `192.0.2.0/24`.

### Why it matters

| | Without AgenticOS | With AgenticOS |
|---|---|---|
| Detection | An alarm wakes an engineer | Automatic, within seconds |
| Diagnosis | The engineer logs in and investigates (minutes) | Done in under a second |
| Human effort | Diagnose, plan, type commands, verify | Read one Slack message, tap ✅ |
| Risk | Human typing errors at 3am | Exact commands shown up front, tested on a twin, applied once |
| Audit | Notes written afterwards, if at all | Complete, automatic, tamper-evident |

The whole incident took **73 seconds**, and **66 of those were the human deciding**; the
machine work took about 6 seconds. The agents did the work, the human kept the authority,
and the kernel enforced the boundary between the two.

### Where the LLM sits

The LLM has exactly one job: propose a cause and a fix from the evidence. Everything around
it is deterministic, because each of those steps needs to be exact, repeatable or
accountable:

| Step | Who does it | Why |
|---|---|---|
| Detect the outage | Watcher (plain code) | Cheap, instant, always on |
| Collect evidence | Kernel + device driver | Facts come from the device, not a model |
| **Propose a cause and fix** | **LLM** (or scripted fallback) | **The only step that needs judgment** |
| Check the proposal against evidence | Diagnosis agent code | Models can be confidently wrong |
| Simulate the fix | Kernel twin | The prediction must not be the model's opinion |
| Allow or refuse | Kernel policy | A model never decides its own permissions |
| Approve | Human | Accountability |
| Apply, verify, audit | Kernel + verifier agent | Exact, once, recorded |

The model's output is treated as untrusted input:
- it is schema-validated, and malformed output falls back to the scripted reasoner;
- its "just apply the fix" suggestions are refused, because the diagnosis agent has no
  write permission;
- fixes become device commands only through an allowlist.

A single shut-down interface is simple enough for rules. LLMs earn their place on messier
incidents: many alarms at once, unusual symptom combinations, log interpretation, and
turning a vague human report into concrete checks. Those are roadmap scenarios.

Reproduce it: [labs/frr-bgp](labs/frr-bgp/README.md).

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
3. **Approvals where people work:** Slack ✅ (reaction-based, outbound-only); Teams and
   ServiceNow next.
4. **Compliance evidence:** keyed audit chain; mappings to NIST AI RMF, ISO/IEC 42001 and the
   EU AI Act (Art. 12, Art. 14).
5. **Proof:** an open benchmark against a plain agent-framework baseline, using the built-in
   fault injection.
6. **Stability:** versioned SDK API, semver, LTS.

## Limits of v0.1 (honest list)

- Real-device support is one FRR driver (vtysh), validated in a 2-router Docker lab.
  Cisco/Juniper/Arista drivers and a full emulated digital twin are roadmap work.
- The local-LLM path has been validated with Qwen 2.5 7B on Ollama. Other models are
  untested.
- Single process: no HA or federation.
- The audit chain is not keyed yet.
- The baseline benchmark has not been run.

## Contributing and license

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities
privately via [SECURITY.md](SECURITY.md). Licensed under [Apache-2.0](LICENSE).
Copyright 2026 vExpertAI. Commercial drivers, agents and support are available from vExpertAI.
