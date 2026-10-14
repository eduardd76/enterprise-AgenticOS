# Enterprise AgenticOS

**AI change control for network operations.**

Let AI diagnose and fix your network, without anyone having to trust the AI.

AI agents can now find the cause of a network outage in seconds. Network teams still don't let
them touch production, and they're right: one bad change can take the business down, and
nobody can prove afterwards who allowed it. AgenticOS is the control layer between the AI and
your devices. The AI **proposes**. AgenticOS checks the proposal against live evidence and
predicts its effect from your real device configurations. Then it raises a change request for
a named human to approve, applies the change exactly once, verifies it, and keeps a
tamper-evident record of all of it.

> **Status: v0.1 design-partner preview.** It has been validated live on Arista cEOS and FRR,
> with a local LLM, NetBox, Batfish and Slack, and red-teamed. It is not production-hardened
> yet. See [SECURITY.md](SECURITY.md) and [CONFORMANCE.md](CONFORMANCE.md). We are looking for
> network teams willing to run it against a **staging** network. Open a discussion.

## What it does, on a real incident

A small EVPN/VXLAN data center on Arista switches ([labs/evpn-ceos](labs/evpn-ceos/README.md))
gets two faults at once: a leaf uplink shut down, and a server port that drifted into another
tenant's VLAN. The tenant's servers can't reach each other.

1. **Evidence.** Agents read every switch (BGP, EVPN, VXLAN, VLANs, MACs) and ping the
   service. They are read-only and hold no credentials.
2. **Diagnosis.** A local LLM (Qwen 2.5 7B on Ollama; no data leaves the building) proposes
   causes. Each proposal must match the live evidence and the **intent in NetBox** ("this port
   belongs in VLAN 10"), or it is discarded.
3. **Prediction.** The proposed change is written into the switches' real running configs, and
   **Batfish** computes the result. For the first fix the prediction was *"VLAN fixed; leaf2's
   BGP and VTEP paths are still down; the service stays unreachable"*. That was correct: the
   other fault remained.
4. **Approval.** A named human approves in **ServiceNow** (as a change request with the
   implementation plan, backout plan and risk) or in **Slack**. The approval is single-use and
   bound to that exact change. The AI tried to apply its own fix twice and was refused twice.
5. **Change.** The change is applied exactly once and verified by an independent agent. The
   incident runs a second round for the remaining fault.
6. **Record.** The result: both faults fixed, the service restored (0% loss, confirmed
   independently on the switches), 2 approved changes, and an intact hash-chained audit log.

```
  NetBox ──intent──┐                       ┌── Batfish: predict from real configs
                   ▼                       ▼
  devices ──evidence──▶  AgenticOS kernel  ──change request──▶ ServiceNow / Slack ──▶ human
                   ▲     (policy, budgets,                                      │
   local LLM ──proposals  approvals, audit)  ◀──────────── approve / reject ────┘
                                  │
                                  └──▶ apply exactly once ──▶ verify ──▶ close the change
```

## Why network teams can say yes

| The objection | What AgenticOS does |
|---|---|
| "What if the AI is wrong?" | Its proposals are checked against live evidence and NetBox intent, then simulated in Batfish. A fix that predicts a regression never reaches a human. |
| "What if it's manipulated?" | Agents run sandboxed with no credentials, no network and no device access. Their only channel is the kernel, and unapproved writes are refused. |
| "Who approved this?" | A named approver, in your change tool (ServiceNow or Slack), recorded with the evidence and the prediction. Separation of duties is enforced: the requester can't approve. |
| "What if it fails halfway?" | Agents restart from checkpoints, a change never runs twice, and an unknown outcome escalates to a human. |
| "Can we prove what happened?" | A hash-chained audit log, and every action can be traced back to the intent and approval behind it. |
| "Will it fit our stack?" | It reads intent from NetBox, predicts changes with Batfish, raises changes in ServiceNow and talks to people in Slack. Everything runs on-premises with local models. |
| "How cautious will it be?" | Risk appetite is operator policy, per tenant ([examples/policy.json](examples/policy.json)). Agents can't change it. |

## Integrations

| | Status | Where |
|---|---|---|
| **NetBox**: source of truth and intent | Live-tested with NetBox 4.3 | [agenticos/sot/netbox.py](agenticos/sot/netbox.py), [labs/evpn-ceos/netbox](labs/evpn-ceos/netbox) |
| **Batfish**: change prediction from real configs | Live-tested against cEOS configs | [agenticos/drivers/batfish.py](agenticos/drivers/batfish.py) |
| **ServiceNow**: approvals as change requests | Tested against a Table API fake; not yet run on a real instance | [agenticos/servicenow.py](agenticos/servicenow.py) |
| **Slack**: approvals by reaction | Live-tested | [agenticos/channels.py](agenticos/channels.py) |
| **Arista EOS** (cEOS) | Live-tested | [agenticos/drivers/eos.py](agenticos/drivers/eos.py) |
| **FRR** | Live-tested, and runs in CI | [agenticos/drivers/frr.py](agenticos/drivers/frr.py) |
| **Local LLMs** (Ollama, OpenAI-compatible) | Live-tested with Qwen 2.5 7B | [agenticos/drivers/models.py](agenticos/drivers/models.py) |

**Who it's for:** network operations teams at telcos, banks, internet exchanges, cloud and
hosting providers, and large enterprises, wherever a bad change is expensive and auditors ask
questions. The kernel is open source, so your security team can inspect it. vExpertAI provides
production agents, device drivers, integration and support.

## Why a kernel, not another agent framework

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
python3 -m pytest -q                        # conformance, red-team, driver and integration tests
```

### Real routers + local LLM

```bash
labs/frr-bgp/lab.sh up                                          # 2 real FRR routers, eBGP
python3 -m agenticos demo --lab --model qwen2.5:7b-instruct     # local model via Ollama
```

This runs a real outage on real FRR routers in Docker, diagnosed by a local LLM, and fixed
through the kernel with approval, exactly-once execution and verification.

**Two faults, real Arista switches, the full stack:**

```bash
labs/evpn-ceos/lab.sh up                         # cEOS spine-leaf fabric (needs the cEOS image)
labs/evpn-ceos/netbox/netbox.sh up               # NetBox, seeded with the fabric's intent
docker run -d -p 127.0.0.1:9996:9996 batfish/allinone && pip install pybatfish
set -a; . var/netbox.env; set +a                # NETBOX_TOKEN, generated by netbox.sh
python3 -m agenticos fabric --model qwen2.5:7b-instruct --sot netbox --twin batfish \
    [--servicenow --approvers var/approvers.json]  # SNOW_INSTANCE, SNOW_USER, SNOW_PASSWORD
```

With scripted rules, AgenticOS fixes 1 of 2 faults and escalates. With a local Qwen model, it
fixes both in two approved rounds, and the tenant service is restored. See
[labs/evpn-ceos](labs/evpn-ceos/README.md).

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
3. **Approvals where people work:** Slack ✅ (reaction-based, outbound-only), ServiceNow
   change requests ✅ (needs a real-instance validation); Teams next.
4. **Compliance evidence:** keyed audit chain; mappings to NIST AI RMF, ISO/IEC 42001 and the
   EU AI Act (Art. 12, Art. 14).
5. **Proof:** an open benchmark against a plain agent-framework baseline, using the built-in
   fault injection.
6. **Stability:** versioned SDK API, semver, LTS.

## Limits of v0.1 (honest list)

- Real-device support: FRR (vtysh) and Arista EOS (cEOS), validated in small Docker labs.
  The change allowlist is small (interface admin state, access VLAN). Cisco and Juniper
  drivers are roadmap work.
- The Batfish twin predicts the control plane: BGP, EVPN sessions, VLANs, VNIs and underlay
  paths. It does not forward host traffic across VXLAN, so the independent verifier still
  pings afterwards.
- The ServiceNow channel has been tested against a fake of the Table API, not a real
  instance. Real instances drive change state through workflows, which may need configuring.
- The local-LLM path has been validated with Qwen 2.5 7B on Ollama. Other models are
  untested.
- Single process: no HA or federation.
- The audit chain is not keyed yet.
- The baseline benchmark has not been run.

## Contributing and license

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities
privately via [SECURITY.md](SECURITY.md). Licensed under [Apache-2.0](LICENSE).
Copyright 2026 vExpertAI. Commercial drivers, agents and support are available from vExpertAI.
