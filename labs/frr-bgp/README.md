# Real-router lab: FRR + local LLM

Two real FRRouting 10.2 routers in Docker, one eBGP session (AS65001 ↔ AS65002). AgenticOS
fixes a real outage on them. Diagnosis runs on a local model through Ollama, so no data
leaves your machine.

```
 lab-r1 (AS65001, 10.10.0.2) ──eBGP── lab-r2 (AS65002, 10.10.0.3)
   announces 192.0.2.0/24              announces 198.51.100.0/24
```

## Run it

```bash
labs/frr-bgp/lab.sh up                                    # start routers, wait for BGP
ollama pull qwen2.5:7b-instruct                           # optional: local reasoning model
python3 -m agenticos demo --lab --model qwen2.5:7b-instruct
python3 -m agenticos demo --lab --model qwen2.5:7b-instruct --interactive   # you approve
labs/frr-bgp/lab.sh status                                # plain vtysh view, no AgenticOS
labs/frr-bgp/lab.sh down
```

Without `--model`, or if Ollama isn't running, diagnosis uses the deterministic scripted
reasoner. Everything else is identical.

## Always-on: the watcher

```bash
# terminal 1: watch the network; incidents open by themselves
python3 -m agenticos watch --model qwen2.5:7b-instruct

# anywhere: break something
docker exec aos-lab-r1 vtysh -c "conf t" -c "interface eth0" -c "shutdown"

# terminal 2: the on-call engineer sees the approval request and decides
python3 -m agenticos approvals
python3 -m agenticos approve apr-0001 --as bob        # or --deny
```

The watcher isn't an AI. It's a cheap, deterministic poller of BGP state. When a link
breaks:

1. It correlates both ends into **one incident** (not two) and assigns it to the router
   whose own interface is down.
2. It opens an intent as the system principal `noc-monitor`, and the agents start.
3. The agents diagnose the fault, test the fix on the twin, and wait for a **human**
   approval. The monitor itself is refused as an approver.
4. They fix, verify, write the report, and **every agent process exits**. The watcher
   prints "agent processes still running: 0" and goes back to watching.

Flapping links are debounced. If a link is still down after its incident closes, the
watcher reports that a human is needed and doesn't retry in a loop.

## What happens (one-shot demo)

1. A **real fault**: `interface eth0 / shutdown` on lab-r1. BGP drops to Idle/Active.
2. The diagnosis agent reads the **real** BGP and interface state through the kernel. Only the
   kernel can reach Docker; the sandboxed agents have no network or socket access.
3. The **local LLM** proposes hypotheses. Its output is schema-validated, and anything
   malformed falls back to the scripted reasoner. It also suggests "just apply the fix"; the
   kernel refuses, because the diagnosis agent was never granted production writes.
4. The change agent asks the kernel to simulate the fix, then requests approval. The review
   package shows the **exact vtysh commands** and the kernel-computed prediction.
5. After approval, the kernel re-checks that lab-r1's running config hasn't changed, then runs
   `interface eth0 / no shutdown`. It kills the agent before the reply arrives, and the retry
   is answered from the record, so the command runs **once**.
6. A verifier polls the real session until it's `Established`.
7. Check it yourself: `docker exec aos-lab-r2 vtysh -c "show ip bgp"` shows 192.0.2.0/24
   learned again.

## Notes

- `inventory.json` stands in for a source of truth such as Nautobot or NetBox: device to
  container, tenant, and neighbor-to-interface mapping.
- The twin is a rule-based model of live state (interface admin state, hold timer), not an
  emulated clone. A Batfish- or Containerlab-backed twin is roadmap work.
- Supported changes are an allowlist (`FrrLab.commands`): interface admin up/down and BGP
  hold time. Anything else is rejected before it reaches vtysh.
- Tested on Apple Silicon (arm64) with Docker/OrbStack and FRR `quay.io/frrouting/frr:10.2.1`.
