# EVPN/VXLAN data center: two faults, Arista cEOS, local LLM

A small spine-leaf data center on real Arista cEOS switches, with a **multi-fault** incident.
It's the scenario where fixed rules stop being enough.

```
                 spine1 (AS65000)
                 /             \
   leaf1 (AS65001)             leaf2 (AS65002)
        |  Ethernet3                |  Ethernet3
     host1 10.10.10.11          host2 10.10.10.12
        └──── tenant-a: VLAN 10 ⇄ VXLAN VNI 10010 ────┘
```

- **Underlay:** eBGP on point-to-point /31 links.
- **Overlay:** eBGP EVPN between the loopbacks, through the spine.
- **Service:** host1 and host2 share a Layer-2 segment (VLAN 10) stretched across the fabric
  with VXLAN.

## The two faults

| # | Fault | What it looks like | Who can find it |
|---|---|---|---|
| 1 | leaf2 `Ethernet1` (uplink) shut down | leaf2 falls off the fabric: underlay and EVPN BGP down | Simple rules ("interface down → bring it up") |
| 2 | leaf2 `Ethernet3` (host2's port) drifted to **VLAN 20** (tenant-b) | After fault 1 is fixed, BGP, EVPN and VXLAN all look healthy, yet host1 still can't reach host2 | Needs reasoning: tenant intent says VLAN 10, the port says VLAN 20, and host2's MAC is learned in the wrong VLAN |

## Result: scripted rules vs. a local LLM (real run)

Same fabric, same two faults, same kernel, same approvals. Only the reasoner differs.

| | Scripted rules (baseline) | Qwen 2.5 7B (local, Ollama) |
|---|---|---|
| Round 1 | Found the shut uplink → fixed | Found the **VLAN drift** ("Ethernet3 is in VLAN 20 instead of 10") → fixed |
| Round 2 | Nothing it recognises → **escalated to a human** | Found the shut uplink → fixed |
| Faults fixed | **1 of 2** | **2 of 2** |
| Service host1 → host2 | still **unreachable** | **reachable** (0% loss) |
| Model tried to apply its own fix | refused (`UNAUTHORIZED`) | refused twice (`UNAUTHORIZED`) |
| Production changes | 1, each approved, applied once | 2, each approved, applied once |
| Total time | ~97 s | ~166 s |

Notes on the Qwen run:
- **The twin's honesty mattered.** The approval package for Qwen's first fix predicted
  `service: unreachable`, telling the approver up front that another fault remained.
- **Nothing was taken on trust.** Every hypothesis was checked against live evidence before
  it could be proposed, and the switches were verified independently afterwards with plain
  EOS commands.

### Full pilot stack: NetBox + Batfish + Qwen (real run)

`fabric --model qwen2.5:7b-instruct --sot netbox --twin batfish`: intent read from NetBox,
every fix predicted by Batfish from the switches' real running-configs.

| Round | Fix (Qwen) | Batfish prediction shown to the approver |
|---|---|---|
| 1 | leaf2 Ethernet3 → VLAN 10 ("in VLAN 20 instead of 10") | host2 port fixed; leaf2 underlay + EVPN BGP still **down**, VTEPs unreachable → service **unreachable** |
| 2 | leaf2 Ethernet1 no shutdown (carried over from round 1) | all BGP sessions up, VTEPs reachable → service **reachable** |

Outcome: resolved, 2 approved changes, host1 → host2 at 0% loss (checked independently
with EOS CLI), audit chain intact. Qwen again tried to apply fixes itself and was refused.

In an earlier run, Qwen named both faults in round 1 but forgot the uplink in round 2. Since
then, hypotheses that passed the evidence check but weren't used are carried into the next
round. They must pass the check again against fresh evidence, so a model's lapse can't drop a
known-good fix.

## How AgenticOS handles it: rounds

Each round:
1. The diagnosis agent gathers fresh evidence from every switch and probes host1 → host2.
2. The reasoner proposes fixes.
3. **Only a fix that the evidence confirms is accepted.** For example, the port really is in
   VLAN 20, and the fix hasn't already been tried.
4. The change agent simulates it on the fabric twin. The twin is honest: *"this repairs the
   uplink; the service stays unreachable"*.
5. A human approves, and the kernel applies the change exactly once.
6. An independent verifier probes host1 → host2. If it's still broken, the next round
   starts, with the history of fixes so far.

The incident ends when the service is reachable, when no verified fix remains (it escalates
to a human), or after 3 rounds.

## Run it

```bash
# one-time: import the cEOS image (download from arista.com with a free account)
docker import --platform linux/arm64 cEOSarm-lab-4.34.8M.tar.xz ceosarm:4.34.8M   # Apple Silicon
# x86 hosts: docker import cEOS-lab-<ver>.tar.xz ceos:<ver> and set it in topology.clab.yml

labs/evpn-ceos/lab.sh up          # deploy with containerlab (runs as a container)

# baseline: scripted rules only
python3 -m agenticos fabric

# with a local LLM
labs/evpn-ceos/lab.sh reset
python3 -m agenticos fabric --model qwen2.5:7b-instruct [--interactive]

labs/evpn-ceos/lab.sh status      # plain EOS view, no AgenticOS
labs/evpn-ceos/lab.sh down
```

`agenticos fabric` injects both faults itself. `lab.sh break` and `lab.sh reset` let you do
it by hand.

## Notes and limits

- **cEOS is licensed by Arista**, so this lab can't run in public CI. CI covers the driver
  logic, change allowlist, twin and evidence checks offline (`tests/test_eos_driver.py`).
- **Apple Silicon: use the native ARM image (`cEOSarm-lab`, 4.32+).** With
  `cEOSarm-lab-4.34.8M`, the whole fabric boots and converges in under 50 s, a CLI call takes
  about 0.1 s, and each switch uses about 0.9 GB RAM. The x86 `cEOS-lab` image under emulation
  was unusable here: one CLI call took about 68 s, and three switches never converged.
- **Local LLM tip:** AgenticOS caps every model call (`AOS_MODEL_MAX_TOKENS`, default 1024).
  Without a cap, JSON-mode generation can loop on whitespace and block Ollama's only slot for
  every later request.
- **Two twins.** The default is a rule-based model of the fabric's health elements (uplinks,
  host-port VLANs, VNI bindings). With `--twin batfish`, the change is written into the
  switches' real running-configs and Batfish computes BGP, EVPN, VLAN, VNI and VTEP-path
  state. Batfish doesn't forward host traffic over VXLAN, so the verifier still pings.
- **Source of truth.** `inventory.json`, or NetBox (`--sot netbox`, see `netbox/`), which also
  supplies the intended VLAN per host port.
- **Allowed changes** (`EosLab.commands`): interface admin up/down, and host-port access VLAN
  limited to VLANs in the inventory. Everything else is rejected before it reaches EOS.
