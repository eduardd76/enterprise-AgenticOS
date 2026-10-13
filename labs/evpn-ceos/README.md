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
# one-time: import the cEOS image (download cEOS-lab from arista.com with a free account)
docker import --platform linux/amd64 cEOS-lab-4.31.10M.tar.xz ceos:4.31.10M

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
- **Apple Silicon:** cEOS-lab 4.31 is x86_64 and runs under emulation in OrbStack or Docker
  Desktop. Expect a 5–10 minute boot and about 1.2–3 GB RAM per switch. An arm64 cEOS build
  boots much faster.
- **The twin is a rule-based model** of fabric health elements: uplinks, host-port VLANs,
  VNI bindings. It is not an emulated EOS.
- **Allowed changes** (`EosLab.commands`): interface admin up/down, and host-port access VLAN
  limited to VLANs in the inventory. Everything else is rejected before it reaches EOS.
