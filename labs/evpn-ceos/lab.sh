#!/usr/bin/env bash
# Small EVPN/VXLAN data center on Arista cEOS, deployed with containerlab (run as a container,
# so nothing is installed on the host). Needs a cEOS image (see README).
set -euo pipefail
cd "$(dirname "$0")"
CLAB_IMAGE=ghcr.io/srl-labs/clab:0.81.0
clab() {
  docker run --rm --privileged --network host --pid host \
    -v /var/run/docker.sock:/var/run/docker.sock -v /var/run/netns:/var/run/netns \
    -v "$PWD":"$PWD" -w "$PWD" $CLAB_IMAGE containerlab "$@"
}
eos() { docker exec "clab-evpn-dc-$1" Cli -p 15 -c "$2"; }
ping_ok() { docker exec clab-evpn-dc-host1 ping -c 3 -W 1 10.10.10.12 >/dev/null 2>&1; }

case "${1:-}" in
  up)
    IMG=$(grep -m1 "image: ceos" topology.clab.yml | awk '{print $2}')
    docker image inspect "$IMG" >/dev/null 2>&1 || {
      echo "missing image $IMG - import it first, e.g.:"
      echo "  docker import --platform linux/arm64 cEOSarm-lab-4.34.8M.tar.xz ceosarm:4.34.8M   # Apple Silicon"
      echo "  docker import cEOS-lab-<ver>.tar.xz ceos:<ver> and edit topology.clab.yml           # x86"; exit 1; }
    clab deploy -t topology.clab.yml --reconfigure
    echo -n "waiting for the fabric (EOS boot + BGP + EVPN)"
    for i in $(seq 1 60); do
      if ping_ok; then echo " ready: host1 <-> host2 over VXLAN"; exit 0; fi
      echo -n "."; sleep 5
    done
    echo " FAILED: host1 cannot reach host2 after 5 min"; exit 1 ;;
  down)
    clab destroy -t topology.clab.yml --cleanup ;;
  status)
    for n in spine1 leaf1 leaf2; do echo "== $n"; eos $n "show bgp evpn summary" | tail -n +6; done
    ping_ok && echo "service tenant-a: host1 -> host2 REACHABLE" \
            || echo "service tenant-a: host1 -> host2 UNREACHABLE" ;;
  break)
    # Fault 1 (obvious): leaf2 uplink shut. Fault 2 (subtle): host2 port drifted to VLAN 20.
    eos leaf2 $'configure\ninterface Ethernet1\nshutdown\nend'
    eos leaf2 $'configure\ninterface Ethernet3\nswitchport access vlan 20\nend'
    echo "injected: leaf2 Ethernet1 shutdown + leaf2 Ethernet3 moved to VLAN 20" ;;
  reset)
    eos leaf2 $'configure\ninterface Ethernet1\nno shutdown\nend'
    eos leaf2 $'configure\ninterface Ethernet3\nswitchport access vlan 10\nend'
    echo "faults cleared" ;;
  *) echo "usage: $0 up|down|status|break|reset"; exit 2 ;;
esac
