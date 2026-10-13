#!/usr/bin/env bash
# Two FRR routers, one eBGP session (AS65001 <-> AS65002) on a dedicated Docker network.
set -euo pipefail
cd "$(dirname "$0")"
IMAGE=quay.io/frrouting/frr:10.2.1
NET=aos-lab-net
case "${1:-}" in
  up)
    docker network inspect $NET >/dev/null 2>&1 || \
      docker network create --subnet 10.10.0.0/29 $NET >/dev/null
    for r in r1 r2; do
      ip=$([ $r = r1 ] && echo 10.10.0.2 || echo 10.10.0.3)
      docker rm -f aos-lab-$r >/dev/null 2>&1 || true
      docker run -d --name aos-lab-$r --hostname lab-$r --network $NET --ip $ip \
        --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add NET_RAW \
        -v "$PWD/$r/daemons:/etc/frr/daemons:ro" \
        -v "$PWD/$r/vtysh.conf:/etc/frr/vtysh.conf:ro" \
        $IMAGE >/dev/null
      docker cp "$PWD/$r/frr.conf" aos-lab-$r:/etc/frr/frr.conf
      docker restart aos-lab-$r >/dev/null
    done
    echo -n "waiting for BGP"
    for _ in $(seq 1 30); do
      if docker exec aos-lab-r1 vtysh -c "show bgp summary" 2>/dev/null | grep -qE "10\.10\.0\.3 .* [0-9]+ +[0-9]+ +N/A|10\.10\.0\.3 +4 +65002 .* 1 +"; then break; fi
      st=$(docker exec aos-lab-r1 vtysh -c "show bgp neighbors 10.10.0.3 json" 2>/dev/null | grep -o '"bgpState":"[A-Za-z]*"' || true)
      [ "$st" = '"bgpState":"Established"' ] && break
      echo -n "."; sleep 1
    done
    echo; docker exec aos-lab-r1 vtysh -c "show bgp summary" ;;
  down)
    docker rm -f aos-lab-r1 aos-lab-r2 >/dev/null 2>&1 || true
    docker network rm $NET >/dev/null 2>&1 || true
    echo "lab removed" ;;
  status)
    docker exec aos-lab-r1 vtysh -c "show bgp summary" ;;
  *) echo "usage: $0 up|down|status"; exit 2 ;;
esac
