"""Batfish twin: config editing is pure and tested offline; the Batfish analysis itself is a
live test (AOS_BATFISH=1, a Batfish service on 127.0.0.1:9996, pybatfish installed)."""

import json
import os

import pytest

from agenticos.drivers.batfish import candidate_config, healthy, interface_settings

INV = os.path.join(os.path.dirname(__file__), "..", "labs", "evpn-ceos", "inventory.json")
LEAF2 = open(os.path.join(os.path.dirname(__file__), "..", "labs", "evpn-ceos", "configs",
                          "leaf2.cfg")).read()


def test_candidate_config_admin_and_vlan():
    down = candidate_config(LEAF2, {"interface": "Ethernet1", "admin": "down"})
    assert interface_settings(down, "Ethernet1")["admin"] == "down"
    assert "   ip address 10.0.2.1/31\n   shutdown\n" in down       # stays inside the stanza
    up = candidate_config(down, {"interface": "Ethernet1", "admin": "up"})
    assert interface_settings(up, "Ethernet1")["admin"] == "up"
    moved = candidate_config(LEAF2, {"interface": "Ethernet3", "access_vlan": 20})
    assert interface_settings(moved, "Ethernet3")["access_vlan"] == 20
    assert moved.count("switchport access vlan") == 1                 # replaced, not added
    assert interface_settings(LEAF2, "Ethernet3") == {"admin": "up", "access_vlan": 10}


def test_candidate_config_unconfigured_interface_and_bad_change():
    cfg = candidate_config(LEAF2, {"interface": "Ethernet2", "admin": "down"})
    assert interface_settings(cfg, "Ethernet2")["admin"] == "down"
    assert interface_settings(LEAF2, "Ethernet2") == {"admin": "up", "access_vlan": 1}
    for bad in ({"interface": "Ethernet1"}, {"interface": "Ethernet1", "admin": "up", "x": 1}):
        with pytest.raises(ValueError):
            candidate_config(LEAF2, bad)


def test_health_values():
    assert healthy("up") and healthy("reachable") and healthy("vlan 10")
    assert not any(healthy(v) for v in ("down", "unreachable", "vlan 20 (wrong)",
                                        "vlan 10 (inactive)", "missing (wrong)"))


@pytest.mark.skipif(os.environ.get("AOS_BATFISH") != "1", reason="needs Batfish (AOS_BATFISH=1)")
def test_live_batfish_predicts_two_fault_fabric():
    from agenticos.drivers.batfish import BatfishTwin
    inv = json.load(open(INV))
    cfgdir = os.path.join(os.path.dirname(INV), "configs")
    cfgs = {d: open(os.path.join(cfgdir, f"{d}.cfg")).read() for d in inv["devices"]}
    twin = BatfishTwin(inv)
    assert twin.evaluate(cfgs)["service:tenant-a"] == "reachable"
    broken = dict(cfgs)
    broken["leaf2"] = candidate_config(candidate_config(
        cfgs["leaf2"], {"interface": "Ethernet1", "admin": "down"}),
        {"interface": "Ethernet3", "access_vlan": 20})
    h = twin.evaluate(broken)
    assert h["leaf2: underlay BGP"] == "down" and h["leaf2: EVPN BGP"] == "down"
    assert h["VTEP leaf1 -> leaf2"] == "unreachable"
    assert h["leaf2:Ethernet3 (host2)"].startswith("vlan 20 (wrong")
    fix1 = {**broken, "leaf2": candidate_config(broken["leaf2"],
                                                {"interface": "Ethernet1", "admin": "up"})}
    h1 = twin.evaluate(fix1)
    assert h1["leaf2: EVPN BGP"] == "up" and h1["service:tenant-a"] == "unreachable"
    bad = {**cfgs, "spine1": candidate_config(cfgs["spine1"],
                                              {"interface": "Ethernet1", "admin": "down"})}
    hb = twin.evaluate(bad)                  # a change on the spine breaks leaf1: a regression
    assert hb["leaf1: underlay BGP"] == "down" and hb["service:tenant-a"] == "unreachable"
