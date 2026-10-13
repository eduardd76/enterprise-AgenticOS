"""EVPN/cEOS driver logic that needs no switches: change allowlist, fabric twin, baseline
reasoner, model-output validation, and the diagnosis agent's evidence check."""

import os

import pytest

from agenticos.agents.fabric import FabricDiagnostic
from agenticos.drivers.eos import EosLab, _parse_json_stream
from agenticos.drivers.models import _mock_fabric, validate_model_output

INV = os.path.join(os.path.dirname(__file__), "..", "labs", "evpn-ceos", "inventory.json")


def broken_model():
    """Live-model shape for the two-fault state: leaf2 uplink down + host2 port in VLAN 20."""
    return {
        "leaf1": {"uplinks": {"Ethernet1": "up"}, "host_ports": {"Ethernet3": 10},
                  "admin": {"Ethernet1": "up", "Ethernet3": "up"}, "vni": {"10010": 10}},
        "leaf2": {"uplinks": {"Ethernet1": "down"}, "host_ports": {"Ethernet3": 20},
                  "admin": {"Ethernet1": "down", "Ethernet3": "up"}, "vni": {"10010": 10}},
    }


@pytest.fixture
def lab(monkeypatch):
    lab = EosLab(INV)
    state = {"m": broken_model()}
    monkeypatch.setattr(lab, "model", lambda: __import__("copy").deepcopy(state["m"]))
    lab._state = state
    return lab


def test_change_allowlist(lab):
    assert lab.commands("leaf2", {"interface": "Ethernet1", "admin": "up"}) == \
        ["interface Ethernet1", "no shutdown"]
    assert lab.commands("leaf2", {"interface": "Ethernet3", "access_vlan": 10}) == \
        ["interface Ethernet3", "switchport access vlan 10"]
    for dev, bad in [("leaf2", {"interface": "Ethernet1", "access_vlan": 10}),  # not a host port
                     ("leaf2", {"interface": "Ethernet3", "access_vlan": 999}),  # unknown VLAN
                     ("leaf2", {"interface": "Ethernet9", "admin": "up"}),
                     ("leaf2", {"interface": "Ethernet3", "access_vlan": "10\nreload"}),
                     ("spine9", {"interface": "Ethernet1", "admin": "up"})]:
        with pytest.raises(ValueError):
            lab.commands(dev, bad)


def test_twin_is_honest_about_multiple_faults(lab):
    fix1 = lab.simulate("leaf2", {"interface": "Ethernet1", "admin": "up"})
    assert "leaf2:Ethernet1 (uplink)" in fix1["improves"]
    assert fix1["predicted"]["service:tenant-a"] == "unreachable"      # the other fault remains
    assert fix1["regressions"] == []
    lab._state["m"]["leaf2"]["uplinks"]["Ethernet1"] = "up"
    lab._state["m"]["leaf2"]["admin"]["Ethernet1"] = "up"
    fix2 = lab.simulate("leaf2", {"interface": "Ethernet3", "access_vlan": 10})
    assert fix2["predicted"]["service:tenant-a"] == "reachable"
    bad = lab.simulate("leaf1", {"interface": "Ethernet3", "access_vlan": 20})
    assert "leaf1:Ethernet3 (host1)" in bad["regressions"]


def test_baseline_rules_see_shutdowns_but_not_vlan_drift():
    ev = {"devices": {"leaf2": {"interfaces": {
        "Ethernet1": {"admin": "down", "vlan": None}, "Ethernet3": {"admin": "up", "vlan": 20}}}}}
    out = _mock_fabric(ev)
    rems = [h["remediation"] for h in out["hypotheses"] if h["remediation"]]
    assert rems == [{"device": "leaf2", "interface": "Ethernet1", "admin": "up"}]


def test_fabric_validator_and_evidence_check():
    out = validate_model_output({"hypotheses": [
        {"claim": "port drift", "likelihood": 0.8,
         "remediation": {"device": "leaf2", "interface": "Ethernet3", "access_vlan": 10}},
        {"claim": "bad", "likelihood": 0.7,
         "remediation": {"device": "leaf2", "interface": "Ethernet3", "vlan": 10}}]})
    assert out["hypotheses"][0]["remediation"]["access_vlan"] == 10
    assert out["hypotheses"][1]["remediation"] is None
    devices = {"leaf2": {"interfaces": {"Ethernet1": {"admin": "up", "vlan": None},
                                        "Ethernet3": {"admin": "up", "vlan": 20}},
                         "host_ports": {"Ethernet3": "host2"}}}
    v = FabricDiagnostic._verify
    assert v({"device": "leaf2", "interface": "Ethernet3", "access_vlan": 10}, devices, set())
    assert not v({"device": "leaf2", "interface": "Ethernet1", "admin": "up"}, devices, set())
    assert not v({"device": "leaf2", "interface": "Ethernet3", "access_vlan": 10}, devices,
                 {("leaf2", "Ethernet3")})                              # already tried
    assert not v({"device": "leaf9", "interface": "Ethernet3", "access_vlan": 10}, devices, set())


def test_eos_json_stream_parsing():
    assert _parse_json_stream('{"a": 1}\n{"b": [2]}\n') == [{"a": 1}, {"b": [2]}]
