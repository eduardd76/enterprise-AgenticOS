"""FRR driver + local-model guardrails. Unit tests run anywhere; the live-lab test runs only
when the Docker lab is up (labs/frr-bgp/lab.sh up) and AOS_LAB=1 is set."""

import asyncio
import json
import os
import subprocess

import pytest

from agenticos.drivers.frr import FrrLab
from agenticos.drivers.models import validate_model_output
from agenticos.errors import SyscallError
from conftest import TENANT_A

INV = os.path.join(os.path.dirname(__file__), "..", "labs", "frr-bgp", "inventory.json")


# --- untrusted model output is schema-checked ------------------------------------------
def test_model_output_validation_keeps_only_well_formed_hypotheses():
    out = validate_model_output({
        "hypotheses": [
            {"id": "H1", "claim": "iface down", "likelihood": 1.7,
             "remediation": {"interface": "eth0", "admin": "up"}},
            {"id": "H2", "claim": "rm -rf", "likelihood": 0.4,
             "remediation": {"shell": "reboot"}},                       # not an allowed shape
            {"claim": 12, "likelihood": 0.9},                          # malformed: dropped
            "garbage"],
        "suggested_action": {"op": "system.exec", "change": {"cmd": "reload"}}})
    assert [h["id"] for h in out["hypotheses"]] == ["H1", "H2"]
    assert out["hypotheses"][0]["likelihood"] == 1.0                   # clamped
    assert out["hypotheses"][1]["remediation"] is None                 # stripped
    assert out["suggested_action"] is None                             # unknown op stripped
    for bad in ({}, {"hypotheses": "x"}, {"hypotheses": [{"likelihood": 1}]}, "text"):
        with pytest.raises(SyscallError):
            validate_model_output(bad)


# --- FRR change translation is an allowlist ---------------------------------------------
def test_frr_change_translation_is_allowlisted():
    lab = FrrLab(INV)
    assert lab.commands("lab-r1", {"interface": "eth0", "admin": "up"}) == \
        ["interface eth0", "no shutdown"]
    assert lab.commands("lab-r1", {"neighbor": "10.10.0.3", "hold_time": 90}) == \
        ["router bgp 65001", "neighbor 10.10.0.3 timers 30 90"]
    for bad in ({"interface": "eth9", "admin": "up"},                  # not in inventory
                {"interface": "eth0", "admin": "up; reload"},          # injection attempt
                {"neighbor": "10.10.0.3", "hold_time": "90\nend\nreload"},
                {"neighbor": "8.8.8.8", "hold_time": 90},
                {"interface": "eth0", "admin": "up", "extra": 1}, "no shutdown", None):
        with pytest.raises(ValueError):
            lab.commands("lab-r1", bad)
    assert lab.tenant_of("lab-r1") == "customer-a" and lab.tenant_of("nope") is None


# --- live lab (opt-in) ---------------------------------------------------------------------
def _lab_up() -> bool:
    if os.environ.get("AOS_LAB") != "1":
        return False
    r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", "aos-lab-r1"],
                       capture_output=True, text=True)
    return r.stdout.strip() == "true"


@pytest.mark.skipif(not _lab_up(), reason="set AOS_LAB=1 with labs/frr-bgp/lab.sh up")
def test_live_lab_fault_is_fixed_once_through_the_kernel(tmp_path):
    from agenticos.cli import demo
    os.environ.pop("AOS_MODEL_URL", None)              # deterministic reasoner for CI-like runs
    assert asyncio.run(demo(str(tmp_path / "lab.db"), interactive=False, lab=True)) == 0
    st = json.loads(subprocess.run(
        ["docker", "exec", "aos-lab-r1", "vtysh", "-c", "show bgp neighbors 10.10.0.3 json"],
        capture_output=True, text=True).stdout)["10.10.0.3"]["bgpState"]
    assert st == "Established"


@pytest.mark.skipif(not _lab_up(), reason="set AOS_LAB=1 with labs/frr-bgp/lab.sh up")
def test_live_watch_opens_one_incident_waits_for_human_and_cleans_up(tmp_path):
    """Event-driven mode: real fault -> one incident -> approval from a *separate process*
    -> fixed -> every agent process exits."""
    import sys
    import time
    db = str(tmp_path / "watch.db")
    os.environ.pop("AOS_MODEL_URL", None)
    w = subprocess.Popen([sys.executable, "-m", "agenticos", "watch", "--once", "--interval", "1",
                          "--db", db], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        time.sleep(4)
        subprocess.run(["docker", "exec", "aos-lab-r1", "vtysh", "-c", "conf t", "-c",
                        "interface eth0", "-c", "shutdown"], check=True)
        cli = [sys.executable, "-m", "agenticos"]
        for _ in range(60):
            out = subprocess.run(cli + ["approvals", "--db", db], capture_output=True,
                                 text=True).stdout
            if "apr-" in out:
                break
            time.sleep(1)
        assert "network.config.apply on lab-r1" in out
        # a non-approver (the system monitor itself) is refused
        r = subprocess.run(cli + ["approve", "apr-0001", "--as", "noc-monitor", "--db", db],
                           capture_output=True, text=True)
        assert r.returncode == 1
        subprocess.run(cli + ["approve", "apr-0001", "--as", "bob", "--db", db], check=True)
        log = w.communicate(timeout=120)[0]
    finally:
        if w.poll() is None:
            w.kill()
    assert w.returncode == 0, log
    assert log.count("ALERT") == 1                      # one outage -> one incident
    assert "INC-0001 closed: COMPLETED" in log
    assert "agent processes still running: 0" in log
    st = json.loads(subprocess.run(
        ["docker", "exec", "aos-lab-r1", "vtysh", "-c", "show bgp neighbors 10.10.0.3 json"],
        capture_output=True, text=True).stdout)["10.10.0.3"]["bgpState"]
    assert st == "Established"
