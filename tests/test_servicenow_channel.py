"""ServiceNow change approval channel against a local fake of the Table API (no network)."""

import asyncio
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from agenticos.servicenow import (ServiceNowApprovalChannel, ServiceNowError,
                                  load_servicenow_approvers)
from conftest import agent, make_kernel
from test_slack_channel import _pending_approval

USER, PASSWORD = "svc.agenticos", "s3cret"
AUTH = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()


class FakeServiceNow:
    """change_request POST/GET/PATCH and sysapproval_approver GET, basic auth."""

    def __init__(self):
        self.changes, self.approvals, self.calls = {}, [], []
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, body, code=200):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _route(self):
                if self.headers.get("Authorization") != AUTH:
                    self._send({"error": {"message": "User Not Authenticated"}}, 401)
                    return None
                u = urlparse(self.path)
                parts = u.path.removeprefix("/api/now/table/").split("/")
                return parts[0], (parts[1] if len(parts) > 1 else None), parse_qs(u.query)

            def _body(self):
                return json.loads(self.rfile.read(int(self.headers["Content-Length"])))

            def do_POST(self):
                body = self._body()
                if (r := self._route()) is None:
                    return
                table, _, _ = r
                fake.calls.append(("POST", table, body))
                n = len(fake.changes) + 1
                sys_id, number = f"sys{n:04d}", f"CHG{n:07d}"
                fake.changes[sys_id] = {**body, "sys_id": sys_id, "number": number,
                                        "approval": "not requested", "state": "-5",
                                        "work_notes": []}
                self._send({"result": {"sys_id": sys_id, "number": number}}, 201)

            def do_PATCH(self):
                body = self._body()
                if (r := self._route()) is None:
                    return
                table, sys_id, _ = r
                fake.calls.append(("PATCH", sys_id, body))
                chg = fake.changes.get(sys_id)
                if chg is None:
                    return self._send({"error": {"message": "No Record found"}}, 404)
                for key, v in body.items():
                    if key == "work_notes":
                        chg["work_notes"].append(v)
                    else:
                        chg[key] = v
                self._send({"result": {"sys_id": sys_id}})

            def do_GET(self):
                if (r := self._route()) is None:
                    return
                table, sys_id, q = r
                if table == "change_request":
                    chg = fake.changes[sys_id]
                    fields = q["sysparm_fields"][0].split(",")
                    return self._send({"result": {f: chg.get(f) for f in fields}})
                want = q["sysparm_query"][0].removeprefix("sysapproval=")
                self._send({"result": [
                    {"state": a["state"], "approver.user_name": a["user"], "comments": ""}
                    for a in fake.approvals if a["sysapproval"] == want]})

        self.server = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def vote(self, sys_id, user, state):
        self.approvals.append({"sysapproval": sys_id, "user": user, "state": state})

    def notes(self, sys_id):
        return self.changes[sys_id]["work_notes"]


@pytest.fixture
def snow():
    s = FakeServiceNow()
    yield s
    s.server.shutdown()


def _channel(snow, approvers, **kw):
    return ServiceNowApprovalChannel(snow.url, approvers, user=USER, password=PASSWORD, **kw)


def test_change_request_carries_the_kernel_package(run, snow):
    async def t():
        k = make_kernel()
        k.netsim.inject("interface_shutdown", "router-edge-01", interface="Gi0/0/0/1")
        rw = agent(k, prod=True)
        ch = _channel(snow, {"bob.smith": "bob"}, assignment_group="network-cab")
        req, apr, pkg = await _pending_approval(k, rw)
        number = ch.post(apr, pkg)
        sys_id, num = ch.changes[apr]
        chg = snow.changes[sys_id]
        assert number == num == chg["number"]
        assert chg["short_description"] == f"AgenticOS: {pkg['op']} on {pkg['target']}"
        assert "Twin prediction (kernel)" in chg["description"]
        assert "agent, unverified" in chg["description"] and apr in chg["description"]
        assert chg["implementation_plan"] and chg["implementation_plan"] in chg["description"]
        assert chg["backout_plan"] == json.dumps(pkg["rollback"])
        assert chg["correlation_id"] == apr and chg["correlation_display"] == "AgenticOS"
        assert chg["category"] == "Network" and chg["type"] == "normal"
        assert chg["assignment_group"] == "network-cab"
        assert chg["risk"] == "4" and chg["impact"] == "2"     # PROCEED, production change
        assert chg["approval"] == "requested" and chg["state"] == "-4"
        req.cancel()
    run(t())


def test_mapped_approver_in_servicenow_decides(run, snow):
    async def t():
        k = make_kernel()
        k.netsim.inject("interface_shutdown", "router-edge-01", interface="Gi0/0/0/1")
        rw = agent(k, prod=True)
        ch = _channel(snow, {"bob.smith": "bob", "carol.jones": "carol"})
        req, apr, pkg = await _pending_approval(k, rw)
        ch.post(apr, pkg)
        sys_id, number = ch.changes[apr]

        snow.vote(sys_id, "eve.stranger", "approved")             # unmapped -> ignored
        snow.vote(sys_id, "carol.jones", "approved")              # mapped, not an approver
        assert ch.check(k, apr) is None
        assert ch.check(k, apr) is None                            # noted once, not twice
        notes = snow.notes(sys_id)
        assert sum("not a mapped AgenticOS approver" in n for n in notes) == 1
        assert sum("refused by kernel" in n for n in notes) == 1

        snow.vote(sys_id, "bob.smith", "approved")
        assert ch.check(k, apr) == "approved"
        assert (await req)["result"]["status"] == "approved"
        audit = json.loads(k.store.one("SELECT data FROM audit WHERE event='approval.decided'")
                           ["data"])
        assert audit["approver"] == "bob"
        assert audit["note"] == f"servicenow {number} user bob.smith (approved)"
        assert any("approved by bob.smith" in n for n in snow.notes(sys_id))
    run(t())


def test_rejection_wins_and_overall_reject_needs_a_mapped_human(run, snow):
    async def t():
        k = make_kernel()
        rw = agent(k, prod=True)
        ch = _channel(snow, {"bob.smith": "bob"})
        req, apr, pkg = await _pending_approval(k, rw)
        ch.post(apr, pkg)
        sys_id, _ = ch.changes[apr]

        snow.changes[sys_id]["approval"] = "rejected"              # no approver record behind it
        assert ch.check(k, apr) is None
        assert any("without a mapped approver" in n for n in snow.notes(sys_id))

        snow.vote(sys_id, "bob.smith", "approved")
        snow.vote(sys_id, "bob.smith", "rejected")                 # conflicting: reject wins
        assert ch.check(k, apr) == "denied"
        assert (await asyncio.gather(req, return_exceptions=True))[0].code == "APPROVAL_DENIED"
    run(t())


def test_requester_cannot_approve_own_change_even_via_servicenow(run, snow):
    async def t():
        k = make_kernel()
        k.add_principal("alice", "customer-a", ["noc-operator", "noc-lead"],
                        k.principals["alice"]["authority"])          # alice is also a lead
        rw = agent(k, prod=True)                                     # intent submitted by alice
        ch = _channel(snow, {"alice.w": "alice"})
        req, apr, pkg = await _pending_approval(k, rw)
        ch.post(apr, pkg)
        sys_id, _ = ch.changes[apr]
        snow.vote(sys_id, "alice.w", "approved")
        assert ch.check(k, apr) is None
        assert any("separation of duties" in n for n in snow.notes(sys_id))
        req.cancel()
    run(t())


def test_close_records_the_outcome(run, snow):
    async def t():
        k = make_kernel()
        rw = agent(k, prod=True)
        ch = _channel(snow, {"bob.smith": "bob"})
        req, apr, pkg = await _pending_approval(k, rw)
        ch.post(apr, pkg)
        sys_id, _ = ch.changes[apr]
        assert ch.close(apr, "verifier: service reachable", True)
        chg = snow.changes[sys_id]
        assert chg["state"] == "3" and chg["close_code"] == "successful"
        assert chg["close_notes"] == "verifier: service reachable"
        assert any("execution outcome" in n for n in chg["work_notes"])
        assert ch.close(apr, "rolled back", False)
        assert snow.changes[sys_id]["close_code"] == "unsuccessful"
        assert ch.close("apr-unknown", "x", True) is False
        req.cancel()
    run(t())


def test_run_loop_end_to_end(run, snow):
    async def t():
        k = make_kernel()
        k.netsim.inject("interface_shutdown", "router-edge-01", interface="Gi0/0/0/1")
        rw = agent(k, prod=True)
        ch = _channel(snow, {"bob.smith": "bob"}, poll_s=0.02)
        req, apr, pkg = await _pending_approval(k, rw)
        ch.post(apr, pkg)
        loop = asyncio.create_task(ch.run(k))
        await asyncio.sleep(0.1)
        assert apr in ch.posted                                    # still waiting for a human
        snow.vote(ch.changes[apr][0], "bob.smith", "approved")
        assert (await asyncio.wait_for(req, 5))["result"]["status"] == "approved"
        await asyncio.sleep(0.1)
        assert apr not in ch.posted                                # forgotten once decided
        loop.cancel()
    run(t())


def test_run_loop_audits_channel_errors(run, snow):
    async def t():
        k = make_kernel()
        rw = agent(k, prod=True)
        ch = _channel(snow, {"bob.smith": "bob"}, poll_s=0.02)
        req, apr, pkg = await _pending_approval(k, rw)
        ch.post(apr, pkg)
        ch._auth = "Basic d3Jvbmc6d3Jvbmc="                        # credentials revoked
        loop = asyncio.create_task(ch.run(k))
        await asyncio.sleep(0.1)
        loop.cancel()
        row = k.store.one("SELECT data FROM audit WHERE event='approval.channel_error'")
        assert json.loads(row["data"])["channel"] == "servicenow"
        req.cancel()
    run(t())


def test_bad_credentials_fail_closed(run, snow):
    async def t():
        k = make_kernel()
        rw = agent(k, prod=True)
        req, apr, pkg = await _pending_approval(k, rw)
        bad = ServiceNowApprovalChannel(snow.url, {}, user=USER, password="wrong")
        with pytest.raises(ServiceNowError, match="401"):
            bad.post(apr, pkg)
        assert not snow.changes
        req.cancel()
    run(t())


def test_credentials_and_https_required():
    with pytest.raises(ValueError, match="credentials"):
        ServiceNowApprovalChannel("https://acme.service-now.com", {})
    with pytest.raises(ValueError, match="credentials"):
        ServiceNowApprovalChannel("https://acme.service-now.com", {}, user="u")
    with pytest.raises(ValueError, match="https"):
        ServiceNowApprovalChannel("http://acme.service-now.com", {}, user="u", password="p")
    ServiceNowApprovalChannel("https://acme.service-now.com", {}, token="oauth-token")
    ServiceNowApprovalChannel("http://localhost:8080", {}, user="u", password="p")


def test_load_servicenow_approvers(tmp_path):
    p = tmp_path / "approvers.json"
    p.write_text(json.dumps({"slack": {"U0123": "bob"}, "servicenow": {"bob.smith": "bob"}}))
    assert load_servicenow_approvers(str(p)) == {"bob.smith": "bob"}
