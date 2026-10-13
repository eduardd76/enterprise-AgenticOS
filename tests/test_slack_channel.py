"""Slack approval channel against a local fake of the Slack Web API (no network needed)."""

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from agenticos.channels import SlackApprovalChannel
from agenticos.confidence import COMPONENTS
from conftest import agent, make_kernel

TOKEN = "xoxb-test-token"


class FakeSlack:
    def __init__(self):
        self.messages, self.replies, self.calls = {}, [], []
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, body):
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(data)

            def _authed(self):
                return self.headers.get("Authorization") == f"Bearer {TOKEN}"

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.calls.append((self.path, body))
                if not self._authed():
                    return self._send({"ok": False, "error": "invalid_auth"})
                if self.path == "/chat.postMessage":
                    if "thread_ts" in body:
                        fake.replies.append(body["text"])
                        return self._send({"ok": True, "ts": "r"})
                    ts = f"{len(fake.messages) + 1}.000"
                    fake.messages[ts] = {"text": body["text"], "reactions": {}}
                    return self._send({"ok": True, "ts": ts})
                self._send({"ok": False, "error": "unknown_method"})

            def do_GET(self):
                u = urlparse(self.path)
                q = parse_qs(u.query)
                if not self._authed():
                    return self._send({"ok": False, "error": "invalid_auth"})
                m = fake.messages[q["timestamp"][0]]
                self._send({"ok": True, "message": {"reactions": [
                    {"name": n, "users": us} for n, us in m["reactions"].items()]}})

        self.server = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def react(self, ts, name, user):
        self.messages[ts]["reactions"].setdefault(name, []).append(user)


@pytest.fixture
def slack():
    s = FakeSlack()
    yield s
    s.server.shutdown()


async def _pending_approval(k, aid_agent):
    ev = await k.gateway.dispatch(aid_agent, "network.bgp.inspect", "router-edge-01",
                                  {"neighbor": "192.0.2.1"})
    c = (await k.gateway.dispatch(aid_agent, "confidence.evaluate", "", {
        "components": {n: .95 for n in COMPONENTS}, "for_op": "network.config.apply",
        "evidence_refs": [ev["evidence_ref"]]}))["result"]
    req = asyncio.create_task(k.gateway.dispatch(aid_agent, "approval.request", "router-edge-01", {
        "op": "network.config.apply", "change": {"interface": "Gi0/0/0/1", "admin": "up"},
        "confidence_ref": c["confidence_id"], "rationale": "iface down", "timeout_s": 10}))
    await asyncio.sleep(0.05)
    row = k.store.one("SELECT approval_id, package FROM approvals ORDER BY ts DESC LIMIT 1")
    return req, row["approval_id"], json.loads(row["package"])


def test_slack_reaction_from_mapped_approver_decides(run, slack):
    async def t():
        k = make_kernel()
        k.netsim.inject("interface_shutdown", "router-edge-01", interface="Gi0/0/0/1")
        rw = agent(k, prod=True)
        ch = SlackApprovalChannel(TOKEN, "C-NOC", {"U-BOB": "bob", "U-CAROL": "carol"},
                                  api_base=slack.url)
        req, apr, pkg = await _pending_approval(k, rw)
        ts = ch.post(apr, pkg)
        posted = slack.messages[ts]["text"]
        assert apr in posted and "Twin prediction" in posted and "*Commands*" in posted
        assert "agent, unverified" in posted                     # rationale is labelled

        slack.react(ts, "white_check_mark", "U-STRANGER")          # unmapped -> ignored
        slack.react(ts, "white_check_mark", "U-CAROL")             # mapped, but not an approver
        assert ch.check(k, apr) is None
        assert any("not a mapped approver" in r for r in slack.replies)
        assert any("refused by kernel" in r for r in slack.replies)

        slack.react(ts, "white_check_mark", "U-BOB")
        assert ch.check(k, apr) == "approved"
        assert (await req)["result"]["status"] == "approved"
        audit = json.loads(k.store.one("SELECT data FROM audit WHERE event='approval.decided'")
                           ["data"])
        assert audit["approver"] == "bob" and "slack user U-BOB" in audit["note"]
    run(t())


def test_slack_deny_wins_and_bad_token_fails_closed(run, slack):
    async def t():
        k = make_kernel()
        rw = agent(k, prod=True)
        ch = SlackApprovalChannel(TOKEN, "C-NOC", {"U-BOB": "bob"}, api_base=slack.url)
        req, apr, pkg = await _pending_approval(k, rw)
        ts = ch.post(apr, pkg)
        slack.react(ts, "white_check_mark", "U-BOB")
        slack.react(ts, "x", "U-BOB")                              # conflicting: deny wins
        assert ch.check(k, apr) == "denied"
        assert (await asyncio.gather(req, return_exceptions=True))[0].code == "APPROVAL_DENIED"

        bad = SlackApprovalChannel("xoxb-wrong", "C-NOC", {}, api_base=slack.url)
        from agenticos.channels import SlackError
        with pytest.raises(SlackError):
            bad.post("apr-x", pkg)
    run(t())


def test_requester_cannot_approve_own_change_even_via_slack(run, slack):
    async def t():
        k = make_kernel()
        k.add_principal("alice", "customer-a", ["noc-operator", "noc-lead"],
                        k.principals["alice"]["authority"])          # alice is also a lead
        rw = agent(k, prod=True)                                     # intent submitted by alice
        ch = SlackApprovalChannel(TOKEN, "C-NOC", {"U-ALICE": "alice"}, api_base=slack.url)
        req, apr, pkg = await _pending_approval(k, rw)
        ts = ch.post(apr, pkg)
        slack.react(ts, "white_check_mark", "U-ALICE")
        assert ch.check(k, apr) is None
        assert any("separation of duties" in r for r in slack.replies)
        req.cancel()
    run(t())


def test_channel_requires_token():
    with pytest.raises(ValueError):
        SlackApprovalChannel("", "C", {})
