"""Human approval channels: where approval requests reach people, and how decisions come back.

SlackApprovalChannel posts the kernel-computed review package to a channel and polls for a
reaction from a *mapped* approver: :white_check_mark: approves, :x: denies. It is
outbound-only — no public URL, no inbound firewall hole — so it works on-prem and
air-gap-adjacent (Slack egress only). The approver's identity is the Slack user id Slack
reports, never text in the message, and it must map to a principal with an approver role;
the kernel's own checks (role, tenant, separation of duties) still decide.

The bot token lives only in the kernel process. Sandboxed agents never see it.
Required bot scopes: chat:write, reactions:read.
"""

from __future__ import annotations

import asyncio
import json
import urllib.parse
import urllib.request

from .errors import SyscallError

APPROVE, DENY = "white_check_mark", "x"


class SlackError(RuntimeError):
    pass


class SlackApprovalChannel:
    def __init__(self, token: str, channel: str, approvers: dict[str, str],
                 api_base: str = "https://slack.com/api", poll_s: float = 3.0):
        if not token:
            raise ValueError("Slack bot token required (SLACK_BOT_TOKEN)")
        if token.startswith("xoxp-"):
            raise ValueError("that is a *user* token (xoxp-), which acts as a person with their "
                             "full rights. Use the Bot User OAuth Token (xoxb-) from "
                             "OAuth & Permissions, and revoke the user token.")
        self.token, self.channel, self.approvers = token, channel, dict(approvers)
        self.api_base, self.poll_s = api_base.rstrip("/"), poll_s
        self.posted: dict[str, str] = {}          # approval id -> message ts
        self.refused: set[tuple[str, str]] = set()  # (approval, slack user) already answered

    # -- Slack Web API ------------------------------------------------------
    def _call(self, method: str, payload: dict | None = None, query: dict | None = None) -> dict:
        url = f"{self.api_base}/{method}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data, {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json; charset=utf-8"})
        with urllib.request.urlopen(req, timeout=10) as r:
            body = json.loads(r.read())
        if not body.get("ok"):
            raise SlackError(f"{method}: {body.get('error', 'unknown error')}")
        return body

    # -- outbound: the review package ---------------------------------------
    def post(self, approval_id: str, pkg: dict) -> str:
        cmds = " ; ".join(x.lstrip("+- ") for x in pkg.get("diff", []))
        conf = pkg["confidence"]
        text = (f":rotating_light: *Approval required* `{approval_id}` — `{pkg['op']}` on "
                f"`{pkg['target']}`\n"
                f"*Rationale* (agent, unverified): {pkg.get('rationale')}\n"
                f"*Commands*: `{cmds}`\n*Rollback*: `{json.dumps(pkg.get('rollback'))}`\n"
                f"*Twin prediction* (kernel): `{json.dumps(pkg.get('predicted'))}`  "
                f"regressions: `{pkg.get('regressions')}`\n"
                f"*Confidence*: {conf['aggregate']} → {conf['decision']}\n"
                f"*Evidence*: {', '.join(pkg.get('evidence_refs', []))}  ·  "
                f"intent `{pkg['intent_id']}`\n"
                f"React :white_check_mark: to approve or :x: to deny (approvers only).")
        msg = self._call("chat.postMessage", {"channel": self.channel, "text": text,
                                              "unfurl_links": False})
        self.posted[approval_id] = msg["ts"]
        return msg["ts"]

    def _reply(self, approval_id: str, text: str) -> None:
        try:
            self._call("chat.postMessage", {"channel": self.channel, "text": text,
                                            "thread_ts": self.posted[approval_id]})
        except (SlackError, OSError):
            pass

    # -- inbound: decisions via reactions ------------------------------------
    # Split by thread affinity: fetch() does HTTP only (safe in a worker thread); decide()
    # touches the kernel and its SQLite store, so it must run on the kernel's own thread.
    def fetch(self, approval_id: str) -> dict[str, list[str]]:
        msg = self._call("reactions.get", query={"channel": self.channel, "full": "true",
                                                 "timestamp": self.posted[approval_id]})
        return {r["name"]: r.get("users", []) for r in msg["message"].get("reactions", [])}

    def decide(self, kernel, approval_id: str,
               reactions: dict[str, list[str]]) -> tuple[str | None, list[str]]:
        """Apply reactions through the kernel. Returns (verdict or None, thread replies)."""
        replies: list[str] = []
        for name, approve in ((DENY, False), (APPROVE, True)):    # a deny wins over an approve
            for user in reactions.get(name, []):
                principal = self.approvers.get(user)
                if principal is None:
                    if (approval_id, user) not in self.refused:
                        self.refused.add((approval_id, user))
                        replies.append(f"<@{user}> is not a mapped approver — ignored.")
                    continue
                try:
                    kernel.approvals.decide(approval_id, principal, approve,
                                            f"slack user {user} (:{name}:)")
                except SyscallError as e:
                    if (approval_id, user) not in self.refused:
                        self.refused.add((approval_id, user))
                        replies.append(f"<@{user}> refused by kernel: {e.message}")
                    continue
                verdict = "approved" if approve else "denied"
                replies.append(f"{'✅' if approve else '❌'} *{verdict}* by <@{user}> "
                               f"({principal}). Recorded in the audit log.")
                return verdict, replies
        return None, replies

    def _status(self, kernel, approval_id: str) -> str | None:
        row = kernel.store.one("SELECT status FROM approvals WHERE approval_id=?", (approval_id,))
        return row["status"] if row else None

    def check(self, kernel, approval_id: str) -> str | None:
        """Synchronous one-shot (single-threaded callers and tests)."""
        status = self._status(kernel, approval_id)
        if status != "pending":
            return status
        verdict, replies = self.decide(kernel, approval_id, self.fetch(approval_id))
        for r in replies:
            self._reply(approval_id, r)
        return verdict

    async def run(self, kernel) -> None:
        """Background loop: HTTP in worker threads, kernel decisions on the kernel thread."""
        while True:
            for aid in list(self.posted):
                if self._status(kernel, aid) != "pending":
                    self.posted.pop(aid, None)
                    continue
                try:
                    reactions = await asyncio.to_thread(self.fetch, aid)
                except (SlackError, OSError) as e:
                    kernel.store.audit("approval.channel_error", approval_id=aid,
                                       channel="slack", error=str(e)[:200])
                    continue
                verdict, replies = self.decide(kernel, aid, reactions)
                for r in replies:
                    await asyncio.to_thread(self._reply, aid, r)
                if verdict:
                    self.posted.pop(aid, None)
            await asyncio.sleep(self.poll_s)


def load_approvers(path: str) -> dict[str, str]:
    """JSON: {"slack": {"U0123ABC": "bob"}} — Slack user id -> AgenticOS principal."""
    with open(path) as f:
        return json.load(f).get("slack", {})

