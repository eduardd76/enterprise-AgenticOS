"""ServiceNow change management as a human approval channel.

An AgenticOS approval becomes a real ServiceNow Change Request; the CAB / approvers decide
in ServiceNow, and the decision comes back through the kernel's own checks.

Flow:
  1. post()   — POST /api/now/table/change_request with the kernel-computed review package
                (commands, rollback = backout plan, twin prediction, confidence, evidence),
                correlated to the approval id, then PATCH it to request approval.
  2. fetch()  — poll the change and its sysapproval_approver records (HTTP only).
  3. decide() — on the kernel thread: a mapped approver's "rejected" or "approved" record
                is applied via kernel.approvals.decide(); a reject wins over an approve.
  4. close()  — after execution, close the change successful / unsuccessful.

Identity is the ServiceNow user_name on the *approver record*, never text in the change,
and it must map to an AgenticOS principal with an approver role; the kernel's own checks
(role, tenant, separation of duties) still decide. An overall change "rejected" with no
mapped approver record behind it is not a decision — a human must be identifiable.

Required roles: an integration user with `itil` (or equivalent change_request write and
sysapproval_approver read rights) for basic auth, or an OAuth token for such a user; the
approvers themselves are ordinary ServiceNow users in the change's approval groups.

Outbound-only: AgenticOS polls the Table API; no inbound webhook, no public URL, no
firewall hole. The credentials live only in the kernel process. Sandboxed agents never
see them.
"""

from __future__ import annotations

import asyncio
import base64
import json
import urllib.error
import urllib.parse
import urllib.request

from .errors import SyscallError

LOCAL_HOSTS = ("127.0.0.1", "localhost")
STATE_ASSESS, STATE_CLOSED = "-4", "3"          # change_request.state for a normal change

# Kernel confidence -> ServiceNow risk / impact (choice values of the OOTB change model:
# risk 2 High, 3 Moderate, 4 Low; impact 1 High, 2 Medium, 3 Low).
#   risk:   twin predicts regressions -> High; PROCEED_WITH_WARNING -> Moderate;
#           PROCEED -> Low; anything else -> High (should not reach approval at all).
#   impact: regressions -> High; a production (impact "high") change -> Medium;
#           otherwise Low. The twin prediction, not the agent, drives both.
RISK = {"PROCEED": "4", "PROCEED_WITH_WARNING": "3"}


def risk_impact(pkg: dict) -> tuple[str, str]:
    conf = pkg.get("confidence", {})
    if pkg.get("regressions"):
        return "2", "1"
    return RISK.get(conf.get("decision"), "2"), "2" if conf.get("impact") == "high" else "3"


class ServiceNowError(RuntimeError):
    pass


class ServiceNowApprovalChannel:
    def __init__(self, instance_url: str, approvers: dict[str, str], user: str | None = None,
                 password: str | None = None, token: str | None = None, poll_s: float = 5.0,
                 assignment_group: str | None = None, change_type: str = "normal"):
        u = urllib.parse.urlparse(instance_url)
        if u.scheme != "https" and u.hostname not in LOCAL_HOSTS:
            raise ValueError(f"ServiceNow instance must use https, got {instance_url!r}")
        if token:
            self._auth = f"Bearer {token}"
        elif user and password:
            self._auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        else:
            raise ValueError("ServiceNow credentials required: user+password or OAuth token")
        self.instance_url, self.approvers = instance_url.rstrip("/"), dict(approvers)
        self.poll_s, self.assignment_group, self.change_type = poll_s, assignment_group, change_type
        self.posted: dict[str, tuple[str, str]] = {}   # pending: approval id -> (sys_id, number)
        self.changes: dict[str, tuple[str, str]] = {}  # every change posted, kept for close()
        self.refused: set[tuple[str, str]] = set()     # (approval, user) already answered

    # -- ServiceNow Table API -------------------------------------------------
    def _call(self, method: str, path: str, payload: dict | None = None,
              query: dict | None = None) -> dict:
        url = f"{self.instance_url}/api/now/table/{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data, {
            "Authorization": self._auth, "Accept": "application/json",
            "Content-Type": "application/json"}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                body = json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise ServiceNowError(f"{method} {path}: HTTP {e.code}") from None
        if "result" not in body:
            raise ServiceNowError(f"{method} {path}: {body.get('error', 'no result')}")
        return body["result"]

    # -- outbound: the review package as a Change Request ---------------------
    def post(self, approval_id: str, pkg: dict) -> str:
        cmds = "\n".join(x.lstrip("+- ") for x in pkg.get("diff", []))
        conf = pkg["confidence"]
        rollback = json.dumps(pkg.get("rollback"))
        risk, impact = risk_impact(pkg)
        description = (
            f"AgenticOS approval {approval_id} — {pkg['op']} on {pkg['target']}\n\n"
            f"Rationale (agent, unverified): {pkg.get('rationale')}\n\n"
            f"Commands:\n{cmds}\n\nRollback: {rollback}\n\n"
            f"Twin prediction (kernel): {json.dumps(pkg.get('predicted'))}\n"
            f"Regressions (kernel): {pkg.get('regressions')}\n"
            f"Improves (kernel): {pkg.get('improves')}\n\n"
            f"Confidence: {conf['aggregate']} -> {conf['decision']}\n"
            f"Evidence: {', '.join(pkg.get('evidence_refs', []))}\n"
            f"Intent: {pkg['intent_id']}  ·  Approval: {approval_id}\n\n"
            f"Approve or reject this change in ServiceNow (mapped approvers only).")
        record = {
            "short_description": f"AgenticOS: {pkg['op']} on {pkg['target']}",
            "description": description, "type": self.change_type, "category": "Network",
            "justification": f"{pkg.get('rationale')} (agent-asserted, unverified; twin "
                             f"prediction computed by the kernel)",
            "implementation_plan": cmds, "backout_plan": rollback,
            "test_plan": "independent verifier probes the tenant service",
            "risk": risk, "impact": impact,
            "correlation_id": approval_id, "correlation_display": "AgenticOS"}
        if self.assignment_group:
            record["assignment_group"] = self.assignment_group
        chg = self._call("POST", "change_request", record,
                         {"sysparm_fields": "sys_id,number"})
        self.posted[approval_id] = self.changes[approval_id] = (chg["sys_id"], chg["number"])
        # Request approval. Real instances usually drive this from the change workflow /
        # flow, which may ignore or override these field writes — that is fine: we only
        # read the approver records it creates.
        patch = {"approval": "requested"}
        if self.change_type == "normal":
            patch["state"] = STATE_ASSESS
        self._call("PATCH", f"change_request/{chg['sys_id']}", patch,
                   {"sysparm_fields": "sys_id"})
        return chg["number"]

    def _note(self, approval_id: str, text: str) -> None:
        """Work note on the change — the analogue of a Slack thread reply. Best effort."""
        try:
            sys_id, _ = self.changes[approval_id]
            self._call("PATCH", f"change_request/{sys_id}", {"work_notes": text},
                       {"sysparm_fields": "sys_id"})
        except (ServiceNowError, OSError, KeyError):
            pass

    # -- inbound: decisions via approver records --------------------------------
    # Split by thread affinity: fetch() does HTTP only (safe in a worker thread); decide()
    # touches the kernel and its SQLite store, so it must run on the kernel's own thread.
    def fetch(self, approval_id: str) -> dict:
        sys_id, _ = self.changes[approval_id]
        chg = self._call("GET", f"change_request/{sys_id}", query={
            "sysparm_fields": "approval,state,number", "sysparm_display_value": "false"})
        recs = self._call("GET", "sysapproval_approver", query={
            "sysparm_query": f"sysapproval={sys_id}",
            "sysparm_fields": "state,approver.user_name,comments",
            "sysparm_display_value": "false"})
        return {"approval": chg.get("approval"), "state": chg.get("state"),
                "approvers": [{"user": r.get("approver.user_name"), "state": r.get("state")}
                              for r in recs]}

    def decide(self, kernel, approval_id: str, fetched: dict) -> tuple[str | None, list[str]]:
        """Apply approver records through the kernel. Returns (verdict or None, work notes)."""
        notes: list[str] = []
        number = self.changes.get(approval_id, ("", approval_id))[1]
        decided_by_mapped = False
        for wanted, approve in (("rejected", False), ("approved", True)):  # reject wins
            for rec in fetched.get("approvers", []):
                user, state = rec.get("user"), rec.get("state")
                if state != wanted:
                    continue
                principal = self.approvers.get(user)
                if principal is None:
                    if (approval_id, user) not in self.refused:
                        self.refused.add((approval_id, user))
                        notes.append(f"{user} is not a mapped AgenticOS approver — ignored.")
                    continue
                decided_by_mapped = True
                try:
                    kernel.approvals.decide(approval_id, principal, approve,
                                            f"servicenow {number} user {user} ({state})")
                except SyscallError as e:
                    if (approval_id, user) not in self.refused:
                        self.refused.add((approval_id, user))
                        notes.append(f"{user} refused by kernel: {e.message}")
                    continue
                verdict = "approved" if approve else "denied"
                notes.append(f"AgenticOS approval {approval_id} {verdict} by {user} "
                             f"({principal}). Recorded in the audit log.")
                return verdict, notes
        if fetched.get("approval") == "rejected" and not decided_by_mapped and \
                (approval_id, "*change*") not in self.refused:
            self.refused.add((approval_id, "*change*"))
            notes.append("Change rejected without a mapped approver record — AgenticOS "
                         "approval left pending (a mapped human must decide).")
        return None, notes

    def _status(self, kernel, approval_id: str) -> str | None:
        row = kernel.store.one("SELECT status FROM approvals WHERE approval_id=?", (approval_id,))
        return row["status"] if row else None

    def check(self, kernel, approval_id: str) -> str | None:
        """Synchronous one-shot (single-threaded callers and tests)."""
        status = self._status(kernel, approval_id)
        if status != "pending":
            return status
        verdict, notes = self.decide(kernel, approval_id, self.fetch(approval_id))
        for n in notes:
            self._note(approval_id, n)
        return verdict

    async def run(self, kernel) -> None:
        """Background loop: HTTP in worker threads, kernel decisions on the kernel thread."""
        while True:
            for aid in list(self.posted):
                if self._status(kernel, aid) != "pending":
                    self.posted.pop(aid, None)
                    continue
                try:
                    fetched = await asyncio.to_thread(self.fetch, aid)
                except (ServiceNowError, OSError) as e:
                    kernel.store.audit("approval.channel_error", approval_id=aid,
                                       channel="servicenow", error=str(e)[:200])
                    continue
                verdict, notes = self.decide(kernel, aid, fetched)
                for n in notes:
                    await asyncio.to_thread(self._note, aid, n)
                if verdict:
                    self.posted.pop(aid, None)
            await asyncio.sleep(self.poll_s)

    # -- after execution ----------------------------------------------------------
    def close(self, approval_id: str, outcome: str, success: bool) -> bool:
        """Close the change with the execution outcome. HTTP only, best effort."""
        if approval_id not in self.changes:
            return False
        sys_id, _ = self.changes[approval_id]
        try:
            self._call("PATCH", f"change_request/{sys_id}", {
                "work_notes": f"AgenticOS execution outcome: {outcome}",
                "state": STATE_CLOSED,
                "close_code": "successful" if success else "unsuccessful",
                "close_notes": outcome}, {"sysparm_fields": "sys_id"})
            return True
        except (ServiceNowError, OSError):
            return False


def load_servicenow_approvers(path: str) -> dict[str, str]:
    """JSON: {"servicenow": {"bob.smith": "bob"}} — ServiceNow user_name -> principal."""
    with open(path) as f:
        return json.load(f).get("servicenow", {})
