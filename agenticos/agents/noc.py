"""AI NOC user-space agents (vExpertAI §4): BGP neighbor down -> diagnose -> remediate -> verify.

Agents are written as resumable stage machines: every completed step is checkpointed, so
a crash-restarted agent continues where it stopped instead of redoing work.
"""

from __future__ import annotations

from ..sdk import Agent, SyscallFailed

BASE = ["checkpoint.*", "ipc.send", "ipc.recv"]


class ChildFailed(Exception):
    pass


class Coordinator(Agent):
    def run(self, cp: dict | None) -> dict:
        s = self.sys
        st = cp or {"stage": "start"}
        dev, nbr = self.params["device"], self.params["neighbor"]
        inc, tenant = self.params["incident_id"], self.boot["tenant"]
        evidence_paths = [f"/aos/tenants/{tenant}/evidence/*"]

        if st["stage"] == "start":
            diag = s.call("agent.spawn", "noc.bgp_diag", role="bgp-diagnosis", grant={
                "capabilities": BASE + ["network.bgp.inspect", "network.interface.inspect",
                                        "model.infer", "confidence.evaluate", "memory.read"],
                "targets": [dev], "memory_paths": evidence_paths,
                "budget_calls": 30, "budget_tokens": 4000, "ttl_s": 120})["result"]["agent_id"]
            st = {"stage": "spawned_diag", "diag": diag}
            s.checkpoint(st)
        if st["stage"] == "spawned_diag":
            s.send(st["diag"], "DIAGNOSIS_REQUEST", {"device": dev, "neighbor": nbr},
                   correlation_id=inc, message_id=f"{inc}-diagnosis-request")
            st["stage"] = "diagnosing"
            s.checkpoint(st)
        if st["stage"] == "diagnosing":
            m = self._await("DIAGNOSIS_RESULT", 60)
            st.update(stage="diagnosed", diagnosis=m["payload"], refs=m["evidence_refs"])
            s.checkpoint(st)

        selected = st["diagnosis"]["selected"]
        if st["stage"] == "diagnosed":
            if not selected.get("remediation") or \
                    st["diagnosis"]["confidence_decision"] not in ("PROCEED", "PROCEED_WITH_WARNING"):
                return self._report(st, "escalated: no safe automated remediation")
            change = s.call("agent.spawn", "noc.change", role="change-execution", grant={
                "capabilities": BASE + ["network.config.get", "network.config.diff",
                                        "twin.simulate", "confidence.evaluate",
                                        "approval.request", "network.config.apply"],
                "targets": [dev], "production_write": True,
                "budget_calls": 20, "budget_tokens": 1000, "ttl_s": 180})["result"]["agent_id"]
            st.update(stage="spawned_change", change_agent=change)
            s.checkpoint(st)
        if st["stage"] == "spawned_change":
            s.send(st["change_agent"], "REMEDIATION_REQUEST",
                   {"device": dev, "neighbor": nbr, "change": selected["remediation"],
                    "hypothesis": selected, "diagnosis_confidence": st["diagnosis"]["confidence"]},
                   correlation_id=inc, message_id=f"{inc}-remediation-request",
                   evidence_refs=st["refs"])
            st["stage"] = "remediating"
            s.checkpoint(st)
        if st["stage"] == "remediating":
            m = self._await("REMEDIATION_RESULT", 180)
            st.update(stage="remediated", remediation=m["payload"])
            s.checkpoint(st)
            if not m["payload"].get("applied"):
                return self._report(st, "remediation not applied")
        if st["stage"] == "remediated":
            ver = s.call("agent.spawn", "noc.verifier", role="post-change-verification", grant={
                "capabilities": BASE + ["network.bgp.inspect"], "targets": [dev],
                "budget_calls": 6, "budget_tokens": 0, "ttl_s": 60})["result"]["agent_id"]
            s.send(ver, "VERIFY_REQUEST", {"device": dev, "neighbor": nbr},
                   correlation_id=inc, message_id=f"{inc}-verify-request")
            st.update(stage="verifying", verifier=ver)
            s.checkpoint(st)
        if st["stage"] == "verifying":
            m = self._await("VERIFY_RESULT", 60)
            st.update(stage="verified", verification=m["payload"])
            s.checkpoint(st)
        outcome = "resolved" if st["verification"]["healthy"] else "remediation did not restore service"
        return self._report(st, outcome)

    def _await(self, msg_type: str, timeout_s: float) -> dict:
        """Wait for a reply, but fail fast if a child dies first (CHILD_EXITED ~ SIGCHLD)."""
        inc = self.params["incident_id"]
        while True:
            m = self.sys.recv(timeout_s=timeout_s)
            if m["type"] == msg_type and m["correlation_id"] == inc:
                return m
            if m["type"] == "CHILD_EXITED" and m["source"] == "kernel" and \
                    m["payload"]["state"] != "COMPLETED":
                raise ChildFailed(f"{m['payload']['child']} {m['payload']['state']}: "
                                  f"{m['payload']['reason']}")

    def _report(self, st: dict, outcome: str) -> dict:
        tenant, inc = self.boot["tenant"], self.params["incident_id"]
        report = {"incident_id": inc, "outcome": outcome, "diagnosis": st.get("diagnosis"),
                  "remediation": st.get("remediation"), "verification": st.get("verification"),
                  "evidence_refs": st.get("refs", [])}
        w = self.sys.call("memory.write", f"/aos/tenants/{tenant}/incidents/{inc}", data=report)
        return {"outcome": outcome, "report_ref": w["result"]["evidence_id"]}


class BgpDiagnostic(Agent):
    def run(self, cp: dict | None) -> dict:
        s = self.sys
        st = cp or {"refs": []}
        if "request" not in st:
            st["request"] = s.recv(timeout_s=60, type="DIAGNOSIS_REQUEST")
            s.checkpoint(st)
        req = st["request"]["payload"]
        dev, nbr = req["device"], req["neighbor"]

        if "bgp" not in st:
            r = s.call("network.bgp.inspect", dev, neighbor=nbr)
            st["bgp"] = r["result"]
            st["refs"].append(r["evidence_ref"])
            s.checkpoint(st)
        if "iface" not in st:
            r = s.call("network.interface.inspect", dev, interface=st["bgp"]["interface"])
            st["iface"] = r["result"]
            st["refs"].append(r["evidence_ref"])
            s.checkpoint(st)
        if "model" not in st:
            r = s.call("model.infer", task="bgp_diagnosis",
                       evidence={"bgp": st["bgp"], "interface": st["iface"]})
            st["model"] = r["result"]
            st["model_provider"] = r["provider"]
            st["refs"].append(r["evidence_ref"])
            s.checkpoint(st)

        # The model suggests acting directly. A bare agent framework would just run it;
        # under AOS the kernel decides, and this agent was never granted production writes.
        suggestion = st["model"].get("suggested_action")
        if suggestion and "overreach" not in st:
            try:
                s.call(suggestion["op"], dev, change=suggestion["change"],
                       idempotency_key="model-suggested")
                st["overreach"] = "EXECUTED"
            except SyscallFailed as e:
                st["overreach"] = e.code
            s.checkpoint(st)

        # Deterministic validation of the leading hypothesis against observed evidence.
        hyps = sorted(st["model"]["hypotheses"], key=lambda h: -h["likelihood"])
        best = hyps[0]
        rem = best.get("remediation") or {}
        verified = (rem.get("interface") and st["iface"]["admin"] == "down") or \
                   (rem.get("neighbor") and st["bgp"].get("hold_time") == 0)
        same_snapshot = st["bgp"]["snapshot_version"] == st["iface"]["snapshot_version"]
        c = s.call("confidence.evaluate", subject=best["id"], evidence_refs=st["refs"],
                   components={"intent": 0.95, "context": 0.9,
                               "data": 0.95 if same_snapshot else 0.6,
                               "model": best["likelihood"], "capability": 0.9, "policy": 1.0,
                               "execution": 0.95 if verified else 0.3, "temporal": 0.95})["result"]
        s.send(st["request"]["source"], "DIAGNOSIS_RESULT",
               {"hypotheses": hyps, "selected": best, "validated": bool(verified),
                "confidence_ref": c["confidence_id"], "confidence": c["aggregate"],
                "confidence_decision": c["decision"], "model_overreach": st["overreach"]},
               correlation_id=st["request"]["correlation_id"],
               message_id=f"{st['request']['correlation_id']}-diagnosis-result",
               evidence_refs=st["refs"])
        return {"selected": best["id"], "decision": c["decision"], "overreach": st["overreach"]}


class ChangeAgent(Agent):
    def run(self, cp: dict | None) -> dict:
        s = self.sys
        st = cp or {}
        if "request" not in st:
            st["request"] = s.recv(timeout_s=120, type="REMEDIATION_REQUEST")
            s.checkpoint(st)
        m = st["request"]
        req, inc = m["payload"], m["correlation_id"]
        dev, nbr, change = req["device"], req["neighbor"], req["change"]

        if "twin" not in st:
            st["diff"] = s.call("network.config.diff", dev, change=change)["result"]["diff"]
            st["twin"] = s.call("twin.simulate", dev, change=change)["result"]
            s.checkpoint(st)
        twin = st["twin"]
        safe = twin["predicted"].get(nbr) == "Established" and not twin["regressions"]
        if not safe:
            return self._reply(m, {"applied": False, "reason": "digital twin predicts no recovery",
                                   "twin": twin})
        if "confidence_ref" not in st:
            c = s.call("confidence.evaluate", subject="remediation", for_op="network.config.apply",
                       evidence_refs=m["evidence_refs"],
                       components={"intent": 0.95, "context": 0.9, "data": 0.95,
                                   "model": req["diagnosis_confidence"], "capability": 0.95,
                                   "policy": 1.0, "execution": 0.97, "temporal": 0.95})["result"]
            st["confidence_ref"], st["confidence"] = c["confidence_id"], c
            s.checkpoint(st)
        if st["confidence"]["decision"] not in ("PROCEED", "PROCEED_WITH_WARNING"):
            return self._reply(m, {"applied": False, "reason": "confidence too low",
                                   "decision": st["confidence"]["decision"]})
        if "approval_id" not in st:
            rollback = {"interface": change["interface"], "admin": "down"} if "interface" in change \
                else {"neighbor": change["neighbor"], "hold_time": 0}
            a = s.call("approval.request", dev, op="network.config.apply", change=change,
                       confidence_ref=st["confidence_ref"], rationale=req["hypothesis"]["claim"],
                       rollback=rollback, predicted=twin["predicted"], diff=st["diff"],
                       evidence_refs=m["evidence_refs"], timeout_s=120)["result"]
            st["approval_id"] = a["approval_id"]
            s.checkpoint(st)
        r = s.call("network.config.apply", dev, change=change, approval_id=st["approval_id"],
                   idempotency_key=f"{inc}-apply")
        return self._reply(m, {"applied": True, "replayed": r.get("replayed", False),
                               "rollback": r["result"]["rollback"], "evidence_ref": r["evidence_ref"],
                               "approval_id": st["approval_id"], "diff": st["diff"]})

    def _reply(self, m: dict, payload: dict) -> dict:
        self.sys.send(m["source"], "REMEDIATION_RESULT", payload, correlation_id=m["correlation_id"],
                      message_id=f"{m['correlation_id']}-remediation-result")
        return payload


class Verifier(Agent):
    def run(self, cp: dict | None) -> dict:
        s = self.sys
        m = s.recv(timeout_s=60, type="VERIFY_REQUEST")
        dev, nbr = m["payload"]["device"], m["payload"]["neighbor"]
        r = s.call("network.bgp.inspect", dev, neighbor=nbr)
        payload = {"healthy": r["result"]["state"] == "Established", "state": r["result"]["state"],
                   "evidence_ref": r["evidence_ref"]}
        s.send(m["source"], "VERIFY_RESULT", payload, correlation_id=m["correlation_id"],
               message_id=f"{m['correlation_id']}-verify-result")
        return payload
