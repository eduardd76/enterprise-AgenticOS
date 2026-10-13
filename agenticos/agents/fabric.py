"""EVPN/VXLAN fabric agents: multi-fault incidents handled in rounds.

Each round: diagnose (fresh evidence from every switch + end-to-end probe) -> pick one fix that
is *verified against the evidence* -> change agent simulates it on the twin and gets human
approval -> apply -> independent verifier probes the tenant service. If the service is still
down, start another round with the history of fixes so far. Stop when it's reachable, when no
verified fix remains (escalate to a human), or after max_rounds.
"""

from __future__ import annotations

import time

from ..sdk import Agent, SyscallFailed

BASE = ["checkpoint.*", "ipc.send", "ipc.recv"]


class ChildFailed(Exception):
    pass


class FabricCoordinator(Agent):
    def run(self, cp: dict | None) -> dict:
        s = self.sys
        p = self.params
        st = cp or {"round": 1, "stage": "diagnose", "history": []}
        inc = p["incident_id"]
        wait = int(p.get("approval_timeout_s", 300))
        while st["round"] <= int(p.get("max_rounds", 3)):
            r = st["round"]
            tag = f"{inc}-r{r}"
            if st["stage"] == "diagnose":
                diag = s.call("agent.spawn", "fabric.diag", role=f"diagnosis-round-{r}", grant={
                    "capabilities": BASE + ["network.fabric.inspect", "network.service.probe",
                                            "model.infer", "confidence.evaluate"],
                    "targets": p["devices"] + p["hosts"], "budget_calls": 40,
                    "budget_tokens": 20_000, "ttl_s": 600},
                    params={"devices": p["devices"]})["result"]["agent_id"]
                s.send(diag, "FABRIC_DIAGNOSIS_REQUEST",
                       {"devices": p["devices"], "history": st["history"]},
                       correlation_id=tag, message_id=f"{tag}-diag-req")
                st["stage"] = "diagnosing"
                s.checkpoint(st)
            if st["stage"] == "diagnosing":
                m = self._await("FABRIC_DIAGNOSIS_RESULT", tag, 600)
                st.update(stage="diagnosed", diagnosis=m["payload"], refs=m["evidence_refs"])
                s.checkpoint(st)
            d = st["diagnosis"]
            if st["stage"] == "diagnosed":
                if d["healthy"]:
                    return self._report(st, "resolved" if st["history"] else "no fault found")
                fix = d.get("selected")
                if not fix or d["confidence_decision"] not in ("PROCEED", "PROCEED_WITH_WARNING"):
                    return self._report(st, "escalated to human: no verified automated fix "
                                            f"(round {r})")
                rem = dict(fix["remediation"])
                device = rem.pop("device")
                change = s.call("agent.spawn", "fabric.change", role=f"change-round-{r}", grant={
                    "capabilities": BASE + ["network.config.diff", "twin.simulate",
                                            "confidence.evaluate", "approval.request",
                                            "network.config.apply"],
                    "targets": [device], "production_write": True, "budget_calls": 20,
                    "budget_tokens": 1000, "ttl_s": wait + 300},
                    params={"approval_timeout_s": wait})["result"]["agent_id"]
                s.send(change, "REMEDIATION_REQUEST",
                       {"device": device, "change": rem, "hypothesis": fix,
                        "diagnosis_confidence": d["confidence"]},
                       correlation_id=tag, message_id=f"{tag}-rem-req", evidence_refs=st["refs"])
                st.update(stage="remediating", pending_fix={"device": device, **rem})
                s.checkpoint(st)
            if st["stage"] == "remediating":
                m = self._await("REMEDIATION_RESULT", tag, wait + 300)
                st["remediation"] = m["payload"]
                if not m["payload"].get("applied"):
                    s.checkpoint(st)
                    return self._report(st, f"remediation not applied: {m['payload'].get('reason')}")
                st["history"].append({**st["pending_fix"], "round": r,
                                      "claim": d["selected"]["claim"]})
                st["stage"] = "verify"
                s.checkpoint(st)
            if st["stage"] == "verify":
                ver = s.call("agent.spawn", "fabric.verifier", role=f"verify-round-{r}", grant={
                    "capabilities": BASE + ["network.service.probe"], "targets": p["hosts"],
                    "budget_calls": 30, "budget_tokens": 0, "ttl_s": 300})["result"]["agent_id"]
                s.send(ver, "VERIFY_REQUEST", {"host": p["hosts"][0]}, correlation_id=tag,
                       message_id=f"{tag}-verify-req")
                st["stage"] = "verifying"
                s.checkpoint(st)
            if st["stage"] == "verifying":
                m = self._await("VERIFY_RESULT", tag, 300)
                st["verification"] = m["payload"]
                if m["payload"]["reachable"]:
                    s.checkpoint(st)
                    return self._report(st, "resolved")
                st.update(round=r + 1, stage="diagnose")      # still broken: next round
                s.checkpoint(st)
        return self._report(st, f"escalated to human: still broken after {st['round'] - 1} rounds")

    def _await(self, msg_type: str, tag: str, timeout_s: float) -> dict:
        while True:
            m = self.sys.recv(timeout_s=timeout_s)
            if m["type"] == msg_type and m["correlation_id"] == tag:
                return m
            if m["type"] == "CHILD_EXITED" and m["source"] == "kernel" and \
                    m["payload"]["state"] != "COMPLETED":
                raise ChildFailed(f"{m['payload']['child']} {m['payload']['state']}: "
                                  f"{m['payload']['reason']}")

    def _report(self, st: dict, outcome: str) -> dict:
        tenant, inc = self.boot["tenant"], self.params["incident_id"]
        report = {"incident_id": inc, "outcome": outcome, "rounds": st["round"],
                  "fixes": st["history"], "last_diagnosis": st.get("diagnosis")}
        w = self.sys.call("memory.write", f"/aos/tenants/{tenant}/incidents/{inc}", data=report)
        return {"outcome": outcome, "fixes": st["history"], "rounds": st["round"],
                "report_ref": w["result"]["evidence_id"]}


class FabricDiagnostic(Agent):
    def run(self, cp: dict | None) -> dict:
        s = self.sys
        st = cp or {"refs": []}
        if "request" not in st:
            st["request"] = s.recv(timeout_s=120, type="FABRIC_DIAGNOSIS_REQUEST")
            s.checkpoint(st)
        req, tag = st["request"]["payload"], st["request"]["correlation_id"]
        if "probe" not in st:
            r = s.call("network.service.probe", "host1")
            st["probe"] = r["result"]
            st["refs"].append(r["evidence_ref"])
            s.checkpoint(st)
        if st["probe"]["reachable"]:
            return self._reply(st, tag, {"healthy": True, "probe": st["probe"]})
        st.setdefault("devices", {})
        for dev in req["devices"]:
            if dev not in st["devices"]:
                r = s.call("network.fabric.inspect", dev)
                st["devices"][dev] = r["result"]
                st["refs"].append(r["evidence_ref"])
                s.checkpoint(st)
        if "model" not in st:
            evidence = {"service": {"name": "tenant-a", "vlan": 10, "vni": 10010,
                                    "hosts": {"host1": "leaf1 Ethernet3",
                                              "host2": "leaf2 Ethernet3"}},
                        "probe": st["probe"], "devices": st["devices"],
                        "history": req["history"]}
            r = s.call("model.infer", task="fabric_diagnosis", evidence=evidence)
            st["model"], st["provider"] = r["result"], r["provider"]
            st["refs"].append(r["evidence_ref"])
            s.checkpoint(st)
        if st["model"].get("suggested_action") and "overreach" not in st:
            sa = st["model"]["suggested_action"]["change"]
            rem = {k: v for k, v in sa.items() if k != "device"}
            try:
                s.call("network.config.apply", sa.get("device", ""), change=rem,
                       idempotency_key="model-suggested")
                st["overreach"] = "EXECUTED"
            except SyscallFailed as e:
                st["overreach"] = e.code
            s.checkpoint(st)
        # Deterministic check: a hypothesis only counts if the evidence shows that fault.
        hyps = sorted(st["model"]["hypotheses"], key=lambda h: -h["likelihood"])
        done = {(h["device"], h["interface"]) for h in req["history"]}
        verified = [h for h in hyps if h.get("remediation") and self._verify(h["remediation"],
                                                                            st["devices"], done)]
        best = verified[0] if verified else None
        c = s.call("confidence.evaluate", subject=best["id"] if best else "none",
                   evidence_refs=st["refs"],
                   components={"intent": 0.95, "context": 0.9, "data": 0.95,
                               "model": best["likelihood"] if best else 0.2, "capability": 0.9,
                               "policy": 1.0, "execution": 0.95 if best else 0.2,
                               "temporal": 0.95})["result"]
        return self._reply(st, tag, {
            "healthy": False, "probe": st["probe"], "hypotheses": hyps, "selected": best,
            "verified_count": len(verified), "confidence_ref": c["confidence_id"],
            "confidence": c["aggregate"], "confidence_decision": c["decision"],
            "model_provider": st["provider"], "model_overreach": st.get("overreach")})

    @staticmethod
    def _verify(rem: dict, devices: dict, done: set) -> bool:
        dev = devices.get(rem.get("device"))
        if dev is None or (rem["device"], rem.get("interface")) in done:
            return False
        iface = dev["interfaces"].get(rem.get("interface"))
        if iface is None:
            return False
        if "admin" in rem:
            return rem["admin"] == "up" and iface["admin"] == "down"
        if "access_vlan" in rem:
            return rem["interface"] in dev["host_ports"] and rem["access_vlan"] == 10 \
                and iface["vlan"] != 10
        return False

    def _reply(self, st: dict, tag: str, payload: dict) -> dict:
        self.sys.send(st["request"]["source"], "FABRIC_DIAGNOSIS_RESULT", payload,
                      correlation_id=tag, message_id=f"{tag}-diag-result",
                      evidence_refs=st["refs"])
        return {k: payload.get(k) for k in ("healthy", "selected", "model_provider",
                                             "model_overreach")}


class FabricChange(Agent):
    def run(self, cp: dict | None) -> dict:
        s = self.sys
        st = cp or {}
        if "request" not in st:
            st["request"] = s.recv(timeout_s=120, type="REMEDIATION_REQUEST")
            s.checkpoint(st)
        m = st["request"]
        req = m["payload"]
        dev, change = req["device"], req["change"]
        if "twin" not in st:
            st["twin"] = s.call("twin.simulate", dev, change=change)["result"]
            s.checkpoint(st)
        twin = st["twin"]
        if twin["regressions"] or not twin.get("improves"):
            return self._reply(m, {"applied": False, "twin": twin,
                                   "reason": "twin predicts no improvement or a regression"})
        if "confidence_ref" not in st:
            c = s.call("confidence.evaluate", subject="remediation",
                       for_op="network.config.apply", evidence_refs=m["evidence_refs"],
                       components={"intent": 0.95, "context": 0.9, "data": 0.95,
                                   "model": req["diagnosis_confidence"], "capability": 0.95,
                                   "policy": 1.0, "execution": 0.97, "temporal": 0.95})["result"]
            st["confidence_ref"], st["confidence"] = c["confidence_id"], c
            s.checkpoint(st)
        if st["confidence"]["decision"] not in ("PROCEED", "PROCEED_WITH_WARNING"):
            return self._reply(m, {"applied": False, "reason": "confidence too low"})
        if "approval_id" not in st:
            a = s.call("approval.request", dev, op="network.config.apply", change=change,
                       confidence_ref=st["confidence_ref"], rationale=req["hypothesis"]["claim"],
                       evidence_refs=m["evidence_refs"],
                       timeout_s=int(self.params.get("approval_timeout_s", 300)))["result"]
            st["approval_id"] = a["approval_id"]
            s.checkpoint(st)
        r = s.call("network.config.apply", dev, change=change, approval_id=st["approval_id"],
                   idempotency_key=f"{m['correlation_id']}-apply")
        return self._reply(m, {"applied": True, "device": dev, "change": change,
                               "rollback": r["result"]["rollback"], "twin": twin,
                               "approval_id": st["approval_id"]})

    def _reply(self, m: dict, payload: dict) -> dict:
        self.sys.send(m["source"], "REMEDIATION_RESULT", payload,
                      correlation_id=m["correlation_id"],
                      message_id=f"{m['correlation_id']}-rem-result")
        return payload


class FabricVerifier(Agent):
    def run(self, cp: dict | None) -> dict:
        s = self.sys
        m = s.recv(timeout_s=120, type="VERIFY_REQUEST")
        for attempt in range(12):                     # EVPN/MAC learning converges in seconds
            r = s.call("network.service.probe", m["payload"]["host"])
            if r["result"]["reachable"]:
                break
            time.sleep(3)
        payload = {**r["result"], "polls": attempt + 1, "evidence_ref": r["evidence_ref"]}
        s.send(m["source"], "VERIFY_RESULT", payload, correlation_id=m["correlation_id"],
               message_id=f"{m['correlation_id']}-verify-result")
        return payload
