"""A scriptable agent for conformance tests: runs a list of syscalls and reports outcomes.

params.script items: {"op", "target", "args", "idempotency_key"} or {"sleep": seconds}
or {"crash_once": true} (SIGKILL-equivalent on the first run only, via checkpoint marker).
"""

from __future__ import annotations

import os
import time

from ..sdk import Agent, SyscallFailed


class ScriptAgent(Agent):
    def run(self, cp: dict | None) -> dict:
        st = cp or {"done": 0, "results": []}
        script = self.params.get("script", [])
        for i, step in enumerate(script):
            if i < st["done"]:
                continue
            if "sleep" in step:
                time.sleep(step["sleep"])
                outcome = {"slept": step["sleep"]}
            elif step.get("crash_once"):
                if not st.get("crashed"):
                    st["crashed"] = True
                    self.sys.checkpoint(st)
                    os._exit(137)
                outcome = {"recovered": True}
            else:
                try:
                    r = self.sys.call(step["op"], step.get("target", ""),
                                      idempotency_key=step.get("idempotency_key"),
                                      **step.get("args", {}))
                    outcome = {"ok": True, "result": r["result"], "replayed": r.get("replayed", False)}
                except SyscallFailed as e:
                    outcome = {"ok": False, "code": e.code}
            st["results"].append(outcome)
            st["done"] = i + 1
            if self.params.get("checkpoint_each", True):
                self.sys.checkpoint(st)
        return {"results": st["results"]}
