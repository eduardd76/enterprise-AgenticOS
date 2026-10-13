"""Agent-side SDK: the libc of AOS. Runs inside the (untrusted) agent process.

The only thing an agent can do to the outside world is `sys.call(...)`, which writes a
JSON frame to the kernel pipe and blocks for the reply.
"""

from __future__ import annotations

import json
import sys as _pysys
from typing import IO, Any


class SyscallFailed(Exception):
    def __init__(self, op: str, error: dict):
        super().__init__(f"{op} -> {error.get('code')}: {error.get('message')}")
        self.op = op
        self.code = error.get("code")
        self.error = error


class Sys:
    def __init__(self, inp: IO[str], out: IO[str]):
        self._in, self._out, self._next = inp, out, 0

    def call(self, op: str, target: str = "", /, *, idempotency_key: str | None = None,
             **args: Any) -> dict:
        """Returns the gateway response: {"result", "evidence_ref", "provider", "policy"}."""
        self._next += 1
        frame = {"id": self._next, "op": op, "target": target, "args": args}
        if idempotency_key:
            frame["idempotency_key"] = idempotency_key
        self._out.write(json.dumps(frame) + "\n")
        self._out.flush()
        line = self._in.readline()
        if not line:
            raise SystemExit(70)        # kernel went away
        reply = json.loads(line)
        if reply.get("id") != self._next:          # channel desync: never act on a wrong reply
            raise SystemExit(71)
        if not reply.get("ok"):
            raise SyscallFailed(op, reply.get("error", {}))
        return reply["result"]

    # conveniences ------------------------------------------------------
    def checkpoint(self, state: dict) -> None:
        self.call("checkpoint.save", state=state)

    def send(self, to: str, type: str, payload: dict, **kw: Any) -> dict:
        return self.call("ipc.send", to, type=type, payload=payload, **kw)["result"]

    def recv(self, timeout_s: float = 30, **filters: Any) -> dict:
        return self.call("ipc.recv", timeout_s=timeout_s, **filters)["result"]

    def log(self, *parts: Any) -> None:
        print(*parts, file=_pysys.stderr, flush=True)


class Agent:
    """Subclass and implement run(). Return a dict to complete; raise to fail."""

    def __init__(self, sys: Sys, boot: dict):
        self.sys = sys
        self.boot = boot
        self.agent_id = boot["agent_id"]
        self.params = boot.get("params", {})

    def run(self, checkpoint: dict | None) -> dict:
        raise NotImplementedError
