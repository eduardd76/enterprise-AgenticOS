"""Kernel services exposed as capabilities: memory, IPC, checkpoints, spawn, confidence,
locks and approvals. They pass through the same gateway as device drivers, so the kernel
mediates its own services exactly as it mediates the network (one enforcement path).
"""

from __future__ import annotations

import asyncio
import json
import math
import posixpath
import re
import time
import uuid
from typing import TYPE_CHECKING

from . import confidence as conf
from . import policy
from .delegation import Grant, matches
from .errors import SyscallError
from .registry import CallContext, Capability, Provider
from .store import sha256

if TYPE_CHECKING:
    from .kernel import Kernel

MSG_TYPE = re.compile(r"^[A-Z][A-Z_]{2,39}$")
KERNEL_MESSAGE_TYPES = {"CHILD_EXITED"}


def new_message_id() -> str:
    return f"msg-{uuid.uuid4().hex[:16]}"      # unguessable, kernel-assigned


def _finite(v, name: str, lo: float, hi: float) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise SyscallError("INVALID_REQUEST", f"{name} must be a number") from None
    if not math.isfinite(f) or not lo <= f <= hi:
        raise SyscallError("INVALID_REQUEST", f"{name} must be within [{lo}, {hi}]")
    return f


def _opt_str(v, limit: int = 128):
    if v is None:
        return None
    if not isinstance(v, str) or len(v) > limit:
        raise SyscallError("INVALID_REQUEST", "expected a short string")
    return v
PRIORITIES = ("low", "normal", "high", "critical")


def _clamp_priority(requested, parent: str) -> str:
    """Scheduling priority is authority too: a child never outranks its parent."""
    if requested not in PRIORITIES:
        return parent
    return min(requested, parent, key=PRIORITIES.index)


# --------------------------------------------------------------------------------------
# Memory / namespace  (vExpertAI §3.C–D: L2 checkpoints, L3 evidence, under /aos/tenants)
# --------------------------------------------------------------------------------------
class Memory:
    def __init__(self, kernel: "Kernel"):
        self.k = kernel

    @staticmethod
    def _check_path(path: str) -> str:
        if not isinstance(path, str) or not path.startswith("/aos/") or \
                posixpath.normpath(path) != path:
            raise SyscallError("INVALID_REQUEST", f"bad path {path!r}")
        return path

    def _authorize(self, agent: dict, d: dict, path: str, write: bool) -> None:
        self._check_path(path)
        if write and (path.startswith(policy.PROTECTED_PATHS) or
                      re.match(r"^/aos/tenants/[^/]+/evidence(/|$)", path)):
            raise SyscallError("POLICY_DENIED", f"{path} is a protected kernel namespace")
        if not path.startswith(f"/aos/tenants/{agent['tenant']}/"):
            raise SyscallError("UNAUTHORIZED", f"cross-tenant memory access to {path}")
        if not any(matches(p, path) for p in d["memory_paths"]):
            raise SyscallError("UNAUTHORIZED", f"memory path {path} not granted")

    def record_evidence(self, tenant: str, path: str, data: dict, provenance: dict) -> str:
        eid = self.k.store.next_id("ev")
        version = (self.k.store.one("SELECT COUNT(*) c FROM evidence WHERE path=?", (path,))["c"]) + 1
        self.k.store.exec("INSERT INTO evidence VALUES (?,?,?,?,?,?,?)",
                          (eid, path, tenant, version, json.dumps(data, default=str),
                           json.dumps(provenance), time.time()))
        return eid

    def read(self, agent: dict, d: dict, ref: str) -> dict:
        if ref.startswith("ev-"):
            row = self.k.store.one("SELECT * FROM evidence WHERE evidence_id=?", (ref,))
            if row is None or row["tenant"] != agent["tenant"]:   # same answer: no oracle
                raise SyscallError("NOT_FOUND", f"no memory object {ref}")
        else:
            self._authorize(agent, d, ref, write=False)            # authorize before lookup
            row = self.k.store.one("SELECT * FROM evidence WHERE path=? ORDER BY version DESC"
                                   " LIMIT 1", (ref,))
            if row is None:
                raise SyscallError("NOT_FOUND", f"no memory object {ref}")
        self._authorize(agent, d, row["path"], write=False)
        return {"evidence_id": row["evidence_id"], "path": row["path"], "version": row["version"],
                "data": json.loads(row["data"]), "provenance": json.loads(row["provenance"])}

    def write(self, agent: dict, d: dict, path: str, data: dict) -> dict:
        self._authorize(agent, d, path, write=True)
        eid = self.record_evidence(agent["tenant"], path, data,
                                   {"op": "memory.write", "agent": agent["agent_id"],
                                    "intent_id": agent["intent_id"]})
        return {"evidence_id": eid, "path": path}

    def same_tenant(self, tenant: str, evidence_id: str) -> bool:
        row = self.k.store.one("SELECT tenant FROM evidence WHERE evidence_id=?", (evidence_id,))
        return row is not None and row["tenant"] == tenant


# --------------------------------------------------------------------------------------
# Approvals  (AOS-0001 §9.9, B.3; vExpertAI §4.6) — single-use, bound to exact change
# --------------------------------------------------------------------------------------
class Approvals:
    TTL_S = 300.0

    def __init__(self, kernel: "Kernel"):
        self.k = kernel
        self._decided: dict[str, asyncio.Event] = {}

    @staticmethod
    def args_hash(args: dict) -> str:
        return sha256({"change": args.get("change")})

    def create(self, agent: dict, d: dict, target: str, args: dict) -> str:
        op = args.get("op")
        cap = self.k.registry.get(op)
        if not cap.consequential:
            raise SyscallError("INVALID_REQUEST", f"{op} does not need approval")
        if not any(matches(p, op) for p in d["capabilities"]) or not d["production_write"]:
            raise SyscallError("UNAUTHORIZED", f"cannot request approval for {op}: not granted")
        cref = args.get("confidence_ref")
        crow = self.k.store.one("SELECT * FROM confidence WHERE confidence_id=?", (cref,))
        if crow is None or crow["intent_id"] != agent["intent_id"]:
            raise SyscallError("CONFIDENCE_INSUFFICIENT", "approval needs a confidence record "
                                                          "for this intent (proof-carrying action)")
        cbody = json.loads(crow["body"])
        decision = cbody["decision"]
        if cbody.get("for_op") != op or crow["agent_id"] != agent["agent_id"]:
            raise SyscallError("CONFIDENCE_INSUFFICIENT",
                               f"confidence {cref} was not evaluated for {op} by this agent")
        if decision not in conf.ACTIONABLE:
            raise SyscallError("CONFIDENCE_INSUFFICIENT", f"confidence decision is {decision}")
        refs = args.get("evidence_refs", [])
        if not isinstance(refs, list):
            raise SyscallError("INVALID_REQUEST", "evidence_refs must be a list")
        for ref in refs:
            if not self.k.memory.same_tenant(agent["tenant"], ref):
                raise SyscallError("UNAUTHORIZED", f"evidence {ref} not readable by tenant")
        # The human sees what the *kernel* computed on the twin, not what the agent claims.
        try:
            twin = self.k.netsim.simulate(target, args.get("change"))
        except (ValueError, KeyError, TypeError, AttributeError):
            raise SyscallError("INVALID_REQUEST", f"unsupported change {args.get('change')!r}")
        aid = self.k.store.next_id("apr")
        package = {"op": op, "target": target, "change": args.get("change"),
                   "rationale": args.get("rationale"),
                   "rationale_source": "agent-asserted (unverified)",
                   "rollback": twin["rollback"], "predicted": twin["predicted"],
                   "regressions": twin["regressions"], "diff": twin["diff"],
                   "twin_source": "kernel digital twin", "evidence_refs": refs,
                   "confidence": json.loads(crow["body"]), "requested_by": agent["agent_id"],
                   "intent_id": agent["intent_id"], "delegation_id": agent["delegation_id"]}
        self.k.store.exec(
            "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?, 'pending', NULL, ?, ?)",
            (aid, agent["agent_id"], agent["intent_id"], op, target, self.args_hash(args),
             self.k.netsim.state_hash(target), cref, json.dumps(package),
             time.time() + self.TTL_S, time.time()))
        self._decided[aid] = asyncio.Event()
        self.k.store.audit("approval.requested", agent_id=agent["agent_id"],
                           intent_id=agent["intent_id"], delegation_id=agent["delegation_id"],
                           approval_id=aid, package_hash=sha256(package))
        self.k.on_approval_request(aid, package)
        return aid

    async def wait(self, aid: str, timeout_s: float) -> str:
        try:
            await asyncio.wait_for(self._decided[aid].wait(), timeout_s)
        except asyncio.TimeoutError:
            self.k.store.exec("UPDATE approvals SET status='expired' WHERE approval_id=? AND "
                              "status='pending'", (aid,))
            self.k.store.audit("approval.expired", approval_id=aid)
        return self.k.store.one("SELECT status FROM approvals WHERE approval_id=?", (aid,))["status"]

    def decide(self, aid: str, principal: str, approve: bool, note: str = "") -> None:
        row = self.k.store.one("SELECT * FROM approvals WHERE approval_id=?", (aid,))
        if row is None or row["status"] != "pending":
            raise SyscallError("NOT_FOUND", f"no pending approval {aid}")
        p = self.k.principals.get(principal, {})
        roles = set(p.get("roles", []))
        allowed = policy.APPROVER_ROLES.get(row["op"], set())
        if not roles & allowed:
            raise SyscallError("UNAUTHORIZED", f"{principal} lacks an approver role for {row['op']}")
        intent = self.k.check_intent(row["intent_id"])
        if p.get("tenant") != intent["tenant"]:
            raise SyscallError("UNAUTHORIZED", f"{principal} cannot approve for another tenant")
        if principal == intent["actor"]["id"]:
            raise SyscallError("UNAUTHORIZED", "separation of duties: requester cannot approve")
        status = "approved" if approve else "denied"
        self.k.store.exec("UPDATE approvals SET status=?, approver=? WHERE approval_id=?",
                          (status, principal, aid))
        self.k.store.audit("approval.decided", approval_id=aid, approver=principal,
                           roles=sorted(roles), status=status, note=note,
                           intent_id=row["intent_id"], agent_id=row["agent_id"])
        if aid in self._decided:
            self._decided[aid].set()

    def consume(self, aid: str, agent: dict, op: str, target: str, args: dict) -> None:
        """Single use, same agent/op/target/change, unexpired, and the device is unchanged."""
        row = self.k.store.one("SELECT * FROM approvals WHERE approval_id=?", (aid,))
        if row is None or row["status"] != "approved":
            raise SyscallError("APPROVAL_REQUIRED", f"approval {aid} is not in approved state")
        if (row["agent_id"], row["op"], row["target"]) != (agent["agent_id"], op, target) or \
                row["args_hash"] != self.args_hash(args):
            raise SyscallError("POLICY_DENIED", f"approval {aid} does not cover this exact action")
        if row["expires_at"] < time.time():
            raise SyscallError("APPROVAL_REQUIRED", f"approval {aid} expired")
        if self.k.netsim.state_hash(target) != row["expected_state"]:
            raise SyscallError("STALE_STATE", f"{target} changed since approval {aid}; re-validate")
        self.k.store.exec("UPDATE approvals SET status='used' WHERE approval_id=?", (aid,))


# --------------------------------------------------------------------------------------
# Capability providers for kernel services
# --------------------------------------------------------------------------------------
def register(kernel: "Kernel") -> None:
    reg, k = kernel.registry, kernel

    def cap(cid, desc, fn, target_kind="none", required=(), outputs=(), side_effects="internal"):
        reg.register(Capability(cid, desc, side_effects, True, target_kind, required, outputs,
                                [Provider("kernel", fn)]))

    async def memory_read(ctx: CallContext, target: str, args: dict) -> dict:
        return k.memory.read(ctx.agent, ctx.delegation, target)

    async def memory_write(ctx: CallContext, target: str, args: dict) -> dict:
        return k.memory.write(ctx.agent, ctx.delegation, target, args["data"])

    async def checkpoint_save(ctx: CallContext, target: str, args: dict) -> dict:
        aid = ctx.agent["agent_id"]
        k.store.exec("INSERT INTO checkpoints(agent_id, data, ts) VALUES (?,?,?)",
                     (aid, json.dumps(args["state"]), time.time()))
        # Checkpoint = ack: messages received so far are now durably reflected in agent state.
        k.store.exec("UPDATE messages SET status='acked' WHERE destination=? AND status='inflight'",
                     (aid,))
        return {"saved": True}

    async def checkpoint_load(ctx: CallContext, target: str, args: dict) -> dict:
        row = k.store.one("SELECT data FROM checkpoints WHERE agent_id=? ORDER BY seq DESC LIMIT 1",
                          (ctx.agent["agent_id"],))
        return {"state": json.loads(row["data"]) if row else None}

    async def ipc_send(ctx: CallContext, target: str, args: dict) -> dict:
        dest = k.store.one("SELECT * FROM agents WHERE agent_id=?", (target,))
        if dest is None or dest["tenant"] != ctx.agent["tenant"] or \
                dest["intent_id"] != ctx.agent["intent_id"]:
            raise SyscallError("UNAUTHORIZED", f"no reachable agent {target} in this intent")
        if dest["state"] in ("COMPLETED", "FAILED", "TERMINATED"):
            raise SyscallError("NOT_FOUND", f"agent {target} is {dest['state']}")
        if not MSG_TYPE.match(str(args["type"])):
            raise SyscallError("INVALID_REQUEST", f"bad message type {args['type']!r}")
        refs = args.get("evidence_refs", [])
        for ref in refs:
            if not k.memory.same_tenant(ctx.agent["tenant"], ref):
                raise SyscallError("UNAUTHORIZED", f"evidence {ref} not shareable from tenant")
        if args["type"] in KERNEL_MESSAGE_TYPES or str(args["type"]).startswith("KERNEL_"):
            raise SyscallError("UNAUTHORIZED", f"{args['type']} is reserved for the kernel")
        src = ctx.agent["agent_id"]
        client_id = args.get("message_id")       # sender-scoped dedup key, never the stored id
        if client_id is not None:
            if not isinstance(client_id, str) or len(client_id) > 128:
                raise SyscallError("INVALID_REQUEST", "message_id must be a short string")
            dup = k.store.one("SELECT message_id FROM messages WHERE source=? AND client_id=?",
                              (src, client_id))
            if dup:
                return {"message_id": dup["message_id"], "duplicate": True}
        deadline_s = _finite(args.get("deadline_s", 300), "deadline_s", 0, 86400)
        mid = new_message_id()
        k.store.exec("INSERT INTO messages(message_id, source, destination, type, correlation_id,"
                     " payload, evidence_refs, deadline, status, ts, client_id)"
                     " VALUES (?,?,?,?,?,?,?,?, 'pending', ?, ?)",
                     (mid, src, target, args["type"], _opt_str(args.get("correlation_id")),
                      json.dumps(args.get("payload", {})), json.dumps(refs),
                      time.time() + deadline_s, time.time(), client_id))
        k.store.audit("ipc.sent", agent_id=ctx.agent["agent_id"], intent_id=ctx.agent["intent_id"],
                      message_id=mid, destination=target, type=args["type"])
        k.mail_event(target).set()
        return {"message_id": mid, "duplicate": False}

    async def ipc_recv(ctx: CallContext, target: str, args: dict) -> dict:
        aid = ctx.agent["agent_id"]
        timeout = _finite(args.get("timeout_s", 30), "timeout_s", 0, 3600)
        end = time.time() + timeout

        def take():
            k.store.exec("UPDATE messages SET status='expired' WHERE destination=? AND "
                         "status='pending' AND deadline<?", (aid, time.time()))
            sql, params = ("SELECT * FROM messages WHERE destination=? AND status='pending'", [aid])
            for f in ("type", "correlation_id"):
                if args.get(f):
                    sql += f" AND {f}=?"
                    params.append(args[f])
            row = k.store.one(sql + " ORDER BY ts LIMIT 1", tuple(params))
            if row:
                k.store.exec("UPDATE messages SET status='inflight' WHERE message_id=?",
                             (row["message_id"],))
                return {"message_id": row["message_id"], "source": row["source"],
                        "type": row["type"], "correlation_id": row["correlation_id"],
                        "payload": json.loads(row["payload"]),
                        "evidence_refs": json.loads(row["evidence_refs"])}
            return None

        async def wait_for_mail():
            while True:
                ev = k.mail_event(aid)
                ev.clear()
                msg = take()
                if msg:
                    return msg
                remaining = end - time.time()
                if remaining <= 0:
                    raise SyscallError("DEADLINE_EXCEEDED", f"no message within {timeout}s")
                try:
                    await asyncio.wait_for(ev.wait(), remaining)
                except asyncio.TimeoutError:
                    pass

        msg = take()
        return msg if msg else await k.block(aid, "ipc", wait_for_mail())

    async def agent_spawn(ctx: CallContext, target: str, args: dict) -> dict:
        if target not in k.agent_types:
            raise SyscallError("INVALID_REQUEST", f"unregistered agent type {target!r}")
        g = args["grant"]
        if not isinstance(g, dict):
            raise SyscallError("INVALID_REQUEST", "grant must be an object")
        if not isinstance(g.get("production_write", False), bool):
            raise SyscallError("INVALID_REQUEST", "production_write must be a boolean")
        # No coercion: delegation._validate type-checks the raw values (int(True) == 1 etc.).
        grant = Grant(capabilities=g.get("capabilities", []), targets=g.get("targets", []),
                      memory_paths=g.get("memory_paths", []),
                      production_write=g.get("production_write", False),
                      budget_calls=g.get("budget_calls", 20),
                      budget_tokens=g.get("budget_tokens", 5000),
                      ttl_s=g.get("ttl_s", 300))    # non-finite/negative -> expired (_ttl)
        role = _opt_str(args.get("role", target), 64) or target
        child_id = k.new_agent_id(target)
        did = k.delegations.attenuate(ctx.agent["delegation_id"], child_id, grant)
        k.create_agent(child_id, target, tenant=ctx.agent["tenant"], owner=ctx.agent["owner"],
                       role=role, intent_id=ctx.agent["intent_id"],
                       delegation_id=did, parent_agent=ctx.agent["agent_id"],
                       priority=_clamp_priority(args.get("priority"), ctx.agent["priority"]),
                       deadline=ctx.agent["deadline"])
        return {"agent_id": child_id, "delegation_id": did}

    async def confidence_evaluate(ctx: CallContext, target: str, args: dict) -> dict:
        # Impact and reversibility come from the manifest of the op being justified — an agent
        # can't talk its way to PROCEED by calling a production write "low impact".
        for_op = args.get("for_op")
        justified = k.registry.get(for_op) if for_op else None
        impact = "high" if justified and justified.consequential else "low"
        reversible = justified.reversible if justified else True
        try:
            comps = {str(n): float(v) for n, v in dict(args["components"]).items()}
            if any(v != v for v in comps.values()):           # NaN
                raise ValueError("NaN confidence component")
            body = conf.evaluate(comps, impact, reversible,
                                 k.confidence_policy(ctx.agent["tenant"]))
        except (ValueError, TypeError) as e:
            raise SyscallError("INVALID_REQUEST", str(e)) from e
        refs = list(args.get("evidence_refs", []))
        for ref in refs:
            if not k.memory.same_tenant(ctx.agent["tenant"], ref):
                raise SyscallError("UNAUTHORIZED", f"evidence {ref} not readable by tenant")
        body.update(subject=args.get("subject"), for_op=for_op, evidence_refs=refs)
        if impact == "high" and (set(comps) != set(conf.COMPONENTS) or not refs):
            body["decision"] = "ESCALATE"
            body["reason"] = "consequential action needs all components and cited evidence"
        cid = k.store.next_id("conf")
        k.store.exec("INSERT INTO confidence VALUES (?,?,?,?,?)",
                     (cid, ctx.agent["agent_id"], ctx.agent["intent_id"], json.dumps(body),
                      time.time()))
        k.store.audit("confidence.evaluated", agent_id=ctx.agent["agent_id"],
                      intent_id=ctx.agent["intent_id"], confidence_id=cid,
                      aggregate=body["aggregate"], decision=body["decision"])
        return {"confidence_id": cid, **body}

    async def approval_request(ctx: CallContext, target: str, args: dict) -> dict:
        aid = k.approvals.create(ctx.agent, ctx.delegation, target, args)
        status = await k.block(ctx.agent["agent_id"], "approval",
                               k.approvals.wait(aid, float(args.get("timeout_s", 120))))
        if status != "approved":
            raise SyscallError("APPROVAL_DENIED", f"approval {aid} {status}")
        return {"approval_id": aid, "status": status}

    async def lock_acquire(ctx: CallContext, target: str, args: dict) -> dict:
        aid = ctx.agent["agent_id"]
        res = await k.block(aid, "lock", k.locks.acquire(
            aid, _lock_name(ctx, target), _finite(args.get("lease_s", 60), "lease_s", 0.1, 3600),
            _finite(args.get("timeout_s", 10), "timeout_s", 0, 600)))
        return {**res, "resource": target}

    async def lock_release(ctx: CallContext, target: str, args: dict) -> dict:
        return {"released": k.locks.release(ctx.agent["agent_id"], _lock_name(ctx, target))}

    def _lock_name(ctx: CallContext, target: str) -> str:
        return f"{ctx.agent['tenant']}:{target}"    # tenants can't contend for each other's locks

    cap("memory.read", "Read a versioned memory/evidence object", memory_read, "path",
        side_effects="none")
    cap("memory.write", "Write a versioned memory object", memory_write, "path", ("data",))
    cap("checkpoint.save", "Persist working state (L2 memory)", checkpoint_save, required=("state",))
    cap("checkpoint.load", "Load latest working state", checkpoint_load)
    cap("ipc.send", "Send a typed message", ipc_send, "agent", ("type",))
    cap("ipc.recv", "Receive a typed message", ipc_recv)
    cap("agent.spawn", "Spawn a child agent with an attenuated grant", agent_spawn, "agent",
        ("grant",))
    cap("confidence.evaluate", "Kernel-decided control action from evidence", confidence_evaluate,
        required=("components",))
    cap("approval.request", "Request human approval for a consequential action",
        approval_request, "device", ("op", "change", "confidence_ref"))
    cap("lock.acquire", "Acquire a leased resource lock", lock_acquire, "path")
    cap("lock.release", "Release a resource lock", lock_release, "path")
