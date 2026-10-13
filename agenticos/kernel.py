"""The AOS kernel: agent process manager, lifecycle state machine and control API.

Agents are real OS subprocesses with a scrubbed environment. Their only channel to the
world is a JSON-lines pipe the kernel owns, so the kernel knows who is calling without
trusting anything the agent says (vExpertAI §3.H: microkernel-inspired, small trusted core).
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

from . import services
from .confidence import DEFAULT_POLICY, ConfidencePolicy
from .delegation import DelegationManager, Grant
from .drivers import models as model_drivers
from .drivers import netsim as net_drivers
from .drivers.netsim import NetSim
from .errors import SyscallError
from .gateway import TERMINAL, Gateway
from .locks import LockManager
from .registry import Registry
from .scheduler import Scheduler
from .services import Approvals, Memory
from .store import Store, canonical, sha256

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MAX_FRAME = 1 << 20          # bytes per syscall frame; larger frames kill the agent

# Legal A-PCB transitions (vExpertAI §3.A; AOS-0001 §7.7, C.2). Anything else is a kernel bug.
LEGAL = {
    "CREATED": {"READY", "TERMINATED"},
    "READY": {"RUNNING", "SUSPENDED", "TERMINATED", "FAILED"},
    "RUNNING": {"WAITING", "SUSPENDED", "COMPLETED", "FAILED", "TERMINATED", "READY"},
    "WAITING": {"READY", "SUSPENDED", "TERMINATED", "FAILED"},
    "SUSPENDED": {"READY", "WAITING", "TERMINATED", "FAILED"},
}

DEFAULT_AGENT_TYPES = {
    "noc.coordinator": "agenticos.agents.noc:Coordinator",
    "noc.bgp_diag": "agenticos.agents.noc:BgpDiagnostic",
    "noc.change": "agenticos.agents.noc:ChangeAgent",
    "noc.verifier": "agenticos.agents.noc:Verifier",
    "test.script": "agenticos.agents.testing:ScriptAgent",
}


def detect_isolation() -> str:
    """Strongest agent confinement available on this host: seatbelt | bwrap | process."""
    if os.environ.get("AOS_NO_SANDBOX"):
        return "process"
    if sys.platform == "darwin" and shutil.which("sandbox-exec"):
        return "seatbelt"
    if sys.platform.startswith("linux") and shutil.which("bwrap"):
        return "bwrap"
    return "process"


class AgentRuntime:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.proc: asyncio.subprocess.Process | None = None
        self.task: asyncio.Task | None = None
        self.resume = asyncio.Event()
        self.resume.set()
        self.blocked = False
        self.holds_slot = False
        self.exited = False
        self.cancelled = False
        self.done: asyncio.Future = asyncio.get_running_loop().create_future()
        self.crash_plan: dict | None = None
        self.syscalls = 0


class Kernel:
    def __init__(self, db_path: str | Path = ":memory:", slots: int = 3,
                 netsim: "NetSim | FrrLab | None" = None, log_dir: str | Path | None = None):
        self.store = Store(db_path)
        self.registry = Registry()
        self.delegations = DelegationManager(self.store)
        self.netsim = netsim or NetSim()
        self.scheduler = Scheduler(slots)
        self.locks = LockManager()
        self.memory = Memory(self)
        self.approvals = Approvals(self)
        self.gateway = Gateway(self)
        if hasattr(self.netsim, "register"):      # real backends (e.g. FrrLab) bring their drivers
            self.netsim.register(self.registry)
        else:
            net_drivers.register(self.registry, self.netsim)
        model_drivers.register(self.registry)
        services.register(self)
        self.principals: dict[str, dict] = {}
        self.agent_types = dict(DEFAULT_AGENT_TYPES)
        self.runtimes: dict[str, AgentRuntime] = {}
        self._mail: dict[str, asyncio.Event] = {}
        self.log_dir = Path(log_dir) if log_dir else None
        self.approval_handler: Callable[[str, dict], None] | None = None
        self.state_dir = None if str(db_path) == ":memory:" else Path(db_path).resolve().parent
        self.isolation = detect_isolation()
        self._jail = tempfile.mkdtemp(prefix="aos-agent-cwd-")
        self._confidence_policies: dict[str, ConfidencePolicy] = {}   # tenant -> policy
        self.autostart = True        # False: create A-PCBs without processes (in-process tests)
        self.on_event: Callable[[str, dict], None] | None = None

    # -- identity & intents ---------------------------------------------
    def add_principal(self, name: str, tenant: str, roles: list[str], authority: Grant) -> None:
        self.principals[name] = {"tenant": tenant, "roles": roles, "authority": authority}

    def submit_intent(self, actor: str, objective: str, agent_type: str, grant: Grant, *,
                      priority: str = "normal", deadline_s: float | None = None,
                      constraints: dict | None = None, success_criteria: list | None = None,
                      params: dict | None = None, start: bool = True) -> tuple[str, str]:
        p = self.principals.get(actor)
        if p is None:
            raise SyscallError("UNAUTHORIZED", f"unknown principal {actor}")
        intent_id = self.store.next_id("int")
        body = {"intent_id": intent_id, "actor": {"type": "human", "id": actor},
                "tenant": p["tenant"], "objective": objective, "constraints": constraints or {},
                "success_criteria": success_criteria or [], "created_at": time.time(),
                "deadline": time.time() + deadline_s if deadline_s else None}
        self.store.exec("INSERT INTO intents VALUES (?,?,?,?,?)",
                        (intent_id, p["tenant"], canonical(body), sha256(body), time.time()))
        self.store.audit("intent.received", intent_id=intent_id, actor=actor,
                         objective_hash=sha256(objective), tenant=p["tenant"])
        agent_id = self.new_agent_id(agent_type)
        did = self.delegations.create_root(intent_id=intent_id, tenant=p["tenant"], principal=actor,
                                           delegatee=agent_id, authority=p["authority"], grant=grant)
        self.create_agent(agent_id, agent_type, tenant=p["tenant"], owner=actor,
                          role=agent_type, intent_id=intent_id, delegation_id=did,
                          priority=priority, deadline=body["deadline"], params=params, start=start)
        return intent_id, agent_id

    # -- operator policy (never reachable from an agent syscall) ---------------
    def set_confidence_policy(self, tenant: str, policy: ConfidencePolicy | dict,
                              set_by: str = "operator") -> str:
        """Set a tenant's risk appetite. Returns the policy version recorded in every decision."""
        if isinstance(policy, dict):
            policy = ConfidencePolicy(**policy)     # validates ranges and ordering
        self._confidence_policies[tenant] = policy
        self.store.audit("policy.confidence.set", tenant=tenant, set_by=set_by,
                         version=policy.version, thresholds=policy.__dict__)
        return policy.version

    def confidence_policy(self, tenant: str) -> ConfidencePolicy:
        return self._confidence_policies.get(
            tenant, getattr(self, "_default_from_file", DEFAULT_POLICY))

    def load_policy_file(self, path: str | Path, set_by: str = "policy-file") -> dict[str, str]:
        """JSON: {"confidence": {"default": {...}, "tenants": {"customer-a": {...}}}}.
        'default' fields apply to every tenant; tenant entries override field by field."""
        cfg = json.loads(Path(path).read_text()).get("confidence", {})
        base = cfg.get("default", {})
        applied = {}
        for tenant, overrides in cfg.get("tenants", {}).items():
            applied[tenant] = self.set_confidence_policy(tenant, {**base, **overrides}, set_by)
        if base:
            global_policy = ConfidencePolicy(**base)
            for tenant in {p["tenant"] for p in self.principals.values()} - set(applied):
                applied[tenant] = self.set_confidence_policy(tenant, global_policy, set_by)
            self._default_from_file = global_policy
        return applied

    def check_intent(self, intent_id: str) -> dict:
        row = self.store.one("SELECT * FROM intents WHERE intent_id=?", (intent_id,))
        if row is None:
            raise SyscallError("UNAUTHORIZED", f"no originating intent {intent_id}")
        body = json.loads(row["body"])
        if sha256(body) != row["body_hash"]:
            raise SyscallError("UNAUTHORIZED", f"intent {intent_id} was modified after submission")
        return body

    # -- agents (A-PCB) ---------------------------------------------------
    def new_agent_id(self, agent_type: str) -> str:
        return self.store.next_id(agent_type.split(".")[-1].replace("_", "-"))

    def agent(self, agent_id: str) -> dict:
        row = self.store.one("SELECT * FROM agents WHERE agent_id=?", (agent_id,))
        if row is None:
            raise SyscallError("UNAUTHORIZED", f"unknown agent {agent_id}")
        return dict(row)

    def create_agent(self, agent_id: str, agent_type: str, *, tenant: str, owner: str, role: str,
                     intent_id: str, delegation_id: str, parent_agent: str | None = None,
                     priority: str = "normal", deadline: float | None = None,
                     retry_budget: int = 2, params: dict | None = None, start: bool = True) -> str:
        if agent_type not in self.agent_types:
            raise SyscallError("INVALID_REQUEST", f"unregistered agent type {agent_type}")
        self.store.exec(
            "INSERT INTO agents(agent_id, agent_type, tenant, owner, role, intent_id, delegation_id,"
            " parent_agent, priority, deadline, state, retry_budget, params, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?, 'CREATED', ?,?,?)",
            (agent_id, agent_type, tenant, owner, role, intent_id, delegation_id, parent_agent,
             priority, deadline, retry_budget, json.dumps(params or {}), time.time()))
        self.store.audit("agent.created", agent_id=agent_id, intent_id=intent_id,
                         delegation_id=delegation_id, agent_type=agent_type, parent=parent_agent,
                         priority=priority)
        self.transition(agent_id, "READY", "admitted")
        if start and self.autostart:
            self._start(agent_id)
        return agent_id

    def transition(self, agent_id: str, to: str, reason: str = "") -> None:
        row = self.agent(agent_id)
        frm = row["state"]
        if to not in LEGAL.get(frm, set()):
            raise RuntimeError(f"illegal transition {agent_id}: {frm} -> {to} ({reason})")
        reason = str(reason)[:500]
        wait_reason = reason if to == "WAITING" else None
        with self.store.db:                      # state + history commit together or not at all
            self.store.db.execute("UPDATE agents SET state=?, wait_reason=? WHERE agent_id=?",
                                  (to, wait_reason, agent_id))
            self.store.db.execute("INSERT INTO agent_history(agent_id, from_state, to_state,"
                                  " reason, ts) VALUES (?,?,?,?,?)",
                                  (agent_id, frm, to, reason, time.time()))
        self.store.audit("agent.state", agent_id=agent_id, intent_id=row["intent_id"],
                         delegation_id=row["delegation_id"], frm=frm, to=to, reason=reason)
        self._emit("state", {"agent_id": agent_id, "from": frm, "to": to, "reason": reason})

    def _emit(self, kind: str, data: dict) -> None:
        if self.on_event:
            self.on_event(kind, data)

    def mail_event(self, agent_id: str) -> asyncio.Event:
        return self._mail.setdefault(agent_id, asyncio.Event())

    def on_approval_request(self, approval_id: str, package: dict) -> None:
        self._emit("approval", {"approval_id": approval_id, "package": package})
        if self.approval_handler:
            self.approval_handler(approval_id, package)

    # -- operator control: the ps / stop / cont / kill of AOS ---------------
    def suspend(self, agent_id: str, reason: str = "operator") -> None:
        if self.agent(agent_id)["state"] not in ("READY", "RUNNING", "WAITING"):
            raise SyscallError("INVALID_REQUEST", f"cannot suspend {agent_id}")
        if rt := self.runtimes.get(agent_id):
            rt.resume.clear()
            self._release_slot(rt)
            if rt.proc and rt.proc.returncode is None:
                os.kill(rt.proc.pid, signal.SIGSTOP)       # frozen now, not at the next syscall
        self.transition(agent_id, "SUSPENDED", reason)

    def resume(self, agent_id: str, reason: str = "operator") -> None:
        if self.agent(agent_id)["state"] != "SUSPENDED":
            raise SyscallError("INVALID_REQUEST", f"{agent_id} is not suspended")
        rt = self.runtimes.get(agent_id)
        self.transition(agent_id, "WAITING" if rt and rt.blocked else "READY", reason)
        if rt:
            if rt.proc and rt.proc.returncode is None:
                os.kill(rt.proc.pid, signal.SIGCONT)
            rt.resume.set()

    def cancel(self, agent_id: str, reason: str = "operator") -> list[str]:
        """Terminate an agent and, via delegation revocation, every agent it spawned."""
        row = self.agent(agent_id)
        if row["state"] in TERMINAL:
            return []
        victims = self._descendants(agent_id) + [agent_id]
        self.delegations.revoke(row["delegation_id"], reason)
        for aid in victims:                                   # deepest first, then self
            self._finish(aid, "TERMINATED", reason)
        return victims

    def _descendants(self, agent_id: str) -> list[str]:
        """Live descendants, deepest first (children settle before their parents)."""
        out = []
        for r in self.store.all("SELECT agent_id, state FROM agents WHERE parent_agent=?",
                                (agent_id,)):
            out += self._descendants(r["agent_id"])
            if r["state"] not in TERMINAL:
                out.append(r["agent_id"])
        return out

    def inject_crash(self, agent_id: str, op: str, nth: int = 1) -> None:
        """Fault injection: SIGKILL the agent right after the kernel completes its nth `op`,
        before the reply reaches it — the worst moment for a non-idempotent change."""
        self.runtimes[agent_id].crash_plan = {"op": op, "nth": nth, "seen": 0}

    async def wait(self, agent_id: str, timeout: float = 60.0) -> str:
        return await asyncio.wait_for(asyncio.shield(self.runtimes[agent_id].done), timeout)

    # -- scheduling hooks -------------------------------------------------
    def _release_slot(self, rt: AgentRuntime) -> None:
        if rt.holds_slot:
            rt.holds_slot = False
            self.scheduler.release(rt.agent_id)

    async def _acquire_slot(self, rt: AgentRuntime) -> None:
        row = self.agent(rt.agent_id)
        while True:
            await rt.resume.wait()
            await self.scheduler.acquire(rt.agent_id, row["priority"], row["deadline"])
            if rt.resume.is_set():
                break
            self.scheduler.release(rt.agent_id)     # suspended while queued
        rt.holds_slot = True
        if self.agent(rt.agent_id)["state"] == "READY":
            self.transition(rt.agent_id, "RUNNING", "scheduled")

    async def block(self, agent_id: str, reason: str, aw):
        """Park an agent on a blocking syscall: give up the slot, WAITING(reason), re-schedule."""
        rt = self.runtimes.get(agent_id)
        if rt is None:                               # in-process (test) caller
            return await aw
        self._release_slot(rt)
        if self.agent(agent_id)["state"] == "RUNNING":
            self.transition(agent_id, "WAITING", reason)
        rt.blocked = True
        try:
            if rt.proc is None:
                return await aw
            waiter = asyncio.ensure_future(aw)
            died = asyncio.ensure_future(rt.proc.wait())
            await asyncio.wait({waiter, died}, return_when=asyncio.FIRST_COMPLETED)
            if not waiter.done():                   # the agent died while parked
                waiter.cancel()
                rt.cancelled_wait = True
                raise SyscallError("PROVIDER_ERROR", "agent process exited during wait")
            died.cancel()
            return waiter.result()
        finally:
            rt.blocked = False
            if not rt.cancelled and not getattr(rt, "cancelled_wait", False):
                if self.agent(agent_id)["state"] == "WAITING":
                    self.transition(agent_id, "READY", f"{reason} satisfied")
                await self._acquire_slot(rt)

    # -- process management -----------------------------------------------
    def _start(self, agent_id: str) -> None:
        rt = AgentRuntime(agent_id)
        self.runtimes[agent_id] = rt
        rt.task = asyncio.create_task(self._run_agent(rt), name=f"agent:{agent_id}")

    async def _run_agent(self, rt: AgentRuntime) -> None:
        try:
            while not rt.cancelled:
                await self._acquire_slot(rt)
                rt.cancelled_wait = False
                await self._spawn_process(rt)
                await self._serve(rt)
                await rt.proc.wait()
                self._release_slot(rt)
                if rt.exited or rt.cancelled or not self._on_crash(rt):
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:                           # kernel-side failure: fail the agent
            self.store.audit("kernel.error", agent_id=rt.agent_id, error=repr(e)[:500])
            try:
                self._finish(rt.agent_id, "FAILED", f"kernel error: {e!r}"[:200])
            except Exception:
                pass
        finally:
            self._release_slot(rt)
            if rt.proc and rt.proc.returncode is None:
                rt.proc.kill()
            if not rt.done.done():
                rt.done.set_result(self.agent(rt.agent_id)["state"])

    async def _spawn_process(self, rt: AgentRuntime) -> None:
        row = self.agent(rt.agent_id)
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(PROJECT_ROOT),
               "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"}   # no credentials
        argv = [sys.executable, "-m", "agenticos.runner", self.agent_types[row["agent_type"]]]
        if self.isolation == "process" and os.environ.get("AOS_REQUIRE_SANDBOX"):
            raise RuntimeError("AOS_REQUIRE_SANDBOX is set but no sandbox is available")
        if self.isolation == "seatbelt":
            argv = ["sandbox-exec", "-p", self._sandbox_profile()] + argv
        elif self.isolation == "bwrap":
            argv = self._bwrap_argv() + argv
        err = asyncio.subprocess.DEVNULL
        if self.log_dir:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            err = open(self.log_dir / f"{rt.agent_id}.log", "a")
        rt.proc = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=err,
            env=env, cwd=self._jail, limit=MAX_FRAME)
        if err is not asyncio.subprocess.DEVNULL:
            err.close()
        boot = {"boot": {"agent_id": rt.agent_id, "tenant": row["tenant"],
                         "intent_id": row["intent_id"], "role": row["role"],
                         "params": json.loads(row["params"] or "{}"),
                         "restarts": row["restarts"]}}
        rt.proc.stdin.write((json.dumps(boot) + "\n").encode())
        await rt.proc.stdin.drain()
        self.store.audit("agent.process.started", agent_id=rt.agent_id, intent_id=row["intent_id"],
                         pid=rt.proc.pid, restarts=row["restarts"], isolation=self.isolation)

    def _bwrap_argv(self) -> list[str]:
        """Linux: bubblewrap with the same contract as the macOS profile — read-only root,
        kernel state hidden under an empty tmpfs, no network namespace, own PID namespace."""
        argv = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
                "--tmpfs", "/tmp", "--unshare-net", "--unshare-pid", "--unshare-ipc",
                "--die-with-parent", "--new-session"]
        if self.state_dir:
            argv += ["--tmpfs", str(self.state_dir)]
        return argv + ["--dir", "/tmp/agent", "--chdir", "/tmp/agent", "--"]

    def _sandbox_profile(self) -> str:
        """macOS Seatbelt: no network, no file writes, kernel state unreadable. The pipe to the
        kernel is the agent's only way out (vExpertAI §3.H; AOS-0001 §14.8 'final enforcement
        moves to a layer the workload cannot bypass')."""
        rules = ["(version 1)", "(allow default)", "(deny network*)", "(deny file-write*)",
                 '(allow file-write* (literal "/dev/null"))']
        if self.state_dir:
            rules.append(f'(deny file-read* (subpath "{self.state_dir}"))')
        return "".join(rules)

    async def _serve(self, rt: AgentRuntime) -> None:
        """Fail closed: anything an agent sends that breaks the loop kills that agent and goes
        through normal crash accounting — never a wedged RUNNING agent."""
        try:
            await self._serve_loop(rt)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.store.audit("kernel.agent_fault", agent_id=rt.agent_id, error=repr(e)[:500])
            if rt.proc and rt.proc.returncode is None:
                rt.proc.kill()

    async def _serve_loop(self, rt: AgentRuntime) -> None:
        while True:
            line = await rt.proc.stdout.readline()
            if not line:
                return
            try:
                req = json.loads(line)
                rid, op = req.get("id"), req.get("op")
                if not isinstance(rid, (int, str, type(None))):
                    raise AttributeError
            except (json.JSONDecodeError, AttributeError, UnicodeDecodeError):
                await self._reply(rt, {"id": None, "ok": False, "error": SyscallError(
                    "INVALID_REQUEST", "malformed syscall frame").to_dict()})
                continue
            if not rt.holds_slot or not rt.resume.is_set():   # resumed or re-admitted: reschedule
                self._release_slot(rt)
                await self._acquire_slot(rt)
            if op == "agent.exit":                    # exit() is always permitted, like _exit(2)
                self._exit(rt, req.get("args"))
                await self._reply(rt, {"id": rid, "ok": True, "result": {}})
                continue
            rt.syscalls += 1
            try:
                result = await self.gateway.dispatch(rt.agent_id, op, req.get("target", ""),
                                                     req.get("args"), req.get("idempotency_key"))
                resp = {"id": rid, "ok": True, "result": result}
            except SyscallError as e:
                resp = {"id": rid, "ok": False, "error": e.to_dict()}
            except Exception as e:                    # kernel/provider bug: fail closed
                self.store.audit("kernel.error", agent_id=rt.agent_id, op=str(op), error=repr(e))
                resp = {"id": rid, "ok": False,
                        "error": SyscallError("PROVIDER_ERROR", f"internal: {e!r}").to_dict()}
            plan = rt.crash_plan
            if plan and plan["op"] == op:
                plan["seen"] += 1
                if plan["seen"] == plan["nth"]:
                    rt.crash_plan = None
                    self.store.audit("fault.injected", agent_id=rt.agent_id, op=op,
                                     kind="SIGKILL-before-reply")
                    rt.proc.kill()
                    return
            await self._reply(rt, resp)

    async def _reply(self, rt: AgentRuntime, msg: dict) -> None:
        try:
            rt.proc.stdin.write((json.dumps(msg, default=str) + "\n").encode())
            await rt.proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _exit(self, rt: AgentRuntime, args) -> None:
        args = args if isinstance(args, dict) else {}
        status = "COMPLETED" if args.get("status") == "completed" else "FAILED"
        result = json.dumps(args.get("result"), default=str)
        if len(result) > MAX_FRAME:
            result = json.dumps({"truncated": True})
        self.store.exec("UPDATE agents SET result=? WHERE agent_id=?", (result, rt.agent_id))
        rt.exited = True
        self._finish(rt.agent_id, status, str(args.get("reason", "agent exit"))[:500])

    def _finish(self, agent_id: str, state: str, reason: str) -> None:
        row = self.agent(agent_id)
        if row["state"] in TERMINAL:
            return
        for child in self._descendants(agent_id):             # no orphans keep spending
            self._finish(child, "TERMINATED", f"parent {agent_id} {state.lower()}")
        self.transition(agent_id, state, reason)
        rt = self.runtimes.get(agent_id)
        if rt and state != "COMPLETED" and not rt.exited:      # teardown before anything fallible
            rt.cancelled = True
            rt.resume.set()
            self._release_slot(rt)
            if rt.proc and rt.proc.returncode is None:
                rt.proc.kill()
            if rt.task and rt.task is not asyncio.current_task():
                rt.task.cancel()
        self.delegations.settle(row["delegation_id"])
        self.locks.release_all(agent_id)
        try:
            self._notify_parent(row, state, reason)
        except Exception as e:                                # notification is best-effort
            self.store.audit("kernel.error", agent_id=agent_id, error=repr(e)[:300])

    def _notify_parent(self, row: dict, state: str, reason: str) -> None:
        """SIGCHLD analogue: a kernel-originated CHILD_EXITED message to the parent agent."""
        parent = row["parent_agent"]
        if not parent or self.agent(parent)["state"] in TERMINAL:
            return
        mid = services.new_message_id()
        self.store.exec("INSERT INTO messages(message_id, source, destination, type,"
                        " correlation_id, payload, evidence_refs, deadline, status, ts)"
                        " VALUES (?,?,?,?,?,?,?,?, 'pending', ?)",
                        (mid, "kernel", parent, "CHILD_EXITED", None,
                         json.dumps({"child": row["agent_id"], "state": state, "reason": reason}),
                         "[]", time.time() + 3600, time.time()))
        self.mail_event(parent).set()

    def _on_crash(self, rt: AgentRuntime) -> bool:
        """Abnormal process death (no agent.exit). Restart from checkpoint within retry budget."""
        row = self.agent(rt.agent_id)
        self.locks.release_all(rt.agent_id)
        self.store.exec("UPDATE messages SET status='pending' WHERE destination=? AND "
                        "status='inflight'", (rt.agent_id,))     # redeliver unacked messages
        restarts = row["restarts"] + 1
        self.store.exec("UPDATE agents SET restarts=? WHERE agent_id=?", (restarts, rt.agent_id))
        self.store.audit("agent.crashed", agent_id=rt.agent_id, intent_id=row["intent_id"],
                         returncode=rt.proc.returncode, restarts=restarts)
        self._emit("crash", {"agent_id": rt.agent_id, "restarts": restarts})
        if restarts > row["retry_budget"]:
            self._finish(rt.agent_id, "FAILED", "retry budget exhausted")
            return False
        if row["state"] in ("RUNNING", "WAITING"):
            self.transition(rt.agent_id, "READY", "crash recovery: restart from checkpoint")
        return True

    async def recover(self) -> list[str]:
        """After a kernel restart, re-admit every non-terminal agent from durable state."""
        recovered = []
        for row in self.store.all("SELECT agent_id, state FROM agents WHERE state NOT IN "
                                  "('COMPLETED','FAILED','TERMINATED')"):
            aid = row["agent_id"]
            self.store.exec("UPDATE messages SET status='pending' WHERE destination=? AND "
                            "status='inflight'", (aid,))
            self.store.exec("UPDATE approvals SET status='expired' WHERE agent_id=? AND "
                            "status='pending'", (aid,))
            if row["state"] in ("RUNNING", "WAITING", "CREATED"):
                self.transition(aid, "READY", "kernel restart recovery")
            self._start(aid)
            if row["state"] == "SUSPENDED":
                self.runtimes[aid].resume.clear()
            recovered.append(aid)
        self.store.audit("kernel.recovered", agents=recovered)
        return recovered

    async def shutdown(self) -> None:
        for rt in list(self.runtimes.values()):
            rt.cancelled = True
            if rt.proc and rt.proc.returncode is None:
                rt.proc.kill()
            if rt.task:
                rt.task.cancel()
        await asyncio.gather(*(rt.task for rt in self.runtimes.values() if rt.task),
                             return_exceptions=True)
        for rt in self.runtimes.values():
            if rt.proc:
                try:
                    await asyncio.wait_for(rt.proc.wait(), 2)
                except (asyncio.TimeoutError, ProcessLookupError):
                    pass
        self.store.db.close()
