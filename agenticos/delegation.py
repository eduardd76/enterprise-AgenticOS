"""Authority-preserving delegation (AOS-0001 §6.9, §12.6, INV-004).

A delegation is a bounded grant: capability patterns, target patterns, memory paths,
production-write flag, call/token budget, and expiry. Children can only narrow it.
Patterns use a single trailing '*' meaning "any suffix" ("network.bgp.*", "router-edge-*").
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass, field

from .errors import SyscallError
from .store import Store


def matches(pattern: str, value: str) -> bool:
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return pattern == value


def covers(parent: str, child: str) -> bool:
    """True if every value matched by `child` is also matched by `parent`."""
    if parent.endswith("*"):
        return child.startswith(parent[:-1])
    return not child.endswith("*") and parent == child


def covered_by_any(parents: list[str], child: str) -> bool:
    return any(covers(p, child) for p in parents)


@dataclass
class Grant:
    """What a principal asks to hand to a delegatee."""
    capabilities: list[str]
    targets: list[str] = field(default_factory=list)
    memory_paths: list[str] = field(default_factory=list)
    production_write: bool = False
    budget_calls: int = 50
    budget_tokens: int = 20_000
    ttl_s: float = 600.0


def _validate(g: Grant) -> None:
    """Grants arrive from untrusted agents: reject anything that isn't a sane, typed value."""
    for name in ("budget_calls", "budget_tokens"):
        v = getattr(g, name)
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise SyscallError("INVALID_REQUEST", f"{name} must be a non-negative integer")
    for name in ("capabilities", "targets", "memory_paths"):
        v = getattr(g, name)
        if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
            raise SyscallError("INVALID_REQUEST", f"{name} must be a list of non-empty strings")


def _ttl(ttl: float) -> float:
    """NaN/inf/negative TTLs collapse to 0 (already expired) instead of poisoning comparisons."""
    return ttl if isinstance(ttl, (int, float)) and math.isfinite(ttl) and ttl > 0 else 0.0


class DelegationManager:
    def __init__(self, store: Store):
        self.s = store

    def get(self, delegation_id: str) -> dict:
        row = self.s.one("SELECT * FROM delegations WHERE delegation_id=?", (delegation_id,))
        if row is None:
            raise SyscallError("UNAUTHORIZED", f"unknown delegation {delegation_id}")
        d = dict(row)
        for k in ("capabilities", "targets", "memory_paths"):
            d[k] = json.loads(d[k])
        return d

    def remaining(self, d: dict) -> tuple[int, int]:
        return (d["budget_calls"] - d["used_calls"] - d["reserved_calls"],
                d["budget_tokens"] - d["used_tokens"] - d["reserved_tokens"])

    # -- creation --------------------------------------------------------
    def create_root(self, *, intent_id: str, tenant: str, principal: str, delegatee: str,
                    authority: Grant, grant: Grant) -> str:
        """Root grant from a human principal's standing authority to the first agent."""
        _validate(grant)
        self._check_subset(authority.capabilities, authority.targets, authority.memory_paths,
                           authority.production_write, grant)
        if grant.budget_calls > authority.budget_calls or grant.budget_tokens > authority.budget_tokens:
            raise SyscallError("BUDGET_EXHAUSTED", "root grant exceeds principal's budget")
        return self._insert(None, intent_id, tenant, principal, delegatee, grant,
                            valid_until=time.time() + _ttl(min(grant.ttl_s, authority.ttl_s)))

    def attenuate(self, parent_id: str, delegatee: str, grant: Grant) -> str:
        """Child delegation: scope ⊆ parent, budget ≤ parent remaining, expiry ≤ parent (eq. 6–8)."""
        p = self.validate_chain(parent_id)
        _validate(grant)
        self._check_subset(p["capabilities"], p["targets"], p["memory_paths"],
                           bool(p["production_write"]), grant)
        rem_calls, rem_tokens = self.remaining(p)
        if grant.budget_calls > rem_calls or grant.budget_tokens > rem_tokens:
            raise SyscallError("BUDGET_EXHAUSTED",
                               f"child budget ({grant.budget_calls} calls, {grant.budget_tokens} tok)"
                               f" exceeds parent remaining ({rem_calls}, {rem_tokens})")
        valid_until = min(p["valid_until"], time.time() + _ttl(grant.ttl_s))
        # Reserve atomically: sum of children's budgets can never exceed the parent's remainder.
        self.s.exec("UPDATE delegations SET reserved_calls=reserved_calls+?, "
                    "reserved_tokens=reserved_tokens+? WHERE delegation_id=?",
                    (grant.budget_calls, grant.budget_tokens, parent_id))
        return self._insert(parent_id, p["root_intent_id"], p["tenant"], p["delegatee"],
                            delegatee, grant, valid_until=valid_until)

    def _check_subset(self, caps, targets, paths, prod_write, g: Grant) -> None:
        for c in g.capabilities:
            if not covered_by_any(caps, c):
                raise SyscallError("UNAUTHORIZED", f"capability '{c}' exceeds parent authority")
        for t in g.targets:
            if not covered_by_any(targets, t):
                raise SyscallError("UNAUTHORIZED", f"target '{t}' exceeds parent authority")
        for m in g.memory_paths:
            if not covered_by_any(paths, m):
                raise SyscallError("UNAUTHORIZED", f"memory path '{m}' exceeds parent authority")
        if g.production_write and not prod_write:
            raise SyscallError("UNAUTHORIZED", "production_write exceeds parent authority")

    def _insert(self, parent_id, intent_id, tenant, delegator, delegatee, g: Grant,
                valid_until: float) -> str:
        did = self.s.next_id("del")
        self.s.exec(
            "INSERT INTO delegations(delegation_id, parent_id, root_intent_id, delegator, delegatee,"
            " tenant, capabilities, targets, memory_paths, production_write, budget_calls,"
            " budget_tokens, valid_until, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (did, parent_id, intent_id, delegator, delegatee, tenant, json.dumps(g.capabilities),
             json.dumps(g.targets), json.dumps(g.memory_paths), int(g.production_write),
             g.budget_calls, g.budget_tokens, valid_until, time.time()))
        self.s.audit("delegation.created", intent_id=intent_id, delegation_id=did,
                      parent_id=parent_id, delegator=delegator, delegatee=delegatee,
                      capabilities=g.capabilities, targets=g.targets, memory_paths=g.memory_paths,
                      production_write=g.production_write, budget_calls=g.budget_calls,
                      budget_tokens=g.budget_tokens, valid_until=valid_until)
        return did

    # -- validation & accounting ----------------------------------------
    def validate_chain(self, delegation_id: str) -> dict:
        """The grant is usable only if it and every ancestor are unexpired and unrevoked."""
        now = time.time()
        leaf = d = self.get(delegation_id)
        while True:
            if d["revoked"]:
                raise SyscallError("REVOKED", f"delegation {d['delegation_id']} revoked")
            if d["valid_until"] < now:
                raise SyscallError("REVOKED", f"delegation {d['delegation_id']} expired")
            if not d["parent_id"]:
                return leaf
            d = self.get(d["parent_id"])

    def charge(self, delegation_id: str, calls: int, tokens: int, bill_overrun: bool = False) -> None:
        d = self.get(delegation_id)
        rem_calls, rem_tokens = self.remaining(d)
        if bill_overrun and tokens > rem_tokens:
            # The model already ran: bill what was consumed (capped at the grant) and fail.
            self.s.exec("UPDATE delegations SET used_tokens=used_tokens+? WHERE delegation_id=?",
                        (max(0, rem_tokens), delegation_id))
        if calls > rem_calls or tokens > rem_tokens:
            raise SyscallError("BUDGET_EXHAUSTED",
                               f"budget exhausted on {delegation_id} (calls left {rem_calls},"
                               f" tokens left {rem_tokens})")
        self.s.exec("UPDATE delegations SET used_calls=used_calls+?, used_tokens=used_tokens+?"
                    " WHERE delegation_id=?", (calls, tokens, delegation_id))

    def settle(self, delegation_id: str) -> None:
        """Child finished: release its reservation on the parent, bill what it actually used."""
        d = self.get(delegation_id)
        if d["settled"] or not d["parent_id"]:
            return
        parent = self.get(d["parent_id"])
        self.s.exec("UPDATE delegations SET reserved_calls=reserved_calls-?, "
                    "reserved_tokens=reserved_tokens-? WHERE delegation_id=?",
                    (d["budget_calls"], d["budget_tokens"], parent["delegation_id"]))
        # Usage always lands on a live ancestor: a parent that settled first must not swallow it.
        while parent["settled"] and parent["parent_id"]:
            parent = self.get(parent["parent_id"])
        self.s.exec("UPDATE delegations SET used_calls=used_calls+?, used_tokens=used_tokens+? "
                    "WHERE delegation_id=?", (d["used_calls"], d["used_tokens"],
                                              parent["delegation_id"]))
        self.s.exec("UPDATE delegations SET settled=1 WHERE delegation_id=?", (delegation_id,))

    def revoke(self, delegation_id: str, reason: str) -> list[str]:
        """Revoke a grant and all descendants (AOS-0001 B.4). Returns every revoked id."""
        revoked, frontier = [], [delegation_id]
        while frontier:
            did = frontier.pop()
            self.s.exec("UPDATE delegations SET revoked=1 WHERE delegation_id=?", (did,))
            revoked.append(did)
            frontier += [r["delegation_id"] for r in
                         self.s.all("SELECT delegation_id FROM delegations WHERE parent_id=?", (did,))]
        self.s.audit("delegation.revoked", delegation_id=delegation_id, reason=reason,
                     cascade=revoked)
        return revoked

    def lineage(self, delegation_id: str) -> list[str]:
        chain, d = [], self.get(delegation_id)
        while d:
            chain.append(d["delegation_id"])
            d = self.get(d["parent_id"]) if d["parent_id"] else None
        return chain
