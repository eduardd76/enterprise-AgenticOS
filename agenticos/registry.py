"""Capability registry (AOS-0001 §6.4–6.5, §11.4, §12.3–12.5).

A capability is a stable outcome contract; providers are replaceable implementations.
Selection is feasibility-first (hard constraints remove providers), then utility ranking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from .errors import SyscallError

# side_effects: "none" (read-only), "internal" (kernel state only), "external-write" (consequential)
SIDE_EFFECTS = ("none", "internal", "external-write")

ProviderFn = Callable[["CallContext", str, dict], Awaitable[dict]]


@dataclass
class Provider:
    id: str
    fn: ProviderFn
    on_prem: bool = True
    healthy: Callable[[], bool] = lambda: True
    trust: float = 0.9
    reliability: float = 0.95
    latency: float = 0.2   # normalized penalty, 0 = instant
    cost: float = 0.1      # normalized penalty


@dataclass
class Capability:
    id: str
    description: str
    side_effects: str = "none"
    idempotent: bool = True
    target_kind: str = "none"          # "device" | "agent" | "path" | "none"
    required_args: tuple[str, ...] = ()
    output_keys: tuple[str, ...] = ()
    providers: list[Provider] = field(default_factory=list)
    reversible: bool = True            # declared by the capability owner, not by the caller

    @property
    def consequential(self) -> bool:
        return self.side_effects == "external-write"

    def manifest(self) -> dict:
        return {"id": self.id, "description": self.description, "side_effects": self.side_effects,
                "idempotent": self.idempotent, "target_kind": self.target_kind,
                "inputs": list(self.required_args), "outputs": list(self.output_keys),
                "providers": [p.id for p in self.providers]}


@dataclass
class CallContext:
    """What a provider sees: the authenticated caller and kernel handle, never raw credentials."""
    kernel: Any
    agent: dict
    delegation: dict
    op: str


class Registry:
    def __init__(self) -> None:
        self._caps: dict[str, Capability] = {}

    def register(self, cap: Capability) -> None:
        if cap.side_effects not in SIDE_EFFECTS:
            raise ValueError(f"bad side_effects {cap.side_effects}")
        if cap.consequential and cap.idempotent:
            raise ValueError("external-write capabilities must declare idempotent=False explicitly")
        self._caps[cap.id] = cap

    def get(self, op: str) -> Capability:
        cap = self._caps.get(op)
        if cap is None:
            raise SyscallError("UNKNOWN_CAPABILITY", f"no capability named '{op}'")
        return cap

    def all(self) -> list[Capability]:
        return list(self._caps.values())

    def select(self, cap: Capability, require_on_prem: bool) -> tuple[list[Provider], list[dict]]:
        """Return (ranked feasible providers, rejected-with-reason). Eq. (4) then eq. (5)."""
        feasible, rejected = [], []
        for p in cap.providers:
            if require_on_prem and not p.on_prem:
                rejected.append({"provider": p.id, "reason": "sovereignty: not on-prem"})
            elif not p.healthy():
                rejected.append({"provider": p.id, "reason": "unhealthy"})
            else:
                feasible.append(p)
        if not feasible:
            raise SyscallError("NO_FEASIBLE_PROVIDER",
                               f"{cap.id}: no feasible provider ({rejected})")

        def utility(p: Provider) -> float:
            return 0.4 * p.trust + 0.4 * p.reliability - 0.1 * p.latency - 0.1 * p.cost

        return sorted(feasible, key=utility, reverse=True), rejected
