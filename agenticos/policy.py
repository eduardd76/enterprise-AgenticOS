"""Deterministic, versioned policy engine (AOS-0001 §6.7, §9.4; vExpertAI §3.H).

Policy is code + data loaded at kernel boot. No capability can modify it, so model output
can propose actions but never rewrite the rules that judge them (vExpertAI kernel invariant).
Same inputs + same version => same decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .registry import Capability

POLICY_VERSION = "aos-policy-2026.10-v1"

# Sovereign deployment profile (AOS-0001 §13.7): only on-prem providers are feasible.
REQUIRE_ON_PREM = True

# Which human roles may approve which consequential capabilities (AOS-0001 §9.9).
APPROVER_ROLES: dict[str, set[str]] = {"network.config.apply": {"noc-lead"}}

# Namespaces no agent may write, regardless of grant.
PROTECTED_PATHS = ("/aos/policies", "/aos/audit", "/aos/agents")

CONSEQUENTIAL_OBLIGATIONS = ["full-lineage", "state-revalidation", "post-change-verification"]


@dataclass(frozen=True)
class PolicyDecision:
    outcome: str                      # "allow" | "deny" | "approve" (approval required)
    rule: str
    rationale: str
    obligations: list[str] = field(default_factory=list)
    version: str = POLICY_VERSION

    def to_dict(self) -> dict:
        return {"outcome": self.outcome, "rule": self.rule, "rationale": self.rationale,
                "obligations": self.obligations, "version": self.version}


def evaluate(cap: Capability, agent: dict, delegation: dict, target: str, args: dict,
             target_tenant: str | None) -> PolicyDecision:
    if cap.target_kind == "device":
        if target_tenant is None:
            return PolicyDecision("deny", "P-001", f"target '{target}' not in inventory")
        if target_tenant != agent["tenant"]:
            return PolicyDecision("deny", "P-001",
                                  f"cross-tenant target: {target} belongs to {target_tenant}")

    if cap.consequential:
        if not delegation["production_write"]:
            return PolicyDecision("deny", "P-002", "production_write not granted to this delegation")
        if not args.get("approval_id"):
            return PolicyDecision("approve", "P-003",
                                  "consequential action requires human approval",
                                  CONSEQUENTIAL_OBLIGATIONS)
        return PolicyDecision("allow", "P-003", "approved consequential action",
                              CONSEQUENTIAL_OBLIGATIONS)

    return PolicyDecision("allow", "P-000", "within delegated authority", ["standard-lineage"])
