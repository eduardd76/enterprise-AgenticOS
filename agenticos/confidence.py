"""Confidence as a control signal (AOS-0001 §6.11, §12.7–12.8, Table 13).

The kernel — not the agent — turns a confidence vector into one of six control actions.
Agents report component evidence; they cannot choose the action themselves.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass

COMPONENTS = ("intent", "context", "data", "model", "capability", "policy", "execution", "temporal")
ACTIONS = ("PROCEED", "PROCEED_WITH_WARNING", "RETRY", "FALLBACK", "ESCALATE", "TERMINATE")

# Actions that permit a consequential change to be submitted for approval.
ACTIONABLE = {"PROCEED", "PROCEED_WITH_WARNING"}

EPSILON = 0.01


def aggregate(components: dict[str, float]) -> float:
    """Weighted geometric mean with equal weights and an ε floor (eq. 9)."""
    values = [min(1.0, max(EPSILON, float(v))) for v in components.values()]
    if not values:
        return 0.0
    return math.exp(sum(math.log(v) for v in values) / len(values))


@dataclass(frozen=True)
class ConfidencePolicy:
    """An operator-set risk appetite. Tenants may differ; agents can never change it.

    Defaults are the v0.1 behaviour. Trade-offs:
      * thresholds too low  -> consequential changes reach approvers on thin evidence;
      * thresholds too high -> everything escalates and engineers drown in investigations;
      * the per-component floor stops one strong signal hiding a weak one (the reason
        AOS-0001 keeps the vector instead of only the aggregate).
    """
    high_proceed: float = 0.90        # production change: aggregate needed to PROCEED ...
    high_floor: float = 0.80          # ... with every component at least this
    high_warn: float = 0.80           # reversible change: aggregate for PROCEED_WITH_WARNING
    allow_warning: bool = True        # False: high-impact changes never proceed "with warning"
    hard_floor: float = 0.50          # any component below -> ESCALATE (TERMINATE if irreversible)
    low_proceed: float = 0.80         # read-only work
    low_warn: float = 0.60

    def __post_init__(self) -> None:
        for name, v in asdict(self).items():
            if name != "allow_warning" and not (isinstance(v, (int, float)) and
                                                not isinstance(v, bool) and 0.0 <= v <= 1.0):
                raise ValueError(f"{name} must be a number in [0, 1]")
        if not isinstance(self.allow_warning, bool):
            raise ValueError("allow_warning must be a boolean")
        if not (self.hard_floor <= self.high_floor and self.high_warn <= self.high_proceed
                and self.low_warn <= self.low_proceed):
            raise ValueError("inconsistent thresholds: need hard_floor <= high_floor, "
                             "high_warn <= high_proceed, low_warn <= low_proceed")

    @property
    def version(self) -> str:
        """Content hash: identical numbers => identical version, so decisions are replayable."""
        return "conf-" + hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()
                                        ).hexdigest()[:12]


DEFAULT_POLICY = ConfidencePolicy()


def decide_action(agg: float, components: dict[str, float], impact: str, reversible: bool,
                  policy: ConfidencePolicy = DEFAULT_POLICY) -> str:
    """Map evidence to a control action (eq. 11) under an operator-set policy."""
    p = policy
    weakest = min(components.values()) if components else 0.0
    if impact == "high":
        if weakest < p.hard_floor:
            return "TERMINATE" if not reversible else "ESCALATE"
        if agg >= p.high_proceed and weakest >= p.high_floor:
            return "PROCEED"
        if p.allow_warning and agg >= p.high_warn and reversible:
            return "PROCEED_WITH_WARNING"
        return "ESCALATE"
    # low impact (read-only / informational)
    if agg >= p.low_proceed:
        return "PROCEED"
    if agg >= p.low_warn:
        return "PROCEED_WITH_WARNING"
    return "RETRY"


def evaluate(components: dict[str, float], impact: str, reversible: bool,
             policy: ConfidencePolicy = DEFAULT_POLICY) -> dict:
    unknown = set(components) - set(COMPONENTS)
    if unknown:
        raise ValueError(f"unknown confidence components: {sorted(unknown)}")
    agg = aggregate(components)
    action = decide_action(agg, components, impact, reversible, policy)
    assert action in ACTIONS
    return {"components": components, "aggregate": round(agg, 4),
            "aggregation": {"method": "weighted_geometric_mean", "weights": "equal",
                            "epsilon": EPSILON},
            "impact": impact, "reversible": reversible, "decision": action,
            "policy_version": policy.version}
