"""Confidence as a control signal (AOS-0001 §6.11, §12.7–12.8, Table 13).

The kernel — not the agent — turns a confidence vector into one of six control actions.
Agents report component evidence; they cannot choose the action themselves.
"""

from __future__ import annotations

import math

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


def decide_action(agg: float, components: dict[str, float], impact: str, reversible: bool) -> str:
    """Map evidence to a control action (eq. 11).

    This is the system's risk appetite, written as code. Trade-offs:
      * thresholds too low  -> consequential changes on thin evidence;
      * thresholds too high -> everything escalates and humans drown in approvals;
      * the per-component floor stops one strong signal hiding a weak one (the reason
        AOS-0001 keeps the vector instead of only the aggregate).
    """
    weakest = min(components.values()) if components else 0.0
    if impact == "high":
        if weakest < 0.5:
            return "TERMINATE" if not reversible else "ESCALATE"
        if agg >= 0.90 and weakest >= 0.80:
            return "PROCEED"
        if agg >= 0.80 and reversible:
            return "PROCEED_WITH_WARNING"
        return "ESCALATE"
    # low impact (read-only / informational)
    if agg >= 0.80:
        return "PROCEED"
    if agg >= 0.60:
        return "PROCEED_WITH_WARNING"
    return "RETRY"


def evaluate(components: dict[str, float], impact: str, reversible: bool) -> dict:
    unknown = set(components) - set(COMPONENTS)
    if unknown:
        raise ValueError(f"unknown confidence components: {sorted(unknown)}")
    agg = aggregate(components)
    action = decide_action(agg, components, impact, reversible)
    assert action in ACTIONS
    return {"components": components, "aggregate": round(agg, 4),
            "aggregation": {"method": "weighted_geometric_mean", "weights": "equal",
                            "epsilon": EPSILON},
            "impact": impact, "reversible": reversible, "decision": action}
