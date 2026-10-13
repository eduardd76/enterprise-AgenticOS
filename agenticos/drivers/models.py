"""Model providers for the `model.infer` capability.

Three providers show feasibility-before-ranking (AOS-0001 §12.3–12.5):
  * local-llm  — OpenAI-compatible endpoint (vLLM / llama.cpp / Ollama) when AOS_MODEL_URL is set.
                 Output is schema-validated; invalid output falls back to mock-local.
  * mock-local — deterministic rule-based reasoner; always available, used by tests and demo.
  * cloud-llm  — deliberately off-prem: always rejected under the sovereign profile.
"""

from __future__ import annotations

import asyncio
import json
import os
import urllib.request

from ..errors import SyscallError
from ..registry import CallContext, Capability, Provider, Registry


def _tokens(obj) -> int:
    return max(1, len(json.dumps(obj)) // 4)


async def mock_infer(ctx: CallContext, target: str, args: dict) -> dict:
    """Deterministic stand-in for an LLM: produces competing hypotheses from evidence."""
    ev = args.get("evidence", {})
    bgp, iface = ev.get("bgp", {}), ev.get("interface", {})
    hypotheses = []
    if iface.get("admin") == "down":
        hypotheses.append({"id": "H1", "claim": "Transport failure: interface administratively down",
                           "likelihood": 0.92,
                           "remediation": {"interface": iface.get("interface"), "admin": "up"}})
    if bgp.get("last_reset") == "Hold timer expired" or bgp.get("hold_time") == 0:
        hypotheses.append({"id": "H2", "claim": "BGP hold timer misconfigured",
                           "likelihood": 0.85,
                           "remediation": {"neighbor": bgp.get("neighbor"), "hold_time": 90}})
    hypotheses.append({"id": "H0", "claim": "Remote peer failure (outside our control)",
                       "likelihood": 0.15 if hypotheses else 0.5, "remediation": None})
    out = {"hypotheses": hypotheses,
           # Like real LLMs, the mock sometimes over-reaches and suggests acting directly.
           "suggested_action": {"op": "network.config.apply",
                                "change": hypotheses[0]["remediation"]}
           if hypotheses[0]["remediation"] else None}
    out["_tokens"] = _tokens(args) + _tokens(out)
    return out


def _model_timeout() -> float:
    return float(os.environ.get("AOS_MODEL_TIMEOUT_S", "120"))


def _local_llm_healthy() -> bool:
    return bool(os.environ.get("AOS_MODEL_URL"))


SYSTEM_PROMPT = """You are a network incident diagnosis model inside a governed operations kernel.
You receive JSON evidence about one BGP neighbor and its interface. Reply with ONLY a JSON object:
{"hypotheses": [{"id": "H1", "claim": "<one sentence>", "likelihood": <0..1>,
                 "remediation": <object or null>}],
 "suggested_action": {"op": "network.config.apply", "change": <object>} or null}
Allowed remediation objects (anything else will be rejected):
  {"interface": "<interface name from evidence>", "admin": "up"}   when the interface is administratively down
  {"neighbor": "<neighbor ip>", "hold_time": 90}                  when the BGP hold timer is misconfigured
Use null when the cause is outside our control (e.g. the remote peer). Order hypotheses by likelihood."""


def _valid_change(c) -> bool:
    if not isinstance(c, dict):
        return False
    if set(c) == {"interface", "admin"}:
        return isinstance(c["interface"], str) and c["admin"] in ("up", "down")
    if set(c) == {"neighbor", "hold_time"}:
        return isinstance(c["neighbor"], str) and isinstance(c["hold_time"], int)
    return False


def validate_model_output(out) -> dict:
    """Model text is untrusted: keep only well-formed hypotheses; reject if none survive."""
    if not isinstance(out, dict) or not isinstance(out.get("hypotheses"), list):
        raise SyscallError("PROVIDER_ERROR", "model output missing hypotheses list")
    hyps = []
    for i, h in enumerate(out["hypotheses"][:5]):
        if not isinstance(h, dict) or not isinstance(h.get("claim"), str):
            continue
        try:
            lk = min(1.0, max(0.0, float(h.get("likelihood", 0))))
        except (TypeError, ValueError):
            continue
        rem = h.get("remediation")
        hyps.append({"id": str(h.get("id") or f"H{i + 1}")[:8], "claim": h["claim"][:300],
                     "likelihood": lk, "remediation": rem if _valid_change(rem) else None})
    if not hyps:
        raise SyscallError("PROVIDER_ERROR", "model produced no valid hypotheses")
    sa = out.get("suggested_action")
    sa = sa if isinstance(sa, dict) and sa.get("op") == "network.config.apply" \
        and _valid_change(sa.get("change")) else None
    return {"hypotheses": hyps, "suggested_action": sa}


async def local_llm_infer(ctx: CallContext, target: str, args: dict) -> dict:
    url = os.environ["AOS_MODEL_URL"].rstrip("/") + "/v1/chat/completions"
    body = {"model": os.environ.get("AOS_MODEL_NAME", "local"),
            "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                         {"role": "user", "content": json.dumps(args.get("evidence", {}))}],
            "temperature": 0, "response_format": {"type": "json_object"}}

    def call() -> dict:
        req = urllib.request.Request(url, json.dumps(body).encode(),
                                     {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=_model_timeout() - 5) as r:
            return json.loads(r.read())

    try:
        resp = await asyncio.to_thread(call)
        raw = json.loads(resp["choices"][0]["message"]["content"])
    except Exception as e:  # provider failure -> gateway falls back to next feasible provider
        raise SyscallError("PROVIDER_ERROR", f"local-llm: {e}") from e
    out = validate_model_output(raw)
    out["model"] = resp.get("model", body["model"])
    out["_tokens"] = resp.get("usage", {}).get("total_tokens", _tokens(body))
    return out


async def cloud_llm_infer(ctx: CallContext, target: str, args: dict) -> dict:
    raise SyscallError("PROVIDER_ERROR", "cloud-llm must never be reached under sovereign profile")


def register(reg: Registry) -> None:
    reg.register(Capability(
        "model.infer", "Generate diagnostic hypotheses from evidence", "none", True, "none",
        ("task", "evidence"), ("hypotheses",),
        [Provider("local-llm", local_llm_infer, on_prem=True, healthy=_local_llm_healthy,
                  trust=0.9, reliability=0.9, latency=0.5, cost=0.2,
                  timeout_s=_model_timeout()),
         # The scripted mock ranks below a healthy local model (lower trust: it can't reason).
         Provider("mock-local", mock_infer, on_prem=True, trust=0.5, reliability=0.99,
                  latency=0.0, cost=0.0),
         Provider("cloud-llm", cloud_llm_infer, on_prem=False, trust=0.95, reliability=0.99,
                  latency=0.3, cost=0.6)]))
