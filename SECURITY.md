# Security Policy

## Status: preview — not production-hardened

Enterprise AgenticOS v0.1 is a **design-partner preview**. Its security boundary has been
red-teamed (see `tests/test_adversarial.py`), but known gaps remain and are listed in
[`CONFORMANCE.md`](CONFORMANCE.md#unsupported--not-yet-implemented). Do not connect it to
production network devices without your own review.

## Security model in one paragraph

Agents are untrusted. Each runs as a separate OS process, confined by a sandbox (macOS
Seatbelt or Linux bubblewrap): no network, no file writes, kernel state unreadable,
scrubbed environment. The only channel out is a JSON syscall pipe to the kernel. The kernel
identifies the caller by pipe, not by anything the agent says. Every request goes through one
gateway that checks lifecycle, intent integrity, capability, delegated authority, tenant,
policy, budget and idempotency before any provider runs. Production writes also require a
single-use human approval, bound to the exact change, plus a re-check of the device state.
Set `AOS_REQUIRE_SANDBOX=1` in any real deployment so the kernel refuses to run agents
without a sandbox.

## Known limitations (summary)

- The audit chain is hash-linked but **not keyed**. Anyone with write access to the state
  database can rewrite it consistently.
- The kernel does not yet track policy obligations (INV-009).
- Lock leases have no fencing tokens.
- On hosts without `sandbox-exec` or `bwrap`, isolation falls back to plain processes,
  unless `AOS_REQUIRE_SANDBOX` is set.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting:
*Security → Report a vulnerability* on this repository. Include a reproducing test in the
style of `tests/test_adversarial.py` if you can, because that is how fixes are verified and
kept fixed.

We aim to acknowledge reports within 5 business days.

## Scope

In scope: anything that lets an agent process get around the gateway or its grant, or escape
its sandbox. Also: cross-tenant access, approval bypass or replay, a non-idempotent action
running twice, audit forgery that the chain can't detect, and kernel denial of service from a
single agent.
