# Contributing to Enterprise AgenticOS

Thanks for helping. This project is a security boundary for AI agents, so the bar is
"provably correct and tested", not "seems to work".

## Getting started

```bash
git clone https://github.com/eduardd76/enterprise-AgenticOS && cd enterprise-AgenticOS
python3 -m pip install -e '.[dev]'      # Python >= 3.12, no runtime dependencies
python3 -m pytest -q                    # must be green before and after your change
python3 -m agenticos demo               # end-to-end AI NOC scenario
```

On Linux, install `bubblewrap` so agents run sandboxed (the sandbox escape test is skipped
without it).

## Ground rules

1. **Kernel invariants are non-negotiable.** Read `docs/DESIGN.md` §5 and
   `CONFORMANCE.md`. A change that weakens an invariant needs an explicit rationale in the
   PR and a maintainer sign-off.
2. **Every bug fix ships with a failing-first test.** Security fixes go in
   `tests/test_adversarial.py`, runtime and lifecycle fixes in `tests/test_invariants.py` or
   `tests/test_processes.py`.
3. **Fail closed.** If the kernel cannot represent or verify a constraint, it denies the
   request. Don't add fallbacks that silently allow.
4. **Untrusted input stays untrusted.** Anything arriving from an agent frame (args, grants,
   ids, numbers) is validated in the kernel. Never coerce it into validity.
5. **No runtime dependencies in the kernel** without discussion. Adapters for external systems
   (OPA, OpenTelemetry, PostgreSQL, Vault) belong behind the registry/provider interfaces.
6. Match the surrounding code style. Keep comments for *why*, not *what*.

## Good first areas

See issues labelled `good first issue`. The roadmap is the "Recommended v0.2 order" section in
`CONFORMANCE.md`:
- keyed audit chain
- obligation tracking (INV-009)
- intent lifecycle (AOS-0001 Table 17)
- PostgreSQL store
- OpenTelemetry export
- an OPA policy adapter
- real network drivers
- the benchmark against a plain agent-framework baseline

## Pull requests

- Keep each PR to one concern.
- Describe which invariant or spec section it touches.
- Paste the `pytest` summary line.
- By contributing, you agree your contribution is licensed under Apache-2.0.

## Security issues

See [SECURITY.md](SECURITY.md). Please report privately, not as public issues.
