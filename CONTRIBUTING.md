# Contributing

Thanks for your interest in `fhe-attack-replay`. Contributions are welcome
under the project's Apache-2.0 license; by submitting a pull request you
confirm that your contribution is offered under those terms.

## Quick start

```bash
git clone https://github.com/BAder82t/fhe-attack-replay
cd fhe-attack-replay
python -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev]"
ruff check .
pytest -ra --cov=fhe_attack_replay
python -m build
python -m twine check dist/*
```

Python 3.11+ is required (`StrEnum`, PEP 695-friendly typing).

## What we accept

- **New attack modules** that re-implement a published attack from its
  public description, with a `Citation`, the original PoC URL where one
  exists, and a clear evidence dict. **Do not vendor upstream PoC source
  unless you also import its license header and add it to `NOTICE`.**
- **New library adapters** for additional FHE libraries (or alternative
  bindings for an existing one).
- **Test improvements**, especially regression tests that lock in attack
  module behavior against a known-vulnerable / known-mitigated parameter
  pair.
- **Documentation, examples, and CI improvements.**

## What we do not accept

- Verbatim copies of upstream PoC source without an Apache-2.0-compatible
  license and matching attribution.
- Modules whose `SAFE` verdict is trivially achievable without exercising
  the attack (a `SAFE` result must mean the attack actually ran).
- Modules without a citation.

## Module checklist

A new attack module under `src/fhe_attack_replay/attacks/` should:

1. Subclass `Attack` and set `id`, `title`, `applies_to_schemes`,
   `citation`.
2. Return an `AttackResult` with a status drawn from `AttackStatus` and an
   evidence dict that lets a reviewer reconstruct the verdict (parameters,
   counters, statistical thresholds, decision rule).
3. Distinguish three intent levels (see
   [docs/status-semantics.md](docs/status-semantics.md)):
   - **Replay**: actually runs the exploit logic end-to-end.
   - **Risk check**: detects vulnerable parameter/config patterns
     statically — must say so in the result message.
   - **Artifact check**: validates traces, logs, or external evidence
     supplied by the user.
4. Ship with at least one parametric test that exercises a vulnerable and a
   mitigated configuration.

## Coding style

- `ruff check .` must pass.
- `pytest -ra --cov=fhe_attack_replay` must pass.
- `python -m build && python -m twine check dist/*` must pass before release.
- New code should carry the file header `Copyright 2026 Vaultbytes (Bader
  Issaei)` and `SPDX-License-Identifier: Apache-2.0`.
- Public APIs go in `__all__` of the relevant `__init__.py`.

## Commit style

Conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
`chore:`. Keep subjects under 72 characters.

## Reporting security issues

Do not file public issues for security-sensitive findings. See
[SECURITY.md](SECURITY.md).
