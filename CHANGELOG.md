# Changelog

All notable changes to `fhe-attack-replay` are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `Coverage` block in every `RunReport` and JSON report (`requested`,
  `ran`, `safe`, `vulnerable`, `skipped`, `not_implemented`, `errors`,
  `implemented`, `ratio`).
- New CLI exit codes: `4` for one-or-more `NOT_IMPLEMENTED` results and
  `5` for runs where every selected attack was `SKIPPED`.
- New CLI flags `--allow-not-implemented` and `--allow-skipped` that
  restore the previous lenient behavior on demand.
- `DISCLAIMER.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- GitHub Action inputs `allow-not-implemented` and `allow-skipped`, plus
  output `coverage-ratio`.

### Changed
- `NOT_IMPLEMENTED` now causes a non-zero CLI exit by default. Previously
  it was treated as success, which could yield green CI for runs in
  which no attack actually ran.
- Badge label now reflects coverage (`X/N implemented`) when any module
  is `NOT_IMPLEMENTED`, instead of "scaffold".
- README rewritten to describe the project as a *framework* until at
  least one attack module produces real verdicts.

## [0.0.1] - 2026-04-27

### Added
- Initial scaffold: CLI, registry, JSON + SVG reports, GitHub Action,
  CI workflow, and citation-bearing module stubs for `cheon-2024-127`,
  `reveal-2023-1128`, `eprint-2025-867`, `guo-qian-usenix24`, and
  `glitchfhe-usenix25`.
- Adapter stubs for OpenFHE, SEAL (via TenSEAL), Lattigo (via Go helper),
  and tfhe-rs (via Rust helper).
- Apache-2.0 license, `NOTICE` with paper-level citations, `pyproject.toml`
  with hatchling backend.
