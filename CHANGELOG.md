# Changelog

All notable changes to `fhe-attack-replay` are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **First real attack module: `cheon-2024-127` as a RiskCheck.** Static
  analysis of `(scheme, adversary_model, decryption_oracle, noise_flooding)`
  against the Cheon-Hong-Kim 2024/127 IND-CPA-D threat model. Returns
  `VULNERABLE`, `SAFE`, or `SKIPPED` with a structured evidence dict.
  Recognized mitigations: `openfhe-NOISE_FLOODING_DECRYPT`,
  `eprint-2024-424`, `eprint-2025-1627` (modulus-switching),
  `eprint-2025-1618` (HintLWE-reduced-noise).
- `AttackIntent` enum with `REPLAY` / `RISK_CHECK` / `ARTIFACT_CHECK`
  values; every result now carries the module's intent so a `SAFE`
  verdict's strength is visible to consumers.
- Example params: `examples/bfv-128-vulnerable.json` and
  `examples/bfv-128-mitigated.json` — paired vulnerable/mitigated
  configurations that exercise the Cheon module end-to-end.
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
- `eprint-2025-867` is now declared as `intent=RISK_CHECK` (it inspects the
  evaluator fingerprint; the real distinguisher is still pending).
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
