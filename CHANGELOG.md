# Changelog

All notable changes to `fhe-attack-replay` are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`cheon-2024-127` now runs as a real live-oracle Replay against
  OpenFHE BFV/BGV via `openfhe-python`.** The adapter now mutates serialized
  OpenFHE JSON ciphertexts directly, adding a constant polynomial to
  ciphertext component `c0` across all DCRT towers, deserializing the
  ciphertext, and running boundary bisection against the native decrypt
  oracle. Replay evidence records `test=polynomial_domain_bisection`,
  `serialization_backend=openfhe-json`, plaintext modulus, ciphertext
  modulus size, and DCRT tower metadata.
- **`cheon-2024-127` now runs as a real live-oracle Replay against the
  in-tree `toy-lwe` adapter.** Bisection-based encryption-noise recovery
  across 8 trials of 20 rounds each; verdict driven by the std-dev of the
  recovered boundary against `0.05 * delta`. Unmitigated configs report
  `VULNERABLE`; configs with `noise_flooding_sigma` ≳ delta/4 report
  `SAFE`. The same module falls back to RiskCheck when the adapter cannot
  drive a live oracle.
- **`toy-lwe` adapter and lab cryptosystem** under
  `src/fhe_attack_replay/lab/` and `src/fhe_attack_replay/adapters/`.
  Pure-Python LWE with deterministic seedable keygen / encrypt / decrypt
  and an optional `noise_flooding_sigma` mirroring OpenFHE's
  `NOISE_FLOODING_DECRYPT` randomization. Not cryptographically secure;
  exists so attack modules can be exercised end-to-end in CI.
- **OpenFHEAdapter wired against `openfhe-python`** for BFV / BGV / CKKS:
  setup (CCParams\* + KeyGen), encrypt (Make\*PackedPlaintext), decrypt
  (GetPackedValue / GetCKKSPackedValue). `is_available` performs a real
  import of the C++ extension — not just a metadata check — so the
  adapter falls back cleanly when the wheel is platform-incompatible.
- New examples: `examples/toy-lwe-vulnerable.json` and
  `examples/toy-lwe-mitigated.json` driving the Replay path end-to-end.
- `numpy>=1.26` is now a runtime dependency (used by the toy-lwe lab).
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
- Root `action.yml`, PR template, CI workflow, publish workflow, and
  `docs/pr-gates.md`.
- CLI flag `--min-coverage` to require a minimum implemented-attack ratio
  in CI gates.
- `eprint-2025-867` now reports a real RiskCheck `VULNERABLE` verdict for
  SEAL/TenSEAL fingerprints with known non-constant NTT surfaces.

### Changed
- `eprint-2025-867` is now declared as `intent=RISK_CHECK` (it inspects the
  evaluator fingerprint; a live trace distinguisher is still pending).
- `NOT_IMPLEMENTED` now causes a non-zero CLI exit by default. Previously
  it was treated as success, which could yield green CI for runs in
  which no attack actually ran.
- GitHub Action usage is now `BAder82t/fhe-attack-replay@v0`; the older
  `action/action.yml` copy remains for compatibility.
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
