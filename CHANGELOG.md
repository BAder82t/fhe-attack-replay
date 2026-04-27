# Changelog

All notable changes to `fhe-attack-replay` are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-04-27

### Added — `reveal-2023-1128` in-tree single-trace correlation analyzer
- **`reveal-2023-1128` now ships an in-tree Pearson-correlation
  analyzer** that replaces the prior `NOT_IMPLEMENTED` placeholder.
  Pass a trace via `--evidence trace=PATH` pointing to a JSON
  document with `samples: [float]` and
  `model: [{label, predictions: [float]}]`. The analyzer computes
  Pearson |ρ| between the trace samples and each candidate model's
  predictions, picks the strongest, and reports `VULNERABLE` when
  |ρ| > `reveal_correlation_threshold` (default 0.5). Otherwise →
  `SAFE`. Caller-supplied `hamming_weight_signature` still
  short-circuits the analyzer for users with their own decision
  pipeline.
- New params for `reveal-2023-1128`:
  `reveal_correlation_threshold`. Evidence carries
  `analyzer="in_tree_pearson_correlation"`, `n_samples`, `n_models`,
  `correlation_threshold`, `best_model`, `best_correlation`, and
  `all_model_scores` with per-model `correlation` + `degenerate`
  flags (the flag fires when a model has zero variance and Pearson is
  undefined; analyzer treats those as no signal).
- Trace-file parser surfaces every malformed input as `ERROR` with a
  precise diagnostic — invalid JSON, non-object top level, missing
  `samples`/`model`, mismatched prediction length, non-numeric
  values, model-not-an-object, out-of-range threshold.
- `reveal-2023-1128` results now record real `duration_seconds`
  rather than `0.0`.

### Changed — test infrastructure
- The catalog no longer contains any `NOT_IMPLEMENTED`-returning
  attack. A test-only `pending_attack_id` fixture in
  `tests/conftest.py` registers a synthetic scaffold attack so the
  runner / CLI's `NOT_IMPLEMENTED` exit-path tests stay exercised
  end-to-end.

## [0.1.1] - 2026-04-27

### Added — `glitchfhe-usenix25` in-tree differential analyzer
- **`glitchfhe-usenix25` now ships an in-tree differential analyzer**
  that replaces the prior `NOT_IMPLEMENTED` placeholder. Pass a fault
  log via `--evidence fault_log=PATH` (JSON array or JSONL, comments
  with `#` allowed in JSONL) where each record carries `expected` and
  `observed` integer arrays. The analyzer computes the **effective
  fault rate** (records with any expected/observed mismatch) and the
  **mean Hamming distance per effective fault**. A high effective rate
  (≥ `glitchfhe_min_effective_fault_rate`, default 0.05) combined with
  low Hamming distance per fault (≤ `glitchfhe_max_mean_hd`, default
  4.0) matches the GlitchFHE USENIX'25 signature → `VULNERABLE`.
  Otherwise → `SAFE`. Caller-supplied `differential_outcome` still
  short-circuits the analyzer for users with their own decision pipeline.
- New params for `glitchfhe-usenix25`:
  `glitchfhe_min_effective_fault_rate`, `glitchfhe_max_mean_hd`.
  Evidence carries `analyzer="in_tree_differential"`,
  `total_records`, `effective_faults`, `effective_fault_rate`,
  `total_hd`, `mean_hd_per_effective_fault`, plus a 32-record
  `per_record_sample` (with `per_record_truncated` flag for large logs).
- Fault-log parser auto-detects format from the first non-whitespace
  character (`[` → JSON array, otherwise JSONL); malformed records,
  missing `expected`/`observed` fields, and out-of-range thresholds
  surface as `ERROR` with a precise diagnostic line number.
- `glitchfhe-usenix25` results now record real `duration_seconds`
  rather than `0.0`.

### Added — `eprint-2025-867` live timing distinguisher
- **`eprint-2025-867` now runs as a live-oracle Replay against any
  adapter that advertises `live_oracle=True` and a non-constant-time
  Harvey-butterfly NTT fingerprint (today: OpenFHE BFV/BGV/CKKS).** The
  module times `adapter.decrypt` across two contrasting plaintext
  stimuli (default `[0,…]` vs `[1,…]`), repeats `replay_timing_repeats`
  times (default 64), and compares per-stimulus mean times. A
  coefficient-of-variation above `safe_timing_cv_threshold` (default
  5%) flags the decrypt path as data-dependent → `VULNERABLE`.
  Replay evidence carries `mode=replay`, `intent_actual=replay`,
  `test=decrypt_timing_distinguisher`, `cv_observed`, `cv_threshold`,
  `per_stimulus_mean_seconds`, `per_stimulus_stdev_seconds`, and
  `leakage_detected`. Falls back to the existing fingerprint
  risk-check on `NotImplementedError` from the adapter.
- New params for `eprint-2025-867`:
  `replay_timing_repeats`, `replay_timing_stimuli`,
  `safe_timing_cv_threshold`, `replay_seed`, and
  `disable_live_replay` (force the conservative fingerprint risk-check
  in CI environments where wall-clock measurements are too noisy).
- `cheon-2024-127` and `eprint-2025-867` results now record real
  `duration_seconds` from `time.monotonic()` rather than `0.0`.
- `cheon-2024-127` accepts `replay_seed` for per-trial reproducibility;
  trial seeds are derived from the master seed and recorded in evidence
  as `replay_master_seed` + `replay_trial_seeds`.
- `cheon-2024-127` mitigation aliases expanded:
  `kim-kim-park-2024`, `dp-decrypt`, `seal-noise-flooding`,
  `lattigo-noise-flooding`, `tfhe-rs-noise-flooding`,
  `li-micciancio-2024`, `rerandomization-2024-424`,
  `openfhe-noise-flood`, `noise-flood`, `noise-flooding-decrypt`.
- `cheon-2024-127` live-oracle dispatch is now capability-driven:
  any adapter exposing `perturb_ciphertext_constant` +
  `plaintext_delta` is routed through the generic polynomial-bisect
  path (was a hard-coded `{toy-lwe, openfhe}` allow-list).

## [0.1.0] - 2026-04-27

### Added — attack module promotions
- **`guo-qian-usenix24` is now an implemented RiskCheck.** Inspects
  `noise_flooding_strategy` (falling back to `noise_flooding` for
  cheon-2024-127-style configs) against the published threat model.
  Average-case-bound flooding (`li-micciancio`, `eprint-2020-1533`, …) is
  reported `VULNERABLE`; worst-case-bound flooding
  (`openfhe-noise-flooding-decrypt`, `eprint-2024-424`,
  `modulus-switching-2025-1627`, `hint-lwe-2025-1618`, …) is reported
  `SAFE`. CKKS-only.
- **`eprint-2025-867` now flags OpenFHE.** OpenFHE's evaluator fingerprint
  declares `ntt_variant: "harvey-butterfly"` (matching the family of
  guard / mul_root surfaces the paper targets). Builds without
  `params['constant_time_decrypt'] = true` are reported `VULNERABLE`;
  hardened builds report `SAFE`.
- **`reveal-2023-1128` is now an implemented ArtifactCheck.** Reads a
  user-supplied power/timing trace via `--evidence trace=PATH` and
  classifies the run based on `params['hamming_weight_signature']` —
  `recovered` → `VULNERABLE`, `clean` → `SAFE`, omitted → `NOT_IMPLEMENTED`
  (the in-tree single-trace correlation analyzer is still pending).
- **`glitchfhe-usenix25` is now an implemented ArtifactCheck.** Reads a
  user-supplied fault log via `--evidence fault_log=PATH` and classifies
  the run based on `params['differential_outcome']` — `recovered` →
  `VULNERABLE`, `resistant` → `SAFE`, omitted → `NOT_IMPLEMENTED`.
- **CLI `--evidence KEY=PATH`** (repeatable). Validates path existence at
  parse time; missing keys / paths return `EXIT_USAGE`. Surfaced into
  `params['evidence_paths'][key]` for ArtifactCheck modules to consume.

### Fixed
- `Coverage.implemented` no longer counts `ERROR` results. Only `SAFE` and
  `VULNERABLE` produce real verdicts, so `--min-coverage 1.0` no longer
  passes a run where every selected attack threw.
- `OpenFHEAdapter._setup_bfv/_bgv/_ckks` now wires
  `params["noise_flooding"]` into OpenFHE's native
  `EXEC_NOISE_FLOODING` / `NOISE_FLOODING_DECRYPT` execution mode when the
  linked openfhe-python build exposes those APIs. Previously the
  `openfhe-NOISE_FLOODING_DECRYPT` example would silently behave as
  unmitigated, producing a misleading live `VULNERABLE` verdict.
- OpenFHE polynomial-domain bisection now raises `RuntimeError` (surfaced
  as `ERROR` with traceback) when the perturbation cannot cross the
  decryption boundary, instead of `NOT_IMPLEMENTED` which falsely implied a
  scaffold.
- `OpenFHEAdapter._exact_int` guards against silent precision loss when
  cereal emits DCRT moduli or coefficients as JSON floats >2^53.
- `cheon-2024-127` lookups for `adversary_model` and `noise_flooding` now
  treat `_`, `-`, and whitespace separators interchangeably; canonical
  recognized labels are stored hyphenated (`openfhe-noise-flooding-decrypt`).
- `--attacks ""` (or whitespace / commas only) now returns
  `EXIT_USAGE` instead of silently running every registered attack.
- CLI subcommand is now required; `fhe-replay` without a verb prints help
  and exits cleanly. Removed the duplicate `_add_run_args(parser)`
  registration that allowed implicit run-style invocations.
- Toy-LWE adapter now advertises `("LWE",)` only — previously it also
  claimed `BFV` to satisfy `applies_to_schemes`, which let users believe
  they were testing real BFV. The cheon module now gates the live replay
  on `adapter.supports(scheme)` and falls back to RiskCheck when the
  scheme is unsupported by the adapter.

### Added
- `AdapterCapability.live_oracle` flag — adapters that can drive
  end-to-end encrypt/perturb/decrypt set this to `True`. Replay-mode
  attacks gate on this flag and fall back to RiskCheck for the rest.
- `examples/bfv-128-mitigated.json` now produces a live `SAFE` verdict
  against OpenFHE BFV when openfhe-python supports the noise-flooding
  execution mode, matching the README's documented behavior.
- `cheon-2024-127` accepts `params["safe_variance_frac_delta"]` to tune
  the SAFE-verdict threshold. Default `0.05`; lower values bias toward
  `SAFE`, higher toward `VULNERABLE`. Documented in
  `docs/status-semantics.md`.
- Action input `dev-install: true` installs from the checked-out repo
  instead of PyPI, for testing the action against an unreleased branch.
- `tests/fixtures/openfhe_bfv_ciphertext.json` pins the OpenFHE-JSON
  ciphertext layout the adapter traverses; failures here surface
  upstream archive reshapes in openfhe-python upgrades.

### Changed
- `runner._setup_or_synthetic` now also catches `RuntimeError` (in
  addition to `NotImplementedError`) so adapters that fail because a
  helper binary is missing on PATH still expose a synthetic context to
  RiskCheck-mode attacks.

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
