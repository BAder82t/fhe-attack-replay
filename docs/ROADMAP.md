# Roadmap

This doc tracks the research-grade and infrastructure items that aren't
yet shipped in fhe-attack-replay. Each entry has a clear acceptance
criterion so anyone (including a future maintainer or a downstream
contributor) can pick it up.

The shipped surface — five attack modules with real verdicts, OpenFHE
BFV/BGV live-oracle replay, multi-stage CLI, JSON Schema, Marketplace
Action — is documented in [README.md](../README.md) and the
[CHANGELOG](../CHANGELOG.md). This file is the *unshipped* surface.

---

## Adapters

### Lattigo helper (Go) — `vendor/lattigo-helper/`

**Status**: scaffold (v0.1.0). `hello` and `shutdown` ops are wired,
the JSON wire format is locked, the Python adapter spawns the helper
and round-trips correctly. Encrypt / decrypt / perturb / plaintext_delta
return an explicit `{"error": "not yet implemented"}` response which
the Python side surfaces as `RuntimeError` (and the harness reports as
`ERROR`).

**Acceptance**: `cheon-2024-127` runs as a live-oracle Replay against
Lattigo BFV/BGV with `< 5%` end-to-end overhead vs the OpenFHE path on
the same parameter set. The `live_oracle` flag in
`LattigoAdapter.capability` flips to `True`. Tests in
`vendor/lattigo-helper/main_test.go` cover the new ops with table-driven
fixtures.

**Effort**: ~2 days. Lattigo's BFV API exposes mutable polynomial
coefficients directly, so `perturb_constant` is straightforward — no
serialisation roundtrip needed.

### tfhe-rs helper (Rust) — `vendor/tfhe-rs-helper/`

**Status**: scaffold (v0.1.0). Same shape as the Lattigo helper.

**Acceptance**: at minimum, `setup` / `encrypt` / `decrypt` work
against `tfhe::FheUint8` / `FheBool`. `cheon-2024-127` does **not**
apply (TFHE has a different threat model — no plaintext modulus in
the BFV sense), so the live-oracle path stays disabled; the static
RiskCheck path against `params["adversary_model"]` continues to work.

**Effort**: ~3 days. The bulk is figuring out which TFHE scheme maps to
which harness scheme name and writing the integer ↔ ciphertext
serialisation glue.

### SEAL live-oracle Cheon Replay

**Status**: not started. The current `seal` (TenSEAL) adapter is
RiskCheck-only because TenSEAL doesn't expose mutable ciphertext
polynomial coefficients.

**Acceptance**: TenSEAL ciphertext mutation via the underlying SEAL
Python-binding internals (Cython-level access to `Ciphertext::data()`)
or, alternatively, direct SEAL-Python (Huelse fork) integration via the
existing `seal-python` adapter. The latter is in progress in a separate
feature branch — see [CHANGELOG](../CHANGELOG.md) Unreleased section.

**Effort**: ~5 days for SEAL-Python; ~10 days for TenSEAL.

---

## Attack modules

### `eprint-2025-867` — power / EM trace ArtifactCheck path

**Status**: live software-timing distinguisher shipped in v0.1.1. The
published RevEAL / 2025/867 attacks are **power / EM** side channels;
this module's live distinguisher is a software-timing analog with
documented granularity caveats.

**Acceptance**: ArtifactCheck path that consumes a power or EM trace
file (via `--evidence trace=PATH`) and runs the published correlation
analyzer against per-NTT-tap intermediates. Maps directly onto the
existing `reveal-2023-1128` Pearson-correlation path; could share
~80% of the code.

**Effort**: ~2 days plus a public-trace dataset to test against.

### `guo-qian-usenix24` — live CKKS noise-flooding bypass

**Status**: RiskCheck-only. The live attack runs ~N decryption-oracle
queries against a CKKS deployment with a noise-flooding decrypt and
extracts secret-key bits via a statistical procedure.

**Acceptance**: Live Replay against the OpenFHE CKKS adapter with
`noise_flooding_strategy="li-micciancio"`. Reports `VULNERABLE` if the
Guo-Qian discriminator converges, `SAFE` otherwise. Requires either
~1k oracle queries on a real CKKS context (slow but possible) or a
mathematically-equivalent shortcut (faster, may bias the discriminator).

**Effort**: ~5 days. Research-grade — the published procedure is
non-trivial to port from the paper's Mathematica-style notation to
production Python.

---

## Documentation

### Public-API stability promise

**Status**: not yet documented. The package has been through `0.0.1`
→ `0.1.3` with several breaking changes (CLI subcommand required,
`Coverage.implemented` semantics, `toy-lwe` schemes).

**Acceptance**: a `docs/api-stability.md` page listing which
identifiers are stable (e.g. `AttackStatus`, `AttackIntent`,
`run()`, `MetricEnvelope`, the CLI surface) and which are
explicitly free to move (e.g. `_LIVE_BISECT_DISPATCH`, internal
helpers). SemVer commitments per identifier.

**Effort**: ~half a day.

### Threat-model overview across attack modules

**Status**: each attack module has its own docstring explaining its
threat model in 1–2 paragraphs. There's no top-level "what does this
harness verify and what does it not" page.

**Acceptance**: `docs/threat-model.md` (modeled on the equivalent in
fairlearn-fhe) summarising the threat model of each attack module,
which `(library, scheme, params)` combinations each one applies to,
and what an `OK` verdict from the harness does and does not imply.

**Effort**: ~1 day.

---

## Tooling

### Vendored binary releases

**Status**: vendor crates have build instructions but no pre-built
binaries are distributed. Users have to install Go / Rust toolchains
to use Lattigo / tfhe-rs even after the helpers' ops land.

**Acceptance**: GitHub release-attached binaries for
`fhe-replay-lattigo-helper` and `fhe-replay-tfhe-rs-helper` covering
linux-x86_64, linux-arm64, darwin-x86_64, darwin-arm64. CI workflow
builds them on tag push.

**Effort**: ~1 day. Standard cross-compile matrices for both Go and
Rust; no code changes needed.

### Property-based fuzzing of the JSON wire protocol

**Status**: each helper has a small unit test suite covering the
documented protocol. There's no fuzz testing of malformed payloads,
oversize payloads, etc.

**Acceptance**: `hypothesis`-based fuzz harness that drives
`_HelperProcess.request` with adversarially-shaped JSON and verifies
the helpers don't crash, hang, or leak the subprocess.

**Effort**: ~1 day.

---

## Priority for the next release cycle

If you want to ship one minor (`v0.2.0`) bump that has the highest
downstream impact:

1. **Lattigo helper ops** — unblocks the entire Lattigo line of
   verdicts. The existing `_HelperProcess` IPC is solid; the work
   is purely in `vendor/lattigo-helper/main.go`.
2. **Vendored binary releases** — the moment #1 is done, ship the
   binaries so users don't need a Go toolchain.
3. **`eprint-2025-867` ArtifactCheck path** — easiest research-grade
   win because it can re-use `reveal-2023-1128`'s correlation
   analyzer almost verbatim.

Further out, the SEAL live Cheon Replay and Guo-Qian live CKKS bypass
are the highest-impact "real research" items, but each is a
multi-week effort.
