# fhe-attack-replay

> **Alpha.** `cheon-2024-127` runs as a real **live-oracle Replay** against
> three adapters:
> - `toy-lwe` (always available) — bisection-based encryption-noise
>   recovery across 8 trials of 20 rounds each.
> - `openfhe` (when `openfhe-python` is built locally) —
>   polynomial-domain bisection against real OpenFHE BFV/BGV using serialized
>   DCRT ciphertext mutation.
> - `lattigo` (when `fhe-replay-lattigo-helper` is on PATH) —
>   polynomial-domain bisection against real Lattigo BFV/BGV via a Go
>   helper binary that drives the unified `schemes/bgv` context.
>
> Unmitigated configs report `VULNERABLE` (exit 2); noise-flooded configs
> report `SAFE` (exit 0). The same module also runs as a **RiskCheck** on
> adapters without a live oracle. See [DISCLAIMER.md](DISCLAIMER.md) for
> what `SAFE` does and does not mean.

Framework for a unified attack-replay regression harness for FHE libraries.
Modules land in three intent levels — **Replay** (end-to-end exploit),
**RiskCheck** (static analysis of `(library, params)` against a known threat
model), and **ArtifactCheck** (validates user-supplied traces or evidence).
See [docs/status-semantics.md](docs/status-semantics.md).

**License:** Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

## Why

Hexens [awesome-fhe-attacks](https://github.com/Hexens/awesome-fhe-attacks) curates
attacks but does not run them. Every library and downstream user re-implements
attack PoCs ad-hoc to verify a fix. `fhe-attack-replay` is the framework that —
once the attack modules land — will let you answer the question "is my CKKS
config still vulnerable to Cheon 2024/127?" in seconds.

## Install

```bash
pip install fhe-attack-replay
```

To target a specific library, install the matching native dependency:

```bash
pip install openfhe         # OpenFHE python bindings  (Linux x86_64 only via PyPI)
pip install tenseal         # SEAL via TenSEAL
# Lattigo / tfhe-rs require helper binaries on PATH.
```

### Building `openfhe-python` from source (macOS / Windows / arm64)

The PyPI `openfhe` wheel only ships a Linux x86_64 ``.so``. Build from
source if you want the live OpenFHE Replay path on other platforms:

```bash
brew install cmake gmp ntl libomp pybind11   # or your distro's equivalents
git clone https://github.com/openfheorg/openfhe-development
cd openfhe-development
cmake -B build -DCMAKE_INSTALL_PREFIX="$HOME/.local/openfhe" \
              -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF
cmake --build build -j
cmake --install build

git clone https://github.com/openfheorg/openfhe-python && cd openfhe-python
cmake -B build \
  -DOpenFHE_DIR="$HOME/.local/openfhe/lib/OpenFHE" \
  -DPython_EXECUTABLE="$(which python3)" \
  -DCMAKE_PREFIX_PATH="$(python3 -c 'import pybind11; print(pybind11.get_cmake_dir())')"
cmake --build build -j
cp build/openfhe.cpython-*.so "$(python3 -c 'import site; print(site.getsitepackages()[0])')/"
mkdir -p "$(python3 -c 'import site; print(site.getsitepackages()[0])')/lib"
cp $HOME/.local/openfhe/lib/libOPENFHE*.dylib \
   "$(python3 -c 'import site; print(site.getsitepackages()[0])')/lib/"
python3 -c "import openfhe; print('OK')"
```

## Quick start

```bash
fhe-replay list all
fhe-replay doctor
fhe-replay run --lib openfhe --params examples/bfv-128.json --attacks all \
    --output-json report.json --badge badge.svg
```

For a dependency-free first run, use the in-tree toy LWE adapter:

```bash
fhe-replay run --lib toy-lwe --params examples/toy-lwe-vulnerable.json \
    --attacks cheon-2024-127
```

`fhe-replay doctor` reports which native adapters are available on the
current machine and prints the dependency note for each missing backend.

Exit codes:

| Code | Meaning                                                                       |
|-----:|-------------------------------------------------------------------------------|
| 0    | At least one attack ran and every result was `SAFE` (or `SKIPPED` if allowed) |
| 2    | At least one attack reported `VULNERABLE`                                     |
| 3    | Internal error during replay                                                  |
| 4    | One or more selected attacks were `NOT_IMPLEMENTED` (override: `--allow-not-implemented`) |
| 5    | Every selected attack was `SKIPPED` and no attack ran (override: `--allow-skipped`) |
| 64   | Usage error                                                                   |

`NOT_IMPLEMENTED` never silently passes by default — green CI requires real
results. See [docs/status-semantics.md](docs/status-semantics.md).

For CI gates that require a minimum implemented-attack ratio:

```bash
fhe-replay run --lib openfhe --params examples/bfv-128.json \
    --attacks cheon-2024-127 --min-coverage 1.0
```

## Attack modules

| ID                    | Source                                             | Intent             | Status     |
|-----------------------|----------------------------------------------------|--------------------|------------|
| `cheon-2024-127`      | Cheon, Hong, Kim — IACR ePrint 2024/127            | Replay + RiskCheck | implemented (Replay against toy-lwe and OpenFHE BFV/BGV; RiskCheck elsewhere) |
| `eprint-2025-867`     | Side-Channel Analysis in HE — IACR ePrint 2025/867 | Replay + RiskCheck | implemented (live decrypt-timing distinguisher on live-oracle adapters; SEAL/OpenFHE Harvey-butterfly fingerprint verdicts elsewhere) |
| `reveal-2023-1128`    | Aydin, Karabulut et al. — IACR ePrint 2023/1128    | ArtifactCheck      | implemented (in-tree Pearson-correlation analyzer over user-supplied JSON traces) |
| `guo-qian-usenix24`   | Guo et al. — USENIX Security 2024                  | RiskCheck          | implemented (average-case vs worst-case noise-flooding decision rule) |
| `glitchfhe-usenix25`  | Mankali et al. — USENIX Security 2025              | ArtifactCheck      | implemented (in-tree differential analyzer over user-supplied JSON/JSONL fault logs) |

### `cheon-2024-127` — IND-CPA-D Replay (live oracle)

Generates keys, encrypts `0`, perturbs the ciphertext polynomial toward the
rounding boundary, then runs a binary search on the decryption oracle to
recover the encryption-noise boundary. Repeats over `N` trials and inspects
the variance of the recovered boundary:

```text
trials := 8 bisection runs
rounds := 20 for toy-lwe; max(20, bit_length(delta)) for OpenFHE
delta  := q / t  (encoding scale)
threshold := max(1, 0.05 * delta)
deterministic := std(boundaries) < threshold
if deterministic:  VULNERABLE  (oracle leaks; published key recovery applies)
else:              SAFE        (oracle randomized; noise-recovery primitive does not converge)
```

Try it:

```bash
fhe-replay run --lib toy-lwe --params examples/toy-lwe-vulnerable.json --attacks cheon-2024-127
fhe-replay run --lib toy-lwe --params examples/toy-lwe-mitigated.json  --attacks cheon-2024-127
fhe-replay run --lib openfhe --params examples/bfv-128-vulnerable.json --attacks cheon-2024-127
```

For OpenFHE BFV/BGV, `openfhe-python` does not expose mutable DCRTPoly
coefficient APIs. The adapter therefore mutates the serialized OpenFHE JSON
ciphertext directly: it adds a constant polynomial to ciphertext component
`c0` across all DCRT towers, deserializes the ciphertext, and queries the
native decrypt oracle. Replay evidence records
`test=polynomial_domain_bisection`, `serialization_backend=openfhe-json`, the
plaintext modulus, and DCRT tower metadata.

For Lattigo BFV/BGV, the Go helper binary owns the keys and ciphertexts.
Perturbation is a per-tower constant addition on `Value[0].Coeffs` while the
ring is in evaluation form (Lattigo BGV defaults to NTT) — equivalent to
adding a constant polynomial in the time domain. The Python adapter
exchanges line-delimited JSON over stdin/stdout, with offsets sent as
decimal strings when delta exceeds int64. Replay evidence records
`serialization_backend=lattigo-bgv`,
`polynomial_domain="RNS evaluation form (NTT)"`, the plaintext modulus, and
the per-tower DCRT moduli sizes.

Mitigated configs (params with a recognized `noise_flooding` label like
`lattigo-noise-flooding`, `openfhe-noise-flooding-decrypt`,
`eprint-2024-424`) drive software flooding on the helper side: every
decrypt samples a fresh Gaussian-distributed integer offset (default
std-dev = `delta/4`, override via `noise_flooding_sigma`) and adds it
as a constant polynomial to c0 before native decryption. Cheon's
across-trial boundary variance then drives a real `SAFE` verdict via
Replay, not via the RiskCheck fallback. Evidence carries
`software_flooding_active=true` and the active sigma.

```bash
# Build the lattigo helper from source
cd vendor/lattigo-helper && go build -o "$HOME/.local/bin/fhe-replay-lattigo-helper" .
# Or download a pre-built binary from the GitHub Releases page and rename it
# to `fhe-replay-lattigo-helper` on PATH.

fhe-replay run --lib lattigo --params examples/bfv-128-vulnerable.json --attacks cheon-2024-127
```

### `guo-qian-usenix24` — Non-worst-case noise-flooding RiskCheck (CKKS)

Inspects `noise_flooding_strategy` (or `noise_flooding`) against the
Guo-Qian USENIX'24 threat model. Average-case-bound flooding constructions
(`li-micciancio`, `eprint-2020-1533`, …) are reported `VULNERABLE`;
worst-case-bound constructions (`openfhe-noise-flooding-decrypt`,
`eprint-2024-424`, `modulus-switching-2025-1627`, …) report `SAFE`. Configs
without an oracle exposure or without a recognized flooding label are
`SKIPPED`.

```bash
fhe-replay run --lib seal --attacks guo-qian-usenix24 \
    --params /dev/stdin <<'JSON'
{"scheme":"CKKS","adversary_model":"ind-cpa-d","noise_flooding_strategy":"li-micciancio"}
JSON
```

### `reveal-2023-1128` / `glitchfhe-usenix25` — ArtifactCheck

Both modules consume user-supplied evidence files via the CLI
`--evidence KEY=PATH` flag and record the analyst's declared outcome:

```bash
fhe-replay run --lib seal --attacks reveal-2023-1128 \
    --params examples/bfv-128.json \
    --evidence trace=runs/seal-ntt.npy
```

Set `params['hamming_weight_signature'] = 'recovered'` (or `'clean'`) to
record the result of an external single-trace correlation analysis;
`glitchfhe-usenix25` reads `params['differential_outcome']` similarly.
Without an outcome declaration the verdict is `NOT_IMPLEMENTED` —
the in-tree distinguishers are pending.

### `cheon-2024-127` — IND-CPA-D RiskCheck (static, all libs)

When the adapter cannot drive a live oracle, the same module runs as a
RiskCheck and inspects `(scheme, adversary_model, decryption_oracle,
noise_flooding)` against the threat model:

```text
oracle_access := decryption_oracle == True
                 OR adversary_model in {ind-cpa-d, threshold, multi-party}
mitigated    := noise_flooding in {openfhe-NOISE_FLOODING_DECRYPT,
                                   eprint-2024-424,
                                   eprint-2025-1627,
                                   eprint-2025-1618,
                                   noise-flooding}
if not oracle_access:        SKIPPED  (threat model n/a)
if mitigated:                SAFE
else:                        VULNERABLE
```

Try it:

```bash
fhe-replay run --lib seal --params examples/bfv-128-vulnerable.json --attacks cheon-2024-127
fhe-replay run --lib seal --params examples/bfv-128-mitigated.json  --attacks cheon-2024-127
```

When a live adapter is available, Replay supersedes this static declaration
check. For example, OpenFHE BFV/BGV only reports `SAFE` if the native decrypt
oracle is actually randomized enough for boundary recovery not to converge.

Each module cites its source and (where applicable) the reference PoC. Replay
implementations are written from public descriptions and ship under Apache-2.0;
no upstream PoC source is redistributed.

## Supported libraries

| Adapter    | Native dependency                                          | Live oracle? |
|------------|------------------------------------------------------------|:-:|
| `toy-lwe`  | none — pure Python, in-tree (CI validation only, not secure)| ✅ Replay |
| `openfhe`  | `openfhe-python` (PyPI wheel = Linux x86_64 only; build from source on macOS/Windows) | ✅ Replay (BFV/BGV polynomial-domain bisection via serialized DCRT mutation) |
| `lattigo`  | `fhe-replay-lattigo-helper` (Go binary on PATH; build from `vendor/lattigo-helper/` or grab a release asset) | ✅ Replay (BFV/BGV polynomial-domain bisection via per-tower constant addition in evaluation form) |
| `seal`     | `tenseal` (microsoft/SEAL backend)                          | ❌ scaffold |
| `tfhe-rs`  | `fhe-replay-tfhe-rs-helper` (Rust binary, PATH; helper crate scaffold) | ❌ scaffold |

> The tfhe-rs helper is still a scaffold (only `hello`/`shutdown` ops);
> its adapter falls back to RiskCheck or NOT_IMPLEMENTED until the
> Rust-side encrypt/decrypt ops land. The lattigo helper covers
> BFV/BGV; CKKS Replay is not yet wired (the `bgv` package handles
> exact-integer schemes only). Lattigo configs with a recognized
> `noise_flooding` mitigation label fall back to the static RiskCheck
> because the helper does not yet implement software flooding.

> When building openfhe-python from source for the live OpenFHE replay,
> pin a release that emits big DCRT moduli as JSON strings during
> serialization. The adapter's precision guard fails fast on JSON-float
> moduli >2^53 to avoid silent truncation.

## GitHub Action

```yaml
- uses: BAder82t/fhe-attack-replay@v0
  with:
    library: openfhe
    params: configs/bfv-128.json
    attacks: all
    min-coverage: "1.0"
```

## Python API

```python
from fhe_attack_replay import run
from fhe_attack_replay.report import to_svg_badge, write_json

report = run(library="openfhe", params={"scheme": "BFV"}, attacks=None)
write_json(report, "report.json")
print(to_svg_badge(report))
```

## Extending

Register a new adapter or attack via `register_adapter` / `register_attack`:

```python
from fhe_attack_replay import register_attack
from fhe_attack_replay.attacks.base import Attack, AttackResult, AttackStatus, Citation

class MyAttack(Attack):
    id = "my-attack-2026"
    title = "..."
    citation = Citation(...)
    def run(self, adapter, ctx):
        return AttackResult(...)

register_attack(MyAttack)
```

## Development

```bash
git clone https://github.com/BAder82t/fhe-attack-replay
cd fhe-attack-replay
python -m pip install -e ".[dev]"
ruff check .
pytest -ra --cov=fhe_attack_replay
python -m build
python -m twine check dist/*
```

## Project docs

- [DISCLAIMER.md](DISCLAIMER.md) — what `SAFE` does and does not mean
- [SECURITY.md](SECURITY.md) — vulnerability reporting policy
- [CONTRIBUTING.md](CONTRIBUTING.md) — module checklist and module-intent levels
- [docs/status-semantics.md](docs/status-semantics.md) — per-attack status, intent levels, exit codes
- [docs/pr-gates.md](docs/pr-gates.md) — using replay reports as PR gates
- [CHANGELOG.md](CHANGELOG.md)
