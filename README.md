# fhe-attack-replay

> **Alpha.** `cheon-2024-127` runs as a real **live-oracle Replay** against
> the in-tree `toy-lwe` adapter — bisection-based encryption-noise recovery
> across multiple trials, exit 2 on `VULNERABLE`, exit 0 on `SAFE` after
> noise flooding. The same module also runs as a **RiskCheck** on adapters
> without a live oracle (e.g. when the OpenFHE C++ build is missing). The
> OpenFHE adapter is wired against `openfhe-python` for setup / encrypt /
> decrypt; a faithful OpenFHE Replay (which needs polynomial-domain
> ciphertext perturbation) lands in a follow-up. See
> [DISCLAIMER.md](DISCLAIMER.md) for what `SAFE` does and does not mean.

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
pip install openfhe         # OpenFHE python bindings
pip install tenseal         # SEAL via TenSEAL
# Lattigo / tfhe-rs require helper binaries on PATH.
```

## Quick start

```bash
fhe-replay list all
fhe-replay run --lib openfhe --params examples/bfv-128.json --attacks all \
    --output-json report.json --badge badge.svg
```

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

## Attack modules

| ID                    | Source                                             | Intent             | Status     |
|-----------------------|----------------------------------------------------|--------------------|------------|
| `cheon-2024-127`      | Cheon, Hong, Kim — IACR ePrint 2024/127            | Replay + RiskCheck | implemented (Replay against toy-lwe; RiskCheck against openfhe/seal/lattigo/tfhe-rs) |
| `eprint-2025-867`     | Side-Channel Analysis in HE — IACR ePrint 2025/867 | RiskCheck          | partial (fingerprint short-circuit) |
| `reveal-2023-1128`    | Aydin, Karabulut et al. — IACR ePrint 2023/1128    | ArtifactCheck      | scaffold   |
| `guo-qian-usenix24`   | Guo et al. — USENIX Security 2024                  | RiskCheck          | scaffold   |
| `glitchfhe-usenix25`  | Mankali et al. — USENIX Security 2025              | ArtifactCheck      | scaffold   |

### `cheon-2024-127` — IND-CPA-D Replay (live oracle, toy-lwe)

Generates keys, encrypts `0`, then runs a binary search on the decryption
oracle to recover the encryption-noise boundary. Repeats over `N` trials
and inspects the variance of the recovered boundary:

```text
trials := 8 bisection runs of 20 rounds each
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
```

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
fhe-replay run --lib openfhe --params examples/bfv-128-vulnerable.json --attacks cheon-2024-127
fhe-replay run --lib openfhe --params examples/bfv-128-mitigated.json  --attacks cheon-2024-127
```

Each module cites its source and (where applicable) the reference PoC. Replay
implementations are written from public descriptions and ship under Apache-2.0;
no upstream PoC source is redistributed.

## Supported libraries

| Adapter    | Native dependency                                          | Live oracle? |
|------------|------------------------------------------------------------|:-:|
| `toy-lwe`  | none — pure Python, in-tree (CI validation only, not secure)| ✅ |
| `openfhe`  | `openfhe-python` (PyPI wheel = Linux x86_64 only; build from source on macOS/Windows) | ⚠ encrypt/decrypt wired; perturbation primitive pending |
| `seal`     | `tenseal` (microsoft/SEAL backend)                          | ❌ scaffold |
| `lattigo`  | `fhe-replay-lattigo-helper` (Go binary, PATH)               | ❌ scaffold |
| `tfhe-rs`  | `fhe-replay-tfhe-rs-helper` (Rust binary, PATH)             | ❌ scaffold |

## GitHub Action

```yaml
- uses: BAder82t/fhe-attack-replay@v0
  with:
    library: openfhe
    params: configs/bfv-128.json
    attacks: all
    fail-on-vulnerable: true
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
```

## Project docs

- [DISCLAIMER.md](DISCLAIMER.md) — what `SAFE` does and does not mean
- [SECURITY.md](SECURITY.md) — vulnerability reporting policy
- [CONTRIBUTING.md](CONTRIBUTING.md) — module checklist and module-intent levels
- [docs/status-semantics.md](docs/status-semantics.md) — per-attack status, intent levels, exit codes
- [CHANGELOG.md](CHANGELOG.md)

