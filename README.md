# fhe-attack-replay

Unified attack-replay regression harness for FHE libraries. Replays published
attacks against any `(library, params)` configuration and emits a JSON report
plus a status SVG badge.

**Status:** alpha scaffold — five attacks wired as `NOT_IMPLEMENTED` placeholders;
adapter and CLI surface are stable.

**License:** Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

## Why

Hexens [awesome-fhe-attacks](https://github.com/Hexens/awesome-fhe-attacks) curates
attacks but does not run them. Every library and downstream user re-implements
attack PoCs ad-hoc to verify a fix. `fhe-attack-replay` ships one runner that
re-executes published attacks against your library/params configuration so you
can answer the question "is my CKKS config still vulnerable to Cheon 2024/127?"
in seconds.

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

| Code | Meaning                                  |
|-----:|------------------------------------------|
| 0    | All attacks reported SAFE / SKIPPED / NOT_IMPLEMENTED |
| 2    | At least one attack reported VULNERABLE  |
| 3    | Internal error during replay             |
| 64   | Usage error                              |

## Replayed attacks

| ID                    | Source                                             |
|-----------------------|----------------------------------------------------|
| `cheon-2024-127`      | Cheon, Hong, Kim — IACR ePrint 2024/127            |
| `reveal-2023-1128`    | Aydin, Karabulut et al. — IACR ePrint 2023/1128    |
| `eprint-2025-867`     | Side-Channel Analysis in HE — IACR ePrint 2025/867 |
| `guo-qian-usenix24`   | Guo et al. — USENIX Security 2024                  |
| `glitchfhe-usenix25`  | Mankali et al. — USENIX Security 2025              |

Each module cites its source and (where applicable) the reference PoC. Replay
implementations are written from public descriptions and ship under Apache-2.0;
no upstream PoC source is redistributed.

## Supported libraries

| Adapter   | Native dependency                              |
|-----------|------------------------------------------------|
| `openfhe` | `openfhe-python` bindings                      |
| `seal`    | `tenseal` (microsoft/SEAL backend)             |
| `lattigo` | `fhe-replay-lattigo-helper` (Go binary, PATH)  |
| `tfhe-rs` | `fhe-replay-tfhe-rs-helper` (Rust binary, PATH)|

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

## Roadmap

This repo ships the scaffold from
[Spec 2](../prototype_discovery_results.md#spec-2--fhe-attack-replay-approved-82100).
Iteration order: adapter wiring → Cheon 2024/127 → eprint 2025/867 → RevEAL
2023/1128 → Guo-Qian USENIX'24 → GlitchFHE USENIX'25 → Hexens PR + Zellic
cross-reference + WAHC 2026 poster.
