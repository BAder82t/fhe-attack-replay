# Pull Request Gates

Use `fhe-attack-replay` as a PR gate when changes can affect decrypt,
parameter selection, evaluator behavior, or native FHE build flags.

## Minimal Gate

```yaml
name: fhe-replay

on:
  pull_request:

jobs:
  replay:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: BAder82t/fhe-attack-replay@v0
        with:
          library: toy-lwe
          params: examples/toy-lwe-mitigated.json
          attacks: cheon-2024-127
          min-coverage: "1.0"
          output-json: fhe-replay-report.json
          badge: fhe-replay-badge.svg
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: fhe-replay
          path: |
            fhe-replay-report.json
            fhe-replay-badge.svg
```

## Native OpenFHE Gate

For projects that already build `openfhe-python`, run the action after the
native dependency is installed:

```yaml
- uses: BAder82t/fhe-attack-replay@v0
  with:
    library: openfhe
    params: configs/bfv-128.json
    attacks: cheon-2024-127
    min-coverage: "1.0"
```

If `openfhe-python` is missing, the adapter falls back to RiskCheck paths where
possible. Do not treat a run as green unless the JSON report has acceptable
`coverage.ratio`.

## Review Checklist

- `overall_status` is not `vulnerable` or `error`.
- `coverage.ratio` meets the repository policy.
- `not_implemented` is zero unless the PR explicitly accepts scaffolded checks.
- `skipped` is understood and documented in the PR.
- The report and badge are uploaded as artifacts for auditability.

## Exit Codes

| Code | Meaning |
|---:|---|
| 0 | Results satisfy the selected gates. |
| 2 | At least one attack reported `VULNERABLE`. |
| 3 | Internal replay error. |
| 4 | `NOT_IMPLEMENTED` result or `--min-coverage` failure. |
| 5 | Every selected attack was `SKIPPED`. |
| 64 | Usage error. |
