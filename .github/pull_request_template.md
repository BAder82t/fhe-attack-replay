## Summary

- 

## Replay Evidence

Paste the relevant command and result:

```bash
fhe-replay run --lib toy-lwe --params examples/toy-lwe-vulnerable.json --attacks cheon-2024-127
```

## Checklist

- [ ] `python -m ruff check .`
- [ ] `python -m pytest -ra --cov=fhe_attack_replay`
- [ ] `python -m build`
- [ ] `python -m twine check dist/*`
- [ ] Added or updated attack evidence, citations, or docs when behavior changed.
- [ ] Confirmed `SAFE`/`VULNERABLE` wording matches `DISCLAIMER.md`.

