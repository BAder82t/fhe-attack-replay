# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security-sensitive reports.

Instead, email **baderissaei@gmail.com** with:

- a description of the issue,
- reproduction steps and a minimal proof of concept if possible,
- the affected version (`fhe-replay --version`) and Python version,
- whether you would like to be credited and under what name.

We aim to acknowledge reports within 5 business days and to publish a fix
or mitigation advisory within 90 days. Coordinated disclosure with paper
authors and library maintainers is welcome.

## Scope

In scope:

- Bugs in the harness, adapters, or attack modules that could mislead a
  user (e.g. a `SAFE` verdict produced when the attack would in fact have
  reproduced).
- Supply-chain issues in this repository (typo-squatted dependencies,
  malicious release artifacts, etc.).

Out of scope (please report upstream):

- Vulnerabilities in OpenFHE, microsoft/SEAL, Lattigo, tfhe-rs themselves —
  this tool exists to *surface* such issues; please coordinate with the
  upstream library maintainers and any cited paper authors.

## Threat model the harness assumes

See [DISCLAIMER.md](DISCLAIMER.md). In short: a `SAFE` result is meaningful
only relative to the threat model of the replayed attack and the
assumptions encoded in the corresponding module under
`src/fhe_attack_replay/attacks/`.
