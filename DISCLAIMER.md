# Disclaimer

`fhe-attack-replay` is a regression and research-validation tool. It re-runs
published attacks against a configured FHE library/parameter target and
reports the outcome.

**A `SAFE` result does not prove that an FHE library or deployment is
secure.** It only means that the selected replay module did not reproduce
the selected attack under the provided configuration and the assumptions
encoded in that module — including:

- the chosen library version and build flags,
- the supplied scheme/parameters,
- the threat model assumed by the original paper (e.g. plaintext-checking
  oracle access, single-trace side-channel access, fault-injection
  capability),
- the modeling fidelity of the replay (a software replay of a hardware
  side-channel attack is, by construction, a lower bound on real-world
  exploitability).

Conversely, a `NOT_IMPLEMENTED` or `SKIPPED` result does not imply safety
in any direction; it means the harness did not exercise that attack.

This tool is **not**:

- a substitute for a code or design audit,
- a substitute for cryptographic peer review,
- a substitute for hardware-side-channel evaluation in a controlled lab,
- a certification, conformity assessment, or regulatory-grade attestation.

Use the JSON report's `coverage` block to understand how many of the
selected attacks actually produced a verdict. Treat unimplemented or
skipped modules as gaps, not as passes.

## Defensive use only

This software is published for defensive security research, library
hardening, regression testing, and educational use. Do not run it against
systems you do not own or do not have explicit, written authorization to
test.

## Liability

The Apache License 2.0 governs all use of this software. Sections 7
(Disclaimer of Warranty) and 8 (Limitation of Liability) of that license
apply in full. See [LICENSE](LICENSE).
