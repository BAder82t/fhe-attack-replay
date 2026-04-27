# `fhe-replay-lattigo-helper`

Tiny Go binary that bridges the Python `fhe-attack-replay` harness to
`tuneinsight/lattigo` (a pure-Go FHE library). The harness's
`LattigoAdapter` shells out to this binary and exchanges JSON messages
on stdin/stdout.

## Status

**Scaffold (v0.1.0).** Only `hello` and `shutdown` commands are wired.
The remaining commands (`setup`, `encrypt`, `decrypt`,
`perturb_constant`, `plaintext_delta`) return an explicit
`{"error":"… not yet implemented …"}` response. The adapter surfaces
those as Python `RuntimeError`s, which the harness's runner reports
as `ERROR` per intended behaviour — no false-positive verdicts.

This scaffold exists to lock in the wire format so a follow-up PR can
implement the lattigo bindings without touching the Python side.

## Build

```bash
cd vendor/lattigo-helper
go build -o "$HOME/.local/bin/fhe-replay-lattigo-helper" .
# or, with GOPATH on PATH:
go install
```

The Python adapter looks up `fhe-replay-lattigo-helper` via
`shutil.which`, so make sure your install location is on `PATH`.

## Wire protocol

Line-oriented JSON. One request per line, one response per line. The
request schema is documented in `main.go`. Example dialogue:

```
> {"op":"hello"}
< {"scheme_support":["BFV","BGV","CKKS"],"version":"0.1.0"}
> {"op":"setup","scheme":"BFV","params":{"plaintext_modulus":65537,"poly_degree":8192}}
< {"error":"command \"setup\" not yet implemented in helper v0.1.0; this is a scaffold pending lattigo BFV/BGV wiring"}
> {"op":"shutdown"}
< {"ok":true}
```

## Smoke test

A no-deps smoke test ships in this directory:

```bash
go test ./...
```

It only exercises the `hello` and `shutdown` commands; once the other
ops are wired they need their own table-driven tests.

## Roadmap

1. Wire `setup` / `encrypt` / `decrypt` against
   `github.com/tuneinsight/lattigo/v6/schemes/bfv` (plus the BGV and
   CKKS schemes).
2. Implement `perturb_constant` via direct ciphertext-element
   manipulation (lattigo exposes mutable polynomial coefficients).
3. Add `plaintext_delta` (returns `Q / t` for BFV/BGV; raises for
   CKKS — matches the OpenFHE adapter's semantics).
4. Add `evaluator_fingerprint` (NTT variant, build flags) so
   `eprint-2025-867` RiskCheck has Lattigo-specific data to consume.

The Python adapter is ready to consume each of these the moment they
land — the contract is the wire protocol above.
