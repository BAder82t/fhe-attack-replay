# `fhe-replay-tfhe-rs-helper`

Tiny Rust binary that bridges the Python `fhe-attack-replay` harness to
`zama-ai/tfhe-rs`. The harness's `TfheRsAdapter` shells out to this
binary and exchanges JSON messages on stdin/stdout.

## Status

**Scaffold (v0.1.0).** Only `hello` and `shutdown` are wired. The
remaining commands (`setup`, `encrypt`, `decrypt`, `perturb_constant`,
`plaintext_delta`) return an explicit
`{"error": "… not yet implemented …"}` response. The Python adapter
surfaces those as `RuntimeError`s, which the harness's runner reports
as `ERROR` per intended behaviour — no false-positive verdicts.

This scaffold pins the wire format so a follow-up PR can implement the
tfhe-rs bindings without touching the Python side.

## Build

```bash
cd vendor/tfhe-rs-helper
cargo build --release
cp target/release/fhe-replay-tfhe-rs-helper "$HOME/.local/bin/"
```

The Python adapter looks up `fhe-replay-tfhe-rs-helper` via
`shutil.which`, so make sure your install location is on `PATH`.

## Wire protocol

Line-oriented JSON. One request per line, one response per line.
Example dialogue:

```
> {"op":"hello"}
< {"scheme_support":["TFHE","Boolean","ShortInt","Integer"],"version":"0.1.0"}
> {"op":"setup","scheme":"TFHE","params":{}}
< {"error":"command \"setup\" not yet implemented in helper v0.1.0 (scheme=Some(\"TFHE\")); this is a scaffold pending tfhe-rs wiring"}
> {"op":"shutdown"}
< {"ok":true}
```

## Tests

```bash
cargo test
```

Covers `hello`, `shutdown`, unknown ops, and the scaffold-op error
shape. When the real ops land they need their own table-driven tests.

## Roadmap

1. Add `tfhe = { version = "0.10", features = ["boolean", "shortint", "integer"] }`
   to `Cargo.toml`.
2. Wire `setup` against `tfhe::ConfigBuilder` (Boolean/ShortInt/Integer).
3. Wire `encrypt` / `decrypt` against `tfhe::FheBool`,
   `tfhe::FheUint8`, etc. Pick the type from the request's `scheme`
   field.
4. `perturb_constant` is meaningful for the integer schemes only;
   gate by scheme and raise `error` for Boolean.
5. `plaintext_delta` is N/A for TFHE (no plaintext modulus in the
   BFV sense); document the divergence and have it raise `error`
   so the cheon-2024-127 attack falls back to the static RiskCheck
   path automatically.

The Python adapter is ready to consume each of these the moment they
land — the contract is the wire protocol above.
