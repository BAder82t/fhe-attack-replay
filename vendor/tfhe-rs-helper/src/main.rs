//! `fhe-replay-tfhe-rs-helper` is a small CLI binary that bridges the
//! Python `fhe-attack-replay` harness to `zama-ai/tfhe-rs`.
//!
//! Protocol: line-oriented JSON on stdin/stdout. One request object per
//! line, one response object per line. The Python adapter
//! (`src/fhe_attack_replay/adapters/tfhe_rs.py`) spawns this binary and
//! exchanges messages with it.
//!
//! Status: **scaffold (v0.1.0).** Only `hello` and `shutdown` are
//! implemented; the rest return an explicit
//! `{"error": "… not yet implemented …"}` response. Adding the tfhe-rs
//! bindings (gate the `tfhe` crate behind a feature, then wire the
//! ops) is straightforward but pulls in a several-second compile —
//! out of scope for this scaffold.
//!
//! Errors: any failure surfaces as `{"error": "..."}`.

use std::io::{self, BufRead, BufWriter, Write};

use serde::Deserialize;
use serde_json::{json, Value};

const HELPER_VERSION: &str = "0.1.0";

#[derive(Deserialize)]
struct Request {
    op: String,
    #[serde(default)]
    scheme: Option<String>,
    #[serde(flatten)]
    _rest: Value,
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        let raw = match line {
            Ok(s) => s,
            Err(e) => {
                writeln!(
                    out,
                    "{}",
                    json!({"error": format!("stdin read error: {}", e)})
                )
                .ok();
                continue;
            }
        };
        if raw.trim().is_empty() {
            continue;
        }
        let req: Request = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                writeln!(
                    out,
                    "{}",
                    json!({"error": format!("malformed JSON: {}", e)})
                )
                .ok();
                let _ = out.flush();
                continue;
            }
        };
        let response = handle(&req);
        writeln!(out, "{}", response).ok();
        let _ = out.flush();
        if req.op == "shutdown" {
            break;
        }
    }
}

fn handle(req: &Request) -> Value {
    match req.op.as_str() {
        "hello" => json!({
            "version": HELPER_VERSION,
            "scheme_support": ["TFHE", "Boolean", "ShortInt", "Integer"],
        }),
        "shutdown" => json!({ "ok": true }),
        "setup" | "encrypt" | "decrypt" | "perturb_constant" | "plaintext_delta" => {
            let scheme = req.scheme.clone().unwrap_or_default();
            json!({
                "error": format!(
                    "command \"{}\" not yet implemented in helper v{} (scheme={:?}); \
                     this is a scaffold pending tfhe-rs wiring",
                    req.op, HELPER_VERSION, scheme
                )
            })
        }
        other => json!({"error": format!("unknown op: {}", other)}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(body: &str) -> Value {
        let req: Request = serde_json::from_str(body).unwrap();
        handle(&req)
    }

    #[test]
    fn hello_reports_version() {
        let r = rt(r#"{"op":"hello"}"#);
        assert_eq!(r["version"], HELPER_VERSION);
        assert!(r["scheme_support"].is_array());
    }

    #[test]
    fn shutdown_returns_ok() {
        let r = rt(r#"{"op":"shutdown"}"#);
        assert_eq!(r["ok"], true);
    }

    #[test]
    fn unknown_op_returns_error() {
        let r = rt(r#"{"op":"frobnicate"}"#);
        assert!(r.get("error").is_some());
    }

    #[test]
    fn scaffold_ops_return_explicit_error() {
        for op in ["setup", "encrypt", "decrypt", "perturb_constant", "plaintext_delta"] {
            let body = format!(r#"{{"op":"{}"}}"#, op);
            let r = rt(&body);
            let err = r["error"].as_str().expect("error should be a string");
            assert!(err.contains("not yet implemented"), "op={} err={:?}", op, err);
        }
    }
}
