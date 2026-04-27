// fhe-replay-lattigo-helper is a small CLI binary that bridges the Python
// fhe-attack-replay harness to tuneinsight/lattigo (a pure-Go FHE library).
//
// Protocol: line-oriented JSON on stdin/stdout. Each request is one
// JSON object on a line; each response is one JSON object on a line.
// The Python adapter (src/fhe_attack_replay/adapters/lattigo.py)
// spawns this binary and exchanges messages with it.
//
// Supported commands (v0):
//
//	{"op":"hello"}                   -> {"version":"0.1.0","scheme_support":["BFV","BGV","CKKS"]}
//	{"op":"setup","scheme":"BFV", "params":{...}}
//	                                 -> {"context_id":"<uuid>","plaintext_modulus":N,"poly_degree":N}
//	{"op":"encrypt","context_id":"<uuid>","values":[ints]}
//	                                 -> {"ciphertext_id":"<uuid>"}
//	{"op":"decrypt","context_id":"<uuid>","ciphertext_id":"<uuid>"}
//	                                 -> {"values":[ints]}
//	{"op":"perturb_constant","context_id":"<uuid>","ciphertext_id":"<uuid>","offset":N}
//	                                 -> {"ciphertext_id":"<uuid>"}
//	{"op":"plaintext_delta","context_id":"<uuid>","ciphertext_id":"<uuid>"}
//	                                 -> {"delta":N}
//	{"op":"shutdown"}                -> {"ok":true}  (then exits)
//
// Errors: any failure surfaces as `{"error":"..."}`.
//
// **Status: scaffold.** Only `hello` and `shutdown` are implemented in
// this version. Wiring the remaining commands against lattigo's BFV/BGV
// types (using the v6 API) is straightforward but requires the lattigo
// dependency to actually build; the Python adapter currently treats any
// non-implemented command as a `RuntimeError`, which the harness
// surfaces as ERROR per intended behaviour.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const helperVersion = "0.1.0"

type request struct {
	Op           string                 `json:"op"`
	Scheme       string                 `json:"scheme,omitempty"`
	Params       map[string]any         `json:"params,omitempty"`
	ContextID    string                 `json:"context_id,omitempty"`
	CiphertextID string                 `json:"ciphertext_id,omitempty"`
	Values       []int64                `json:"values,omitempty"`
	Offset       int64                  `json:"offset,omitempty"`
}

type response map[string]any

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1<<20), 1<<24)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	for in.Scan() {
		line := in.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			writeJSON(out, response{"error": "malformed JSON: " + err.Error()})
			continue
		}
		switch req.Op {
		case "hello":
			writeJSON(out, response{
				"version":        helperVersion,
				"scheme_support": []string{"BFV", "BGV", "CKKS"},
			})
		case "shutdown":
			writeJSON(out, response{"ok": true})
			out.Flush()
			return
		case "setup", "encrypt", "decrypt", "perturb_constant", "plaintext_delta":
			writeJSON(out, response{
				"error": fmt.Sprintf(
					"command %q not yet implemented in helper v%s; "+
						"this is a scaffold pending lattigo BFV/BGV wiring",
					req.Op, helperVersion,
				),
			})
		default:
			writeJSON(out, response{
				"error": "unknown op: " + req.Op,
			})
		}
		out.Flush()
	}
	if err := in.Err(); err != nil && err != io.EOF {
		writeJSON(out, response{"error": "stdin scan error: " + err.Error()})
		out.Flush()
		os.Exit(1)
	}
}

func writeJSON(w *bufio.Writer, payload response) {
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"error":"failed to marshal response"}`)
	}
	w.Write(body)
	w.WriteByte('\n')
}
