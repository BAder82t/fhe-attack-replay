package main

import (
	"bufio"
	"encoding/json"
	"strings"
	"testing"
)

// roundtrip walks one or more requests through the helper's writeJSON
// path and decodes the responses. Stdin is provided as a string of
// newline-terminated JSON lines.
//
// The real `main()` reads stdin and writes stdout; we re-use the same
// command-dispatch by replicating it here. Keeps the binary itself
// dependency-free while still pinning the protocol shape.
func roundtrip(t *testing.T, input string) []response {
	t.Helper()
	var got []response
	scanner := bufio.NewScanner(strings.NewReader(input))
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<24)
	out := &capturingWriter{}
	w := bufio.NewWriter(out)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			writeJSON(w, response{"error": "malformed JSON: " + err.Error()})
			w.Flush()
			continue
		}
		switch req.Op {
		case "hello":
			writeJSON(w, response{
				"version":        helperVersion,
				"scheme_support": []string{"BFV", "BGV", "CKKS"},
			})
		case "shutdown":
			writeJSON(w, response{"ok": true})
		case "setup", "encrypt", "decrypt", "perturb_constant", "plaintext_delta":
			writeJSON(w, response{"error": "scaffold-only"})
		default:
			writeJSON(w, response{"error": "unknown op: " + req.Op})
		}
		w.Flush()
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}
	for _, raw := range strings.Split(strings.TrimRight(out.String(), "\n"), "\n") {
		if raw == "" {
			continue
		}
		var r response
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			t.Fatalf("failed to parse response %q: %v", raw, err)
		}
		got = append(got, r)
	}
	return got
}

func TestHello(t *testing.T) {
	got := roundtrip(t, `{"op":"hello"}`+"\n")
	if len(got) != 1 {
		t.Fatalf("expected 1 response, got %d", len(got))
	}
	if got[0]["version"] != helperVersion {
		t.Fatalf("expected version %q, got %v", helperVersion, got[0]["version"])
	}
}

func TestShutdown(t *testing.T) {
	got := roundtrip(t, `{"op":"shutdown"}`+"\n")
	if got[0]["ok"] != true {
		t.Fatalf("expected ok=true, got %v", got[0])
	}
}

func TestUnknownOp(t *testing.T) {
	got := roundtrip(t, `{"op":"frobnicate"}`+"\n")
	if got[0]["error"] == nil {
		t.Fatalf("expected error response, got %v", got[0])
	}
}

func TestMalformedJSON(t *testing.T) {
	got := roundtrip(t, "not json\n")
	if got[0]["error"] == nil {
		t.Fatalf("expected error response, got %v", got[0])
	}
}

func TestScaffoldOpsReturnExplicitError(t *testing.T) {
	for _, op := range []string{"setup", "encrypt", "decrypt", "perturb_constant", "plaintext_delta"} {
		req, _ := json.Marshal(request{Op: op})
		got := roundtrip(t, string(req)+"\n")
		if got[0]["error"] == nil {
			t.Fatalf("op %q: expected scaffold error, got %v", op, got[0])
		}
	}
}

// capturingWriter is a minimal io.Writer that accumulates bytes for inspection.
type capturingWriter struct {
	buf strings.Builder
}

func (c *capturingWriter) Write(p []byte) (int, error) {
	return c.buf.Write(p)
}

func (c *capturingWriter) String() string {
	return c.buf.String()
}
