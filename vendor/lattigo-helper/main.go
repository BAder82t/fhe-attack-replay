// fhe-replay-lattigo-helper is a small CLI binary that bridges the Python
// fhe-attack-replay harness to tuneinsight/lattigo (a pure-Go FHE library).
//
// Protocol: line-oriented JSON on stdin/stdout. Each request is one
// JSON object on a line; each response is one JSON object on a line.
// The Python adapter (src/fhe_attack_replay/adapters/lattigo.py)
// spawns this binary and exchanges messages with it.
//
// Supported commands:
//
//	{"op":"hello"}                   -> {"version":"0.2.0","scheme_support":["BFV","BGV"]}
//	{"op":"setup","scheme":"BFV", "params":{...}}
//	                                 -> {"context_id":"<id>","plaintext_modulus":"N","poly_degree":N,"delta":"N","ciphertext_modulus_bits":N,"dcrt_tower_count":N,"dcrt_moduli_bits":[...]}
//	{"op":"encrypt","context_id":"<id>","values":[ints]}
//	                                 -> {"ciphertext_id":"<id>"}
//	{"op":"decrypt","context_id":"<id>","ciphertext_id":"<id>"}
//	                                 -> {"values":[ints]}
//	{"op":"perturb_constant","context_id":"<id>","ciphertext_id":"<id>","offset":N,"component":N}
//	                                 -> {"ciphertext_id":"<id>"}
//	{"op":"plaintext_delta","context_id":"<id>","ciphertext_id":"<id>"}
//	                                 -> {"delta":"N"}
//	{"op":"shutdown"}                -> {"ok":true}  (then exits)
//
// Errors: any failure surfaces as `{"error":"..."}`.
//
// Plaintext-modulus / Q / delta values that may exceed 2^53 are
// transmitted as decimal strings to round-trip through JSON without
// precision loss. The Python adapter parses them back via int().
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const helperVersion = "0.2.0"

type request struct {
	Op           string         `json:"op"`
	Scheme       string         `json:"scheme,omitempty"`
	Params       map[string]any `json:"params,omitempty"`
	ContextID    string         `json:"context_id,omitempty"`
	CiphertextID string         `json:"ciphertext_id,omitempty"`
	Values       []int64        `json:"values,omitempty"`
	// Offset accepts either a JSON number or a JSON decimal string so
	// big-int offsets (perturb amounts that exceed int64 against
	// production-bit-size delta = floor(Q/t)) round-trip without loss.
	Offset    any `json:"offset,omitempty"`
	Component int `json:"component,omitempty"`
}

type response map[string]any

// helperContext holds keys, encoder, encryptor/decryptor, and a registry
// of live ciphertexts for one (scheme, params) tuple.
type helperContext struct {
	scheme       string
	params       bgv.Parameters
	encoder      *bgv.Encoder
	encryptor    *rlwe.Encryptor
	decryptor    *rlwe.Decryptor
	ciphertexts  map[string]*rlwe.Ciphertext
	ciphertextN  uint64 // monotonic counter for ciphertext_id
}

var (
	contexts  = map[string]*helperContext{}
	contextN  uint64
)

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
		writeJSON(out, dispatch(&req))
		out.Flush()
		if req.Op == "shutdown" {
			return
		}
	}
	if err := in.Err(); err != nil && err != io.EOF {
		writeJSON(out, response{"error": "stdin scan error: " + err.Error()})
		out.Flush()
		os.Exit(1)
	}
}

func dispatch(req *request) response {
	switch req.Op {
	case "hello":
		return response{
			"version":        helperVersion,
			"scheme_support": []string{"BFV", "BGV"},
		}
	case "shutdown":
		return response{"ok": true}
	case "setup":
		return opSetup(req)
	case "encrypt":
		return opEncrypt(req)
	case "decrypt":
		return opDecrypt(req)
	case "perturb_constant":
		return opPerturbConstant(req)
	case "plaintext_delta":
		return opPlaintextDelta(req)
	default:
		return response{"error": "unknown op: " + req.Op}
	}
}

// -- helpers ----------------------------------------------------------------

func writeJSON(w *bufio.Writer, payload response) {
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"error":"failed to marshal response"}`)
	}
	w.Write(body)
	w.WriteByte('\n')
}

func newID(prefix string, counter *uint64) string {
	*counter++
	return fmt.Sprintf("%s-%d", prefix, *counter)
}

func paramInt(p map[string]any, key string, def int) int {
	if p == nil {
		return def
	}
	switch v := p[key].(type) {
	case nil:
		return def
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return def
		}
		return n
	}
	return def
}

func paramUint64(p map[string]any, key string, def uint64) uint64 {
	if p == nil {
		return def
	}
	switch v := p[key].(type) {
	case nil:
		return def
	case float64:
		return uint64(v)
	case int:
		return uint64(v)
	case int64:
		return uint64(v)
	case string:
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return def
		}
		return n
	}
	return def
}

func paramIntSlice(p map[string]any, key string, def []int) []int {
	if p == nil {
		return def
	}
	raw, ok := p[key].([]any)
	if !ok {
		return def
	}
	out := make([]int, 0, len(raw))
	for _, item := range raw {
		switch v := item.(type) {
		case float64:
			out = append(out, int(v))
		case int:
			out = append(out, v)
		case string:
			if n, err := strconv.Atoi(v); err == nil {
				out = append(out, n)
			}
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}

// log2OfPowerOfTwo returns log2(n) for n a positive power of two; -1 otherwise.
func log2OfPowerOfTwo(n int) int {
	if n <= 0 {
		return -1
	}
	for k, v := 0, n; v > 0; k, v = k+1, v>>1 {
		if v == 1 {
			if 1<<k == n {
				return k
			}
			return -1
		}
	}
	return -1
}

// -- ops --------------------------------------------------------------------

func opSetup(req *request) response {
	scheme := req.Scheme
	if scheme == "" {
		scheme = "BFV"
	}
	switch scheme {
	case "BFV", "BGV":
	default:
		return response{"error": fmt.Sprintf("unsupported scheme %q (BFV/BGV only)", scheme)}
	}

	polyDegree := paramInt(req.Params, "poly_degree", 8192)
	logN := log2OfPowerOfTwo(polyDegree)
	if logN < 0 {
		return response{"error": fmt.Sprintf("poly_degree must be a positive power of two; got %d", polyDegree)}
	}

	plainModulus := paramUint64(req.Params, "plaintext_modulus", 65537)
	if plainModulus == 0 {
		return response{"error": "plaintext_modulus must be > 0"}
	}

	logQ := paramIntSlice(req.Params, "log_q", []int{55, 40, 40, 40, 40})
	logP := paramIntSlice(req.Params, "log_p", []int{45})

	literal := bgv.ParametersLiteral{
		LogN:             logN,
		LogQ:             logQ,
		LogP:             logP,
		PlaintextModulus: plainModulus,
	}
	params, err := bgv.NewParametersFromLiteral(literal)
	if err != nil {
		return response{"error": "lattigo NewParametersFromLiteral: " + err.Error()}
	}

	kgen := bgv.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	enc := bgv.NewEncryptor(params, sk)
	dec := bgv.NewDecryptor(params, sk)
	ecd := bgv.NewEncoder(params)

	ringQ := params.RingQ()
	moduli := ringQ.ModuliChain()
	q := big.NewInt(1)
	bitsPerTower := make([]int, len(moduli))
	for i, m := range moduli {
		q.Mul(q, new(big.Int).SetUint64(m))
		bitsPerTower[i] = bits64Len(m)
	}
	t := new(big.Int).SetUint64(plainModulus)
	delta := new(big.Int).Quo(q, t)

	id := newID("ctx", &contextN)
	contexts[id] = &helperContext{
		scheme:      scheme,
		params:      params,
		encoder:     ecd,
		encryptor:   enc,
		decryptor:   dec,
		ciphertexts: map[string]*rlwe.Ciphertext{},
	}

	return response{
		"context_id":              id,
		"poly_degree":             params.N(),
		"plaintext_modulus":       strconv.FormatUint(plainModulus, 10),
		"delta":                   delta.String(),
		"ciphertext_modulus":      q.String(),
		"ciphertext_modulus_bits": q.BitLen(),
		"dcrt_tower_count":        len(moduli),
		"dcrt_moduli_bits":        bitsPerTower,
		"scheme":                  scheme,
	}
}

func bits64Len(n uint64) int {
	bits := 0
	for n > 0 {
		bits++
		n >>= 1
	}
	return bits
}

func opEncrypt(req *request) response {
	ctx, ok := contexts[req.ContextID]
	if !ok {
		return response{"error": "unknown context_id"}
	}
	values := req.Values
	if values == nil {
		values = []int64{}
	}
	pt := bgv.NewPlaintext(ctx.params, ctx.params.MaxLevel())
	if err := ctx.encoder.Encode(values, pt); err != nil {
		return response{"error": "encode: " + err.Error()}
	}
	ct, err := ctx.encryptor.EncryptNew(pt)
	if err != nil {
		return response{"error": "encrypt: " + err.Error()}
	}
	id := newID("ct", &ctx.ciphertextN)
	ctx.ciphertexts[id] = ct
	return response{"ciphertext_id": id}
}

func opDecrypt(req *request) response {
	ctx, ok := contexts[req.ContextID]
	if !ok {
		return response{"error": "unknown context_id"}
	}
	ct, ok := ctx.ciphertexts[req.CiphertextID]
	if !ok {
		return response{"error": "unknown ciphertext_id"}
	}
	pt := ctx.decryptor.DecryptNew(ct)
	out := make([]int64, ctx.params.N())
	if err := ctx.encoder.Decode(pt, out); err != nil {
		return response{"error": "decode: " + err.Error()}
	}
	return response{"values": out}
}

func opPerturbConstant(req *request) response {
	ctx, ok := contexts[req.ContextID]
	if !ok {
		return response{"error": "unknown context_id"}
	}
	src, ok := ctx.ciphertexts[req.CiphertextID]
	if !ok {
		return response{"error": "unknown ciphertext_id"}
	}
	component := req.Component
	if component < 0 || component >= len(src.Value) {
		return response{"error": fmt.Sprintf("component index %d out of range [0,%d)", component, len(src.Value))}
	}

	offset, err := parseOffset(req.Offset)
	if err != nil {
		return response{"error": "offset: " + err.Error()}
	}

	dst := src.CopyNew()
	level := dst.Level()
	moduli := ctx.params.RingQ().ModuliChain()
	if level+1 > len(moduli) {
		return response{"error": "ciphertext level exceeds RingQ moduli chain"}
	}
	moduli = moduli[:level+1]

	poly := dst.Value[component]
	for tower, q := range moduli {
		residue := bigSignedModUint64(offset, q)
		coeffs := poly.Coeffs[tower]
		for i := range coeffs {
			sum := coeffs[i] + residue
			if sum >= q {
				sum -= q
			}
			coeffs[i] = sum
		}
	}

	id := newID("ct", &ctx.ciphertextN)
	ctx.ciphertexts[id] = dst
	return response{"ciphertext_id": id}
}

// parseOffset accepts either a JSON number (decoded as float64), a JSON
// integer (rare in encoding/json — surfaces as float64 too), or a JSON
// decimal string. Returns a *big.Int. Bisect callers send decimal
// strings when delta exceeds int64; the wire protocol stays
// number-friendly for small offsets.
func parseOffset(raw any) (*big.Int, error) {
	switch v := raw.(type) {
	case nil:
		return big.NewInt(0), nil
	case float64:
		// JSON numbers parse as float64. We require integer values; reject
		// fractional offsets explicitly so callers don't silently truncate.
		if v != float64(int64(v)) {
			return nil, fmt.Errorf("non-integer JSON number %v", v)
		}
		return big.NewInt(int64(v)), nil
	case string:
		bi, ok := new(big.Int).SetString(v, 10)
		if !ok {
			return nil, fmt.Errorf("invalid decimal string %q", v)
		}
		return bi, nil
	}
	return nil, fmt.Errorf("unsupported offset type %T", raw)
}

// bigSignedModUint64 returns ((offset mod q) + q) mod q as uint64,
// supporting negative offsets without overflow. Equivalent to Python's
// offset % q.
func bigSignedModUint64(offset *big.Int, q uint64) uint64 {
	bigQ := new(big.Int).SetUint64(q)
	r := new(big.Int).Mod(offset, bigQ)
	if r.Sign() < 0 {
		r.Add(r, bigQ)
	}
	return r.Uint64()
}

func opPlaintextDelta(req *request) response {
	ctx, ok := contexts[req.ContextID]
	if !ok {
		return response{"error": "unknown context_id"}
	}
	if _, ok := ctx.ciphertexts[req.CiphertextID]; !ok {
		// plaintext_delta is parameter-level; but mirroring OpenFHE, we still
		// require a ciphertext handle so fingerprinting can vary per-level.
		return response{"error": "unknown ciphertext_id"}
	}
	moduli := ctx.params.RingQ().ModuliChain()
	q := big.NewInt(1)
	for _, m := range moduli {
		q.Mul(q, new(big.Int).SetUint64(m))
	}
	t := new(big.Int).SetUint64(ctx.params.PlaintextModulus())
	delta := new(big.Int).Quo(q, t)
	return response{"delta": delta.String()}
}

