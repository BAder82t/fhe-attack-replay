package main

import (
	"math/big"
	"strconv"
	"testing"
)

func resetState() {
	contexts = map[string]*helperContext{}
	contextN = 0
}

func TestHello(t *testing.T) {
	resetState()
	got := dispatch(&request{Op: "hello"})
	if got["version"] != helperVersion {
		t.Fatalf("expected version %q, got %v", helperVersion, got["version"])
	}
	schemes, ok := got["scheme_support"].([]string)
	if !ok || len(schemes) == 0 {
		t.Fatalf("expected non-empty scheme_support, got %v", got["scheme_support"])
	}
}

func TestShutdown(t *testing.T) {
	got := dispatch(&request{Op: "shutdown"})
	if got["ok"] != true {
		t.Fatalf("expected ok=true, got %v", got)
	}
}

func TestUnknownOp(t *testing.T) {
	got := dispatch(&request{Op: "frobnicate"})
	if got["error"] == nil {
		t.Fatalf("expected error response, got %v", got)
	}
}

func TestSetupBFV(t *testing.T) {
	resetState()
	resp := dispatch(&request{
		Op:     "setup",
		Scheme: "BFV",
		Params: map[string]any{"poly_degree": 4096, "plaintext_modulus": 65537},
	})
	if errVal, ok := resp["error"]; ok {
		t.Fatalf("setup returned error: %v", errVal)
	}
	if resp["context_id"] == nil {
		t.Fatalf("expected context_id, got %v", resp)
	}
	if resp["poly_degree"].(int) != 4096 {
		t.Fatalf("expected poly_degree=4096, got %v", resp["poly_degree"])
	}
	if resp["plaintext_modulus"] != "65537" {
		t.Fatalf("expected plaintext_modulus=\"65537\", got %v", resp["plaintext_modulus"])
	}
	delta, err := strconv.ParseUint(resp["delta"].(string), 10, 64)
	if err == nil && delta == 0 {
		t.Fatalf("expected non-zero delta, got %v", resp["delta"])
	}
}

func TestSetupBGV(t *testing.T) {
	resetState()
	resp := dispatch(&request{
		Op:     "setup",
		Scheme: "BGV",
		Params: map[string]any{"poly_degree": 4096, "plaintext_modulus": 65537},
	})
	if errVal, ok := resp["error"]; ok {
		t.Fatalf("setup returned error: %v", errVal)
	}
	if resp["scheme"] != "BGV" {
		t.Fatalf("expected scheme=BGV, got %v", resp["scheme"])
	}
}

func TestSetupRejectsUnsupportedScheme(t *testing.T) {
	resetState()
	resp := dispatch(&request{Op: "setup", Scheme: "CKKS"})
	if resp["error"] == nil {
		t.Fatalf("expected error for unsupported scheme, got %v", resp)
	}
}

func TestSetupRejectsNonPowerOfTwoPolyDegree(t *testing.T) {
	resetState()
	resp := dispatch(&request{
		Op:     "setup",
		Scheme: "BFV",
		Params: map[string]any{"poly_degree": 6000, "plaintext_modulus": 65537},
	})
	if resp["error"] == nil {
		t.Fatalf("expected error for poly_degree=6000, got %v", resp)
	}
}

func TestEncryptDecryptZeroRoundTrip(t *testing.T) {
	resetState()
	setup := dispatch(&request{
		Op:     "setup",
		Scheme: "BFV",
		Params: map[string]any{"poly_degree": 4096, "plaintext_modulus": 65537},
	})
	ctxID := setup["context_id"].(string)

	enc := dispatch(&request{
		Op:        "encrypt",
		ContextID: ctxID,
		Values:    []int64{0},
	})
	if errVal, ok := enc["error"]; ok {
		t.Fatalf("encrypt returned error: %v", errVal)
	}
	ctID := enc["ciphertext_id"].(string)

	dec := dispatch(&request{
		Op:           "decrypt",
		ContextID:    ctxID,
		CiphertextID: ctID,
	})
	values, ok := dec["values"].([]int64)
	if !ok {
		t.Fatalf("expected values []int64, got %T (%v)", dec["values"], dec["values"])
	}
	if values[0] != 0 {
		t.Fatalf("expected first slot=0, got %d", values[0])
	}
}

func TestEncryptDecryptIntegerRoundTrip(t *testing.T) {
	resetState()
	setup := dispatch(&request{
		Op:     "setup",
		Scheme: "BFV",
		Params: map[string]any{"poly_degree": 4096, "plaintext_modulus": 65537},
	})
	ctxID := setup["context_id"].(string)

	values := []int64{1, 2, 3, 4, 5, 6, 7, 8}
	enc := dispatch(&request{Op: "encrypt", ContextID: ctxID, Values: values})
	ctID := enc["ciphertext_id"].(string)
	dec := dispatch(&request{Op: "decrypt", ContextID: ctxID, CiphertextID: ctID})
	got := dec["values"].([]int64)
	for i, want := range values {
		if got[i] != want {
			t.Fatalf("slot %d: want %d, got %d", i, want, got[i])
		}
	}
}

func TestPerturbConstantSmallOffset(t *testing.T) {
	resetState()
	setup := dispatch(&request{
		Op:     "setup",
		Scheme: "BFV",
		Params: map[string]any{"poly_degree": 4096, "plaintext_modulus": 65537},
	})
	ctxID := setup["context_id"].(string)

	enc := dispatch(&request{Op: "encrypt", ContextID: ctxID, Values: []int64{0}})
	ctID := enc["ciphertext_id"].(string)

	// Small offset (1 << delta) should be absorbed by BFV rounding -> still decrypts to 0.
	pert := dispatch(&request{
		Op:           "perturb_constant",
		ContextID:    ctxID,
		CiphertextID: ctID,
		Offset:       float64(1),
	})
	if errVal, ok := pert["error"]; ok {
		t.Fatalf("perturb returned error: %v", errVal)
	}
	pertID := pert["ciphertext_id"].(string)

	dec := dispatch(&request{Op: "decrypt", ContextID: ctxID, CiphertextID: pertID})
	values := dec["values"].([]int64)
	if values[0] != 0 {
		t.Fatalf("expected slot 0 after small perturb to remain 0, got %d", values[0])
	}
}

func TestPerturbConstantBigIntStringOffset(t *testing.T) {
	resetState()
	setup := dispatch(&request{
		Op:     "setup",
		Scheme: "BFV",
		Params: map[string]any{"poly_degree": 4096, "plaintext_modulus": 65537},
	})
	ctxID := setup["context_id"].(string)
	delta := setup["delta"].(string)

	enc := dispatch(&request{Op: "encrypt", ContextID: ctxID, Values: []int64{0}})
	ctID := enc["ciphertext_id"].(string)

	// delta exceeds int64 for production-bit-size Q; pass it as a
	// decimal string. The helper parses via big.Int + per-tower mod.
	pert := dispatch(&request{
		Op:           "perturb_constant",
		ContextID:    ctxID,
		CiphertextID: ctID,
		Offset:       delta,
	})
	if errVal, ok := pert["error"]; ok {
		t.Fatalf("perturb returned error: %v", errVal)
	}
	if pert["ciphertext_id"] == nil {
		t.Fatalf("expected ciphertext_id, got %v", pert)
	}
}

func TestPerturbConstantRejectsFractionalOffset(t *testing.T) {
	resetState()
	setup := dispatch(&request{
		Op:     "setup",
		Scheme: "BFV",
		Params: map[string]any{"poly_degree": 4096, "plaintext_modulus": 65537},
	})
	ctxID := setup["context_id"].(string)
	enc := dispatch(&request{Op: "encrypt", ContextID: ctxID, Values: []int64{0}})
	ctID := enc["ciphertext_id"].(string)

	resp := dispatch(&request{
		Op:           "perturb_constant",
		ContextID:    ctxID,
		CiphertextID: ctID,
		Offset:       float64(1.5),
	})
	if resp["error"] == nil {
		t.Fatalf("expected error for fractional offset, got %v", resp)
	}
}

func TestPerturbConstantRejectsInvalidString(t *testing.T) {
	resetState()
	setup := dispatch(&request{
		Op:     "setup",
		Scheme: "BFV",
		Params: map[string]any{"poly_degree": 4096, "plaintext_modulus": 65537},
	})
	ctxID := setup["context_id"].(string)
	enc := dispatch(&request{Op: "encrypt", ContextID: ctxID, Values: []int64{0}})
	ctID := enc["ciphertext_id"].(string)

	resp := dispatch(&request{
		Op:           "perturb_constant",
		ContextID:    ctxID,
		CiphertextID: ctID,
		Offset:       "not-a-number",
	})
	if resp["error"] == nil {
		t.Fatalf("expected error for non-numeric string, got %v", resp)
	}
}

func TestPlaintextDelta(t *testing.T) {
	resetState()
	setup := dispatch(&request{
		Op:     "setup",
		Scheme: "BFV",
		Params: map[string]any{"poly_degree": 4096, "plaintext_modulus": 65537},
	})
	ctxID := setup["context_id"].(string)
	enc := dispatch(&request{Op: "encrypt", ContextID: ctxID, Values: []int64{0}})
	ctID := enc["ciphertext_id"].(string)

	resp := dispatch(&request{Op: "plaintext_delta", ContextID: ctxID, CiphertextID: ctID})
	if resp["delta"] != setup["delta"] {
		t.Fatalf("plaintext_delta=%v != setup.delta=%v", resp["delta"], setup["delta"])
	}
}

func TestUnknownContextID(t *testing.T) {
	resetState()
	resp := dispatch(&request{Op: "encrypt", ContextID: "missing"})
	if resp["error"] == nil {
		t.Fatalf("expected error for missing context, got %v", resp)
	}
}

func TestUnknownCiphertextID(t *testing.T) {
	resetState()
	setup := dispatch(&request{
		Op:     "setup",
		Scheme: "BFV",
		Params: map[string]any{"poly_degree": 4096, "plaintext_modulus": 65537},
	})
	ctxID := setup["context_id"].(string)
	resp := dispatch(&request{Op: "decrypt", ContextID: ctxID, CiphertextID: "missing"})
	if resp["error"] == nil {
		t.Fatalf("expected error for missing ciphertext, got %v", resp)
	}
}

func TestSetupFloodingActive(t *testing.T) {
	resetState()
	resp := dispatch(&request{
		Op:     "setup",
		Scheme: "BFV",
		Params: map[string]any{
			"poly_degree":          4096,
			"plaintext_modulus":    65537,
			"noise_flooding_sigma": "1000000000",
		},
	})
	if errVal, ok := resp["error"]; ok {
		t.Fatalf("setup returned error: %v", errVal)
	}
	if resp["noise_flooding_active"] != true {
		t.Fatalf("expected noise_flooding_active=true, got %v", resp["noise_flooding_active"])
	}
	if resp["noise_flooding_sigma"] != "1000000000" {
		t.Fatalf("expected sigma echoed back, got %v", resp["noise_flooding_sigma"])
	}
}

func TestSetupRejectsNegativeSigma(t *testing.T) {
	resetState()
	resp := dispatch(&request{
		Op:     "setup",
		Scheme: "BFV",
		Params: map[string]any{
			"poly_degree":          4096,
			"plaintext_modulus":    65537,
			"noise_flooding_sigma": "-10",
		},
	})
	if resp["error"] == nil {
		t.Fatalf("expected error for negative sigma, got %v", resp)
	}
}

func TestFloodingDecryptVariesAcrossSeeds(t *testing.T) {
	resetState()
	// Probe setup once to get delta (helper-computed floor(Q/t)),
	// then re-setup with sigma = delta/2 so flooding noise actually
	// changes the decoded slot across seeds. Hard-coded sigma values
	// would either be smaller than the rounding window (no observable
	// effect) or wider than Q (degenerate).
	probe := dispatch(&request{
		Op:     "setup",
		Scheme: "BFV",
		Params: map[string]any{"poly_degree": 4096, "plaintext_modulus": 65537},
	})
	deltaStr := probe["delta"].(string)
	delta, _ := new(big.Int).SetString(deltaStr, 10)
	sigma := new(big.Int).Quo(delta, big.NewInt(2))

	resetState()
	setup := dispatch(&request{
		Op:     "setup",
		Scheme: "BFV",
		Params: map[string]any{
			"poly_degree":          4096,
			"plaintext_modulus":    65537,
			"noise_flooding_sigma": sigma.String(),
		},
	})
	ctxID := setup["context_id"].(string)
	enc := dispatch(&request{Op: "encrypt", ContextID: ctxID, Values: []int64{0}})
	ctID := enc["ciphertext_id"].(string)

	dispatch(&request{Op: "set_seed", ContextID: ctxID, Seed: 1})
	a := dispatch(&request{Op: "decrypt", ContextID: ctxID, CiphertextID: ctID})
	dispatch(&request{Op: "set_seed", ContextID: ctxID, Seed: 999999})
	b := dispatch(&request{Op: "decrypt", ContextID: ctxID, CiphertextID: ctID})

	av := a["values"].([]int64)
	bv := b["values"].([]int64)
	same := true
	for i := range av {
		if av[i] != bv[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatalf("flooding decrypt produced identical output for distinct seeds; expected variance")
	}
}

func TestSetSeedRequiresKnownContext(t *testing.T) {
	resetState()
	resp := dispatch(&request{Op: "set_seed", ContextID: "missing", Seed: 42})
	if resp["error"] == nil {
		t.Fatalf("expected error for missing context, got %v", resp)
	}
}

func TestPerturbComponentOutOfRange(t *testing.T) {
	resetState()
	setup := dispatch(&request{
		Op:     "setup",
		Scheme: "BFV",
		Params: map[string]any{"poly_degree": 4096, "plaintext_modulus": 65537},
	})
	ctxID := setup["context_id"].(string)
	enc := dispatch(&request{Op: "encrypt", ContextID: ctxID, Values: []int64{0}})
	ctID := enc["ciphertext_id"].(string)

	resp := dispatch(&request{
		Op:           "perturb_constant",
		ContextID:    ctxID,
		CiphertextID: ctID,
		Component:    99,
	})
	if resp["error"] == nil {
		t.Fatalf("expected error for component=99, got %v", resp)
	}
}

