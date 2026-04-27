# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Native-path tests for the SEAL adapter (TenSEAL backend).

Skips automatically when ``tenseal`` is not importable so the adapter's
fallback-to-synthetic behavior remains exercised by the runner tests.
"""

from __future__ import annotations

import pytest

from fhe_attack_replay import run
from fhe_attack_replay.adapters.seal import SEALAdapter
from fhe_attack_replay.attacks.base import AttackStatus

tenseal = pytest.importorskip("tenseal")


@pytest.fixture()
def adapter() -> SEALAdapter:
    return SEALAdapter()


def test_is_available_when_tenseal_installed(adapter: SEALAdapter):
    assert adapter.is_available() is True


def test_bfv_setup_encrypt_decrypt_roundtrip(adapter: SEALAdapter):
    ctx = adapter.setup("BFV", {"poly_modulus_degree": 8192, "plaintext_modulus": 1032193})
    ct = adapter.encrypt(ctx, [1, 2, 3, 4])
    pt = adapter.decrypt(ctx, ct)
    assert pt[:4] == [1, 2, 3, 4]


def test_ckks_setup_encrypt_decrypt_roundtrip(adapter: SEALAdapter):
    ctx = adapter.setup(
        "CKKS",
        {
            "poly_modulus_degree": 8192,
            "coeff_mod_bit_sizes": [60, 40, 40, 60],
            "scale_bits": 40,
        },
    )
    ct = adapter.encrypt(ctx, [1.0, 2.5, -3.25])
    pt = adapter.decrypt(ctx, ct)
    assert len(pt) >= 3
    for got, want in zip(pt[:3], [1.0, 2.5, -3.25], strict=True):
        assert abs(got - want) < 1e-2


def test_unsupported_scheme_raises_not_implemented(adapter: SEALAdapter):
    # NotImplementedError lets the runner fall back to a synthetic context
    # rather than aborting — see SEALAdapter.setup for rationale.
    with pytest.raises(NotImplementedError, match="does not support scheme"):
        adapter.setup("BGV", {})


def test_evaluator_fingerprint_carries_ring_dimension(adapter: SEALAdapter):
    ctx = adapter.setup("BFV", {"poly_modulus_degree": 8192})
    fp = adapter.evaluator_fingerprint(ctx)
    assert fp["implementation"] == "microsoft/SEAL via tenseal"
    assert fp["ntt_variant"] == "harvey-butterfly"
    assert fp["constant_time_decrypt"] is False
    assert fp["ring_dimension"] == 8192
    assert fp["scheme"] == "BFV"


def test_evaluator_fingerprint_handles_synthetic_context(adapter: SEALAdapter):
    # When setup was skipped (synthetic context), ring_dimension is None but
    # the rest of the fingerprint still surfaces — keeps the eprint risk-check
    # path working without TenSEAL.
    from fhe_attack_replay.adapters.base import AdapterContext

    synthetic = AdapterContext(library="seal", scheme="CKKS", params={}, handles={})
    fp = adapter.evaluator_fingerprint(synthetic)
    assert fp["ring_dimension"] is None
    assert fp["ntt_variant"] == "harvey-butterfly"


def test_run_against_real_seal_marks_eprint_vulnerable():
    # Full runner integration: real TenSEAL setup, real fingerprint, real verdict.
    report = run(library="seal", params={"scheme": "CKKS"}, attacks=["eprint-2025-867"])
    assert report.results[0].status is AttackStatus.VULNERABLE
    fp = report.results[0].evidence["evaluator_fingerprint"]
    assert fp["ring_dimension"] == 8192


def test_run_against_real_seal_with_constant_time_override_marks_safe():
    report = run(
        library="seal",
        params={"scheme": "CKKS", "constant_time_decrypt": True},
        attacks=["eprint-2025-867"],
    )
    assert report.results[0].status is AttackStatus.SAFE
