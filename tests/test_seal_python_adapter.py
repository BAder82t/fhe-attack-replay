# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Native-path tests for the seal-python adapter.

This adapter exists alongside the TenSEAL ``SEALAdapter`` because
seal-python (the thin pybind11 wrapper) exposes the SEAL ``Evaluator``
methods that TenSEAL hides — including ``transform_to_ntt_inplace``.
The eprint-2025-867 live distinguisher uses that primitive to time
NTT calls in isolation from the rest of the decrypt pipeline.

Tests skip cleanly when ``seal-python`` is not importable so the rest
of the suite still runs in environments without it.
"""

from __future__ import annotations

import pytest

from fhe_attack_replay import run
from fhe_attack_replay.adapters.base import AdapterContext
from fhe_attack_replay.adapters.seal_python import SealPythonAdapter
from fhe_attack_replay.attacks.base import AttackStatus

seal = pytest.importorskip("seal")


@pytest.fixture()
def adapter() -> SealPythonAdapter:
    return SealPythonAdapter()


# ---------------------------------------------------------------------------
# Adapter availability + setup
# ---------------------------------------------------------------------------


def test_is_available_when_seal_python_installed(adapter):
    assert adapter.is_available() is True


def test_bfv_setup_encrypt_decrypt_roundtrip(adapter):
    ctx = adapter.setup("BFV", {"poly_modulus_degree": 8192, "plaintext_modulus": 1032193})
    ct = adapter.encrypt(ctx, [1, 2, 3, 4])
    pt = adapter.decrypt(ctx, ct)
    assert pt[:4] == [1, 2, 3, 4]


def test_bgv_setup_encrypt_decrypt_roundtrip(adapter):
    ctx = adapter.setup("BGV", {"poly_modulus_degree": 8192, "plaintext_modulus": 1032193})
    ct = adapter.encrypt(ctx, [5, 6, 7, 8])
    pt = adapter.decrypt(ctx, ct)
    assert pt[:4] == [5, 6, 7, 8]


def test_ckks_setup_encrypt_decrypt_roundtrip(adapter):
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


def test_unsupported_scheme_raises_not_implemented(adapter):
    # NotImplementedError lets the runner's ``_setup_or_synthetic`` fall
    # back to a synthetic context for risk-check-only attacks.
    with pytest.raises(NotImplementedError, match="does not support scheme"):
        adapter.setup("TFHE", {})


# ---------------------------------------------------------------------------
# Per-NTT primitive
# ---------------------------------------------------------------------------


def test_transform_to_ntt_returns_ntt_form_ciphertext(adapter):
    ctx = adapter.setup("BFV", {})
    ct = adapter.encrypt(ctx, [1, 2, 3, 4])
    transformed = adapter.transform_to_ntt(ctx, ct)
    # is_ntt_form on seal-python is a method, not a property.
    assert transformed.is_ntt_form() is True


def test_transform_to_ntt_does_not_mutate_original(adapter):
    ctx = adapter.setup("BFV", {})
    ct = adapter.encrypt(ctx, [1, 2, 3, 4])
    _ = adapter.transform_to_ntt(ctx, ct)
    # Original ciphertext stays in plain (non-NTT) form so the caller
    # can re-time the same input.
    assert ct.is_ntt_form() is False


# ---------------------------------------------------------------------------
# Fingerprint exposure
# ---------------------------------------------------------------------------


def test_evaluator_fingerprint_advertises_per_ntt_timing(adapter):
    ctx = adapter.setup("BFV", {"poly_modulus_degree": 8192})
    fp = adapter.evaluator_fingerprint(ctx)
    assert fp["implementation"] == "microsoft/SEAL via seal-python"
    assert fp["ntt_variant"] == "harvey-butterfly"
    assert fp["constant_time_decrypt"] is False
    assert fp["ring_dimension"] == 8192
    assert fp["scheme"] == "BFV"
    # The per-NTT capability flag drives eprint-2025-867's branch
    # selection.
    assert fp["exposes_per_ntt_timing"] is True


def test_evaluator_fingerprint_handles_synthetic_context(adapter):
    synthetic = AdapterContext(library="seal-python", scheme="BFV", params={}, handles={})
    fp = adapter.evaluator_fingerprint(synthetic)
    assert fp["ring_dimension"] is None
    assert fp["exposes_per_ntt_timing"] is True


def test_evaluator_fingerprint_constant_time_override(adapter):
    ctx = adapter.setup("BFV", {"constant_time_decrypt": True})
    fp = adapter.evaluator_fingerprint(ctx)
    assert fp["constant_time_decrypt"] is True


# ---------------------------------------------------------------------------
# eprint-2025-867 prefers the per-NTT primitive when present
# ---------------------------------------------------------------------------


def test_eprint_2025_867_uses_per_ntt_timing_against_seal_python():
    report = run(
        library="seal-python",
        params={
            "scheme": "BFV",
            "constant_time_decrypt": False,
            "replay_timing_repeats": 16,
        },
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    # The new test_label / measured_op fields prove the per-NTT branch
    # ran instead of the whole-decrypt fallback.
    assert r.evidence["mode"] == "replay"
    assert r.evidence["test"] == "transform_to_ntt_timing_distinguisher"
    assert r.evidence["measured_op"] == "Evaluator.transform_to_ntt_inplace"
    assert r.evidence["ntt_capable"] is True
    # Status is timing-noise dependent on shared CI; just assert the
    # evidence shape and that a verdict was rendered.
    assert r.status in (AttackStatus.SAFE, AttackStatus.VULNERABLE)


def test_eprint_2025_867_seal_python_constant_time_short_circuits_to_safe():
    report = run(
        library="seal-python",
        params={"scheme": "BFV", "constant_time_decrypt": True},
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.SAFE
    assert r.evidence["mode"] == "risk_check"


# ---------------------------------------------------------------------------
# Registry integration
# ---------------------------------------------------------------------------


def test_seal_python_appears_in_registry_listing():
    from fhe_attack_replay.registry import list_adapters
    assert "seal-python" in list_adapters()


def test_seal_python_unavailable_branch(monkeypatch):
    # Force the import-helper to return None so we exercise the missing-
    # native fallback path.
    monkeypatch.setattr(
        "fhe_attack_replay.adapters.seal_python.importlib.import_module",
        lambda *_a, **_k: (_ for _ in ()).throw(ImportError("not installed")),
    )
    a = SealPythonAdapter()
    assert a.is_available() is False
    with pytest.raises(RuntimeError, match="not importable"):
        a.setup("BFV", {})


def test_seal_python_try_import_swallows_oserror(monkeypatch):
    from fhe_attack_replay.adapters import seal_python

    def raise_os(*_a, **_k):
        raise OSError("dlopen failure")

    monkeypatch.setattr(seal_python.importlib, "import_module", raise_os)
    assert seal_python._try_import_seal() is None


def test_read_poly_modulus_degree_swallows_attribute_error():
    class _Stub:
        def first_context_data(self):
            raise AttributeError("no method")

    assert SealPythonAdapter._read_poly_modulus_degree(_Stub()) is None


def test_read_poly_modulus_degree_returns_none_for_none_ctx():
    assert SealPythonAdapter._read_poly_modulus_degree(None) is None
