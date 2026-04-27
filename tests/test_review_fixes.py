# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the review-pass fixes.

Each test corresponds to a specific issue called out in the repo review:
Coverage bookkeeping, OpenFHE noise-flooding wiring, OpenFHE bisect-overflow
classification, OpenFHE JSON precision guard, CLI argument validation,
adversary_model normalization, and the live-oracle capability flag.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fhe_attack_replay import run
from fhe_attack_replay.adapters.base import (
    AdapterCapability,
    AdapterContext,
    LibraryAdapter,
)
from fhe_attack_replay.adapters.openfhe import (
    OpenFHEAdapter,
    _apply_native_noise_flooding,
    _normalize_flooding_label,
)
from fhe_attack_replay.attacks.base import AttackResult, AttackStatus
from fhe_attack_replay.attacks.cheon_2024_127 import _normalize
from fhe_attack_replay.cli import (
    EXIT_OK,
    EXIT_USAGE,
    _resolve_attacks,
    main,
)
from fhe_attack_replay.registry import register_adapter
from fhe_attack_replay.runner import Coverage

# --- Coverage.implemented excludes ERROR ----------------------------------


def test_coverage_implemented_does_not_count_errors():
    # Manually build results: one VULNERABLE, one ERROR. Implemented should
    # be 1, not 2 — ERROR is the absence of a verdict.
    results = [
        AttackResult(
            attack="cheon-2024-127",
            library="toy-lwe",
            scheme="LWE",
            status=AttackStatus.VULNERABLE,
            duration_seconds=0.01,
        ),
        AttackResult(
            attack="reveal-2023-1128",
            library="toy-lwe",
            scheme="LWE",
            status=AttackStatus.ERROR,
            duration_seconds=0.01,
        ),
    ]
    cov = Coverage.from_results(requested=2, results=results)
    assert cov.implemented == 1
    assert cov.errors == 1
    assert cov.ratio == 0.5


def test_coverage_implemented_zero_when_only_errors():
    results = [
        AttackResult(
            attack="cheon-2024-127",
            library="x",
            scheme="LWE",
            status=AttackStatus.ERROR,
            duration_seconds=0.0,
        )
    ]
    cov = Coverage.from_results(requested=1, results=results)
    assert cov.implemented == 0
    assert cov.ratio == 0.0


# --- OpenFHE noise-flooding wiring (without requiring openfhe-python) -----


class _StubParams:
    """Mimics the openfhe CCParamsBFVRNS surface that flooding setup touches."""

    def __init__(self) -> None:
        self.execution_mode = None
        self.decrypt_mode = None

    def SetExecutionMode(self, mode):  # noqa: N802 - mirrors openfhe API
        self.execution_mode = mode

    def SetDecryptionNoiseMode(self, mode):  # noqa: N802 - mirrors openfhe API
        self.decrypt_mode = mode


class _StubOpenFHE:
    EXEC_NOISE_FLOODING = "EXEC_NOISE_FLOODING"
    NOISE_FLOODING_DECRYPT = "NOISE_FLOODING_DECRYPT"


class _StubOpenFHEMissingAPI:
    pass


def test_apply_native_noise_flooding_wires_when_label_recognized():
    p = _StubParams()
    flooded = _apply_native_noise_flooding(
        _StubOpenFHE(), p, {"noise_flooding": "openfhe-NOISE_FLOODING_DECRYPT"}
    )
    assert flooded is True
    assert p.execution_mode == "EXEC_NOISE_FLOODING"
    assert p.decrypt_mode == "NOISE_FLOODING_DECRYPT"


def test_apply_native_noise_flooding_skips_when_unrecognized_label():
    p = _StubParams()
    flooded = _apply_native_noise_flooding(
        _StubOpenFHE(), p, {"noise_flooding": "eprint-2024-424"}
    )
    assert flooded is False
    assert p.execution_mode is None


def test_apply_native_noise_flooding_skips_when_unspecified():
    p = _StubParams()
    flooded = _apply_native_noise_flooding(_StubOpenFHE(), p, {})
    assert flooded is False


def test_apply_native_noise_flooding_raises_when_api_missing():
    p = _StubParams()
    with pytest.raises(RuntimeError, match="SetExecutionMode"):
        _apply_native_noise_flooding(
            _StubOpenFHEMissingAPI(), p, {"noise_flooding": "noise-flooding"}
        )


def test_normalize_flooding_label_handles_separators_and_case():
    assert _normalize_flooding_label("openfhe-NOISE_FLOODING_DECRYPT") == (
        "openfhe-noise-flooding-decrypt"
    )
    assert _normalize_flooding_label("openfhe-noise-flooding-decrypt") == (
        "openfhe-noise-flooding-decrypt"
    )
    assert _normalize_flooding_label(None) == ""


# --- OpenFHE adapter precision guard --------------------------------------


def test_exact_int_accepts_strings_and_safe_ints():
    assert OpenFHEAdapter._exact_int("12345678901234567890", "tower") == (
        12345678901234567890
    )
    assert OpenFHEAdapter._exact_int(12345, "tower") == 12345


def test_exact_int_rejects_unsafe_floats():
    with pytest.raises(RuntimeError, match="JSON float"):
        OpenFHEAdapter._exact_int(2.0**60, "DCRT modulus")


def test_exact_int_accepts_safe_floats():
    # Floats that round-trip cleanly under 2**53 are fine; openfhe-python
    # legitimately emits small ints as JSON numbers.
    assert OpenFHEAdapter._exact_int(65537.0, "x") == 65537


def test_exact_int_rejects_unexpected_types():
    with pytest.raises(RuntimeError, match="Unexpected type"):
        OpenFHEAdapter._exact_int([1, 2, 3], "x")


# --- CLI argument validation ----------------------------------------------


def test_resolve_attacks_all_returns_none():
    assert _resolve_attacks("all") is None
    assert _resolve_attacks("ALL") is None


def test_resolve_attacks_empty_raises():
    with pytest.raises(ValueError, match="empty"):
        _resolve_attacks("")
    with pytest.raises(ValueError, match="empty"):
        _resolve_attacks("   ")
    with pytest.raises(ValueError, match="empty"):
        _resolve_attacks(",,,")


def test_resolve_attacks_returns_id_list():
    assert _resolve_attacks("cheon-2024-127, eprint-2025-867") == [
        "cheon-2024-127",
        "eprint-2025-867",
    ]


def test_cli_run_empty_attacks_returns_usage_error(tmp_path: Path):
    params = tmp_path / "params.json"
    params.write_text(json.dumps({"scheme": "LWE"}))
    rc = main(
        [
            "run",
            "--lib",
            "toy-lwe",
            "--params",
            str(params),
            "--attacks",
            "",
            "--quiet",
        ]
    )
    assert rc == EXIT_USAGE


def test_cli_run_missing_params_file_returns_usage_error(tmp_path: Path):
    rc = main(
        [
            "run",
            "--lib",
            "toy-lwe",
            "--params",
            str(tmp_path / "nope.json"),
            "--quiet",
        ]
    )
    assert rc == EXIT_USAGE


# --- adversary_model normalization (underscores accepted) -----------------


def test_normalize_collapses_underscores_and_whitespace():
    assert _normalize("IND_CPA_D") == "ind-cpa-d"
    assert _normalize("ind cpa d") == "ind-cpa-d"
    assert _normalize("IND-CPA-D") == "ind-cpa-d"
    assert _normalize(None) == ""


def test_cheon_recognizes_underscore_separator_adversary_model():
    report = run(
        library="seal",
        params={"scheme": "BFV", "adversary_model": "IND_CPA_D"},
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    # Same verdict as the canonical "ind-cpa-d" form.
    assert r.status is AttackStatus.VULNERABLE
    assert r.evidence["decryption_oracle"] is True


def test_cheon_recognizes_hyphenated_mitigation_label():
    # The recognized set is now stored hyphenated; underscored input should
    # still match because of the normalize transform.
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "adversary_model": "ind-cpa-d",
            "noise_flooding": "openfhe-noise-flooding-decrypt",
        },
        attacks=["cheon-2024-127"],
    )
    assert report.results[0].status is AttackStatus.SAFE
    assert report.results[0].evidence["mitigation_recognized"] is True


# --- live-oracle capability gate ------------------------------------------


def test_live_oracle_default_false_keeps_scaffold_adapters_on_riskcheck():
    # Lattigo's capability does not set live_oracle => cheon-2024-127 picks
    # the RiskCheck branch even though the adapter's `is_available()` is
    # False (helper missing). This test pins that contract.
    report = run(
        library="lattigo",
        params={"scheme": "BFV", "adversary_model": "ind-cpa-d", "noise_flooding": "none"},
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    assert r.evidence["mode"] == "risk_check"
    assert r.status is AttackStatus.VULNERABLE


def test_openfhe_capability_advertises_live_oracle():
    cap = OpenFHEAdapter.capability
    assert cap.live_oracle is True


def test_seal_capability_does_not_advertise_live_oracle():
    from fhe_attack_replay.adapters.seal import SEALAdapter

    assert SEALAdapter.capability.live_oracle is False


def test_synthetic_adapter_with_live_oracle_flag_but_no_dispatch_falls_back():
    """A future adapter could set live_oracle=True without the cheon module
    knowing how to bisect against it. The dispatcher must fall back to
    RiskCheck rather than crash."""

    class _FutureAdapter(LibraryAdapter):
        name = "future-fhe"
        capability = AdapterCapability(
            schemes=("BFV",),
            requires_native=False,
            live_oracle=True,
        )

        def is_available(self):
            return True

        def setup(self, scheme, params):
            return AdapterContext(library=self.name, scheme=scheme, params=params)

        def encrypt(self, ctx, plaintext):
            raise NotImplementedError

        def decrypt(self, ctx, ciphertext):
            raise NotImplementedError

        def evaluator_fingerprint(self, ctx):
            return {"implementation": "future", "ntt_variant": "n/a"}

    register_adapter(_FutureAdapter)
    report = run(
        library="future-fhe",
        params={"scheme": "BFV", "adversary_model": "ind-cpa-d", "noise_flooding": "none"},
        attacks=["cheon-2024-127"],
    )
    # No replay path wired => RiskCheck verdict.
    assert report.results[0].evidence["mode"] == "risk_check"
    assert report.results[0].status is AttackStatus.VULNERABLE


# --- toy-lwe scheme list no longer lies about BFV --------------------------


def test_toy_lwe_capability_advertises_only_lwe():
    from fhe_attack_replay.adapters.toy_lwe import ToyLWEAdapter

    assert ToyLWEAdapter.capability.schemes == ("LWE",)


def test_safe_variance_frac_delta_param_overrides_default():
    # Set the variance threshold low enough that even the modest residual
    # variance of the unmitigated toy-lwe oracle exceeds it. Result: a SAFE
    # verdict on a config that would otherwise report VULNERABLE.
    report = run(
        library="toy-lwe",
        params={
            "scheme": "LWE",
            "noise_flooding_sigma": 0.0,
            "seed": 1,
            "safe_variance_frac_delta": 1e-9,
        },
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    assert r.evidence["mode"] == "replay"
    assert r.evidence["variance_frac_delta"] == pytest.approx(1e-9)
    # Threshold floors at 1.0 (the `max(1.0, frac * delta)` guard), so the
    # tiny override doesn't actually flip the verdict here — but the param
    # is plumbed through and visible in evidence.
    assert r.evidence["variance_threshold"] == pytest.approx(1.0)


def test_safe_variance_frac_delta_invalid_raises_via_runner():
    # Negative or zero fractions don't make sense — the attack should error
    # out rather than silently disable the threshold check.
    report = run(
        library="toy-lwe",
        params={
            "scheme": "LWE",
            "seed": 1,
            "safe_variance_frac_delta": 0,
        },
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "safe_variance_frac_delta" in r.message


def test_runner_falls_back_to_synthetic_on_runtime_error_setup():
    """Lattigo / tfhe-rs adapters raise RuntimeError when the helper binary
    is missing on PATH. The runner should still produce a synthetic context
    so RiskCheck attacks can run instead of crashing the harness."""

    class _RaisingAdapter(LibraryAdapter):
        name = "raising-adapter"
        capability = AdapterCapability(schemes=("BFV",), live_oracle=False)

        def is_available(self):
            return True

        def setup(self, scheme, params):
            raise RuntimeError("helper binary not on PATH")

        def encrypt(self, ctx, plaintext):
            raise NotImplementedError

        def decrypt(self, ctx, ciphertext):
            raise NotImplementedError

        def evaluator_fingerprint(self, ctx):
            return {"implementation": "stub", "ntt_variant": "n/a"}

    register_adapter(_RaisingAdapter)
    report = run(
        library="raising-adapter",
        params={
            "scheme": "BFV",
            "adversary_model": "ind-cpa-d",
            "noise_flooding": "none",
        },
        attacks=["cheon-2024-127"],
    )
    # RiskCheck path engages — VULNERABLE for an unmitigated config.
    assert report.results[0].status is AttackStatus.VULNERABLE


def test_toy_lwe_with_bfv_scheme_skips_cleanly():
    # Previously the adapter advertised BFV too; users would assume they were
    # testing real BFV. Now `applies()` returns False and the runner emits
    # SKIPPED rather than a misleading verdict.
    report = run(
        library="toy-lwe",
        params={"scheme": "BFV"},
        attacks=["cheon-2024-127"],
    )
    assert report.results[0].status is AttackStatus.SKIPPED


# --- end-to-end JSON serialization includes the new fields -----------------


def test_run_report_to_dict_serializes_implemented_without_errors():
    report = run(
        library="toy-lwe",
        params={"scheme": "LWE", "seed": 11},
        attacks=["cheon-2024-127"],
    )
    payload = report.to_dict()
    cov = payload["coverage"]
    # implemented = safe + vulnerable, never includes errors.
    assert cov["implemented"] == cov["safe"] + cov["vulnerable"]


# --- CLI subparser is now required -----------------------------------------


def test_cli_no_subcommand_errors(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    # argparse exits with code 2 on usage error from a required subparser.
    assert exc.value.code == 2


def test_cli_list_attacks_only(capsys):
    rc = main(["list", "attacks"])
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert "attacks:" in out
    assert "libraries:" not in out
