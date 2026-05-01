# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""End-to-end Cheon-Hong-Kim 2024/127 replay against the lattigo adapter.

These tests exercise the full attack path against real Lattigo BFV/BGV
through the Go helper binary (``fhe-replay-lattigo-helper``). Skipped
when the helper is not on PATH — the helper is built from
``vendor/lattigo-helper/`` or installed via release binaries.
"""

from __future__ import annotations

import shutil

import pytest

from fhe_attack_replay import run
from fhe_attack_replay.attacks.base import AttackStatus

_HELPER_AVAILABLE = shutil.which("fhe-replay-lattigo-helper") is not None
pytestmark = pytest.mark.skipif(
    not _HELPER_AVAILABLE,
    reason="fhe-replay-lattigo-helper not on PATH",
)


def test_replay_vulnerable_against_unmitigated_lattigo_bfv():
    report = run(
        library="lattigo",
        params={
            "scheme": "BFV",
            "poly_degree": 4096,
            "plaintext_modulus": 65537,
            "replay_trials": 2,
            "bisect_rounds": 8,
        },
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    assert r.evidence["mode"] == "replay"
    assert r.evidence["intent_actual"] == "replay"
    assert r.evidence["test"] == "polynomial_domain_bisection"
    assert r.evidence["library_class"] == "production"
    assert r.evidence["serialization_backend"] == "lattigo-bgv"
    assert r.evidence["deterministic_oracle"] is True
    assert r.status is AttackStatus.VULNERABLE


def test_replay_vulnerable_against_unmitigated_lattigo_bgv():
    report = run(
        library="lattigo",
        params={
            "scheme": "BGV",
            "poly_degree": 4096,
            "plaintext_modulus": 65537,
            "replay_trials": 2,
            "bisect_rounds": 8,
        },
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    assert r.evidence["mode"] == "replay"
    assert r.evidence["serialization_backend"] == "lattigo-bgv"
    assert r.status is AttackStatus.VULNERABLE


def test_mitigated_lattigo_drives_software_flooding_safe_via_replay():
    # Helper protocol v0.3 supports software noise-flooding: setup
    # accepts `noise_flooding_sigma` and decrypt samples a fresh
    # Gaussian offset added per-tower to c0 in eval form. Mitigated
    # configs (recognized `noise_flooding` label) get sigma = delta/4
    # auto-derived by the adapter, and Cheon's per-trial reseed makes
    # bisection see across-trial variance → real SAFE via Replay.
    report = run(
        library="lattigo",
        params={
            "scheme": "BFV",
            "poly_degree": 4096,
            "plaintext_modulus": 65537,
            "adversary_model": "ind-cpa-d",
            "noise_flooding": "lattigo-noise-flooding",
            "replay_trials": 3,
            "bisect_rounds": 16,
            "replay_seed": 7,
        },
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    assert r.evidence["mode"] == "replay"
    assert r.evidence["intent_actual"] == "replay"
    assert r.evidence["software_flooding_active"] is True
    assert r.evidence["software_flooding_sigma"] > 0
    assert r.evidence["deterministic_oracle"] is False
    assert r.status is AttackStatus.SAFE


def test_explicit_noise_flooding_sigma_routes_through_helper():
    # User can set sigma directly. The helper echoes it back through
    # `software_flooding_sigma` and decrypt-time flooding takes effect;
    # Cheon dispatch reaches Replay regardless of the label-based
    # mitigation routing. (We don't pin SAFE/VULNERABLE here because
    # the boundary-vs-threshold relationship depends on bisection
    # depth × sigma in a non-trivial way; the auto-derived mitigation
    # path in test_mitigated_lattigo_drives_software_flooding_safe_via_replay
    # is the SAFE-verdict gate.)
    report = run(
        library="lattigo",
        params={
            "scheme": "BFV",
            "poly_degree": 4096,
            "plaintext_modulus": 65537,
            "noise_flooding_sigma": str(int(2e58)),  # comparable to delta/4
            "replay_trials": 2,
            "bisect_rounds": 8,
            "replay_seed": 11,
        },
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    assert r.evidence["mode"] == "replay"
    assert r.evidence["software_flooding_active"] is True
    assert r.evidence["software_flooding_sigma"] == int(2e58)


def test_replay_evidence_carries_lattigo_polynomial_metadata():
    report = run(
        library="lattigo",
        params={
            "scheme": "BFV",
            "poly_degree": 4096,
            "plaintext_modulus": 65537,
            "replay_trials": 2,
            "bisect_rounds": 8,
        },
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    assert r.evidence["polynomial_domain"] == "RNS evaluation form (NTT)"
    assert r.evidence["plaintext_modulus"] == 65537
    assert r.evidence["dcrt_tower_count"] >= 1
    assert isinstance(r.evidence["dcrt_moduli_bits"], list)
    assert r.evidence["ciphertext_modulus_bits"] > 0
