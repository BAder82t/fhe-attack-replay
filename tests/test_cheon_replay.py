# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""End-to-end Cheon-Hong-Kim 2024/127 replay against the toy-lwe adapter.

These tests exercise the full attack path — keygen, encrypt(0),
decryption-oracle bisection over multiple trials — and assert that the
unmitigated configuration is recovered as VULNERABLE while the
noise-flooded configuration is SAFE. They are the strongest signal in the
test suite that the harness produces real verdicts on a real cryptographic
target, even if the target is a toy.
"""

from __future__ import annotations

from fhe_attack_replay import run
from fhe_attack_replay.attacks.base import AttackIntent, AttackStatus


def test_replay_vulnerable_against_unmitigated_toy_lwe():
    report = run(
        library="toy-lwe",
        params={
            "scheme": "LWE",
            "n": 16,
            "q": 1 << 20,
            "t": 16,
            "sigma": 3.2,
            "noise_flooding_sigma": 0.0,
            "seed": 1,
        },
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    # Class-declared intent stays RISK_CHECK; replay-mode is flagged in evidence.
    assert r.intent is AttackIntent.RISK_CHECK
    assert r.evidence["mode"] == "replay"
    assert r.evidence["intent_actual"] == "replay"
    assert r.evidence["deterministic_oracle"] is True
    assert r.status is AttackStatus.VULNERABLE


def test_replay_safe_against_noise_flooded_toy_lwe():
    # noise_flooding_sigma comparable to delta/4 randomizes the oracle enough
    # to break the bisection-recovery primitive.
    report = run(
        library="toy-lwe",
        params={
            "scheme": "LWE",
            "n": 16,
            "q": 1 << 20,
            "t": 16,
            "sigma": 3.2,
            "noise_flooding_sigma": float(1 << 14),  # ~ delta/4 with q=2**20, t=16
            "seed": 1,
        },
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    assert r.evidence["mode"] == "replay"
    assert r.evidence["deterministic_oracle"] is False
    assert r.status is AttackStatus.SAFE


def test_replay_evidence_carries_boundaries_sample():
    report = run(
        library="toy-lwe",
        params={"scheme": "LWE", "seed": 7},
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    assert "boundaries_sample" in r.evidence
    assert isinstance(r.evidence["boundaries_sample"], list)
    assert len(r.evidence["boundaries_sample"]) == r.evidence["trials"]


def test_replay_overall_status_vulnerable_drives_exit_code():
    report = run(
        library="toy-lwe",
        params={"scheme": "LWE", "noise_flooding_sigma": 0.0, "seed": 1},
        attacks=["cheon-2024-127"],
    )
    assert report.overall_status is AttackStatus.VULNERABLE
    assert report.coverage.vulnerable == 1
    assert report.coverage.implemented == 1


def test_risk_check_path_still_works_for_non_replay_adapters():
    # OpenFHE is registered but the native build is unavailable on macOS arm64
    # CI; the adapter falls back to a synthetic context, which means the
    # Replay path's `is_available` check returns False and the dispatcher
    # selects the RiskCheck path.
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "adversary_model": "ind-cpa-d",
            "noise_flooding": "openfhe-NOISE_FLOODING_DECRYPT",
        },
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    assert r.evidence["mode"] in {"replay", "risk_check"}
    # On a CI host without OpenFHE built, mode should be risk_check.
    if r.evidence["mode"] == "risk_check":
        assert r.status is AttackStatus.SAFE
        assert r.evidence["mitigation_recognized"] is True
