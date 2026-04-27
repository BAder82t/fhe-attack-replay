# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

import pytest

from fhe_attack_replay import run
from fhe_attack_replay.attacks.base import AttackIntent, AttackStatus


@pytest.mark.parametrize(
    "params",
    [
        {"scheme": "BFV", "adversary_model": "ind-cpa-d", "noise_flooding": "none"},
        {"scheme": "BFV", "decryption_oracle": True, "noise_flooding": "none"},
        {"scheme": "BGV", "adversary_model": "threshold"},
        {"scheme": "BFV", "adversary_model": "multi-party"},
        {"scheme": "BFV", "adversary_model": "IND-CPA-D"},  # casing
    ],
)
def test_cheon_vulnerable_when_oracle_and_no_mitigation(params):
    report = run(library="openfhe", params=params, attacks=["cheon-2024-127"])
    r = report.results[0]
    assert r.status is AttackStatus.VULNERABLE
    assert r.intent is AttackIntent.RISK_CHECK
    assert r.evidence["decryption_oracle"] is True
    assert r.evidence["mitigation_recognized"] is False


@pytest.mark.parametrize(
    "noise_flooding",
    [
        "openfhe-NOISE_FLOODING_DECRYPT",
        "openfhe-noise_flooding_decrypt",
        "eprint-2024-424",
        "modulus-switching-2025-1627",
        "hint-lwe-2025-1618",
        "noise-flooding",
    ],
)
def test_cheon_safe_when_recognized_mitigation(noise_flooding):
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "adversary_model": "ind-cpa-d",
            "noise_flooding": noise_flooding,
        },
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.SAFE
    assert r.evidence["mitigation_recognized"] is True


@pytest.mark.parametrize(
    "params",
    [
        {"scheme": "BFV"},  # no adversary_model, no oracle => threat model n/a
        {"scheme": "BFV", "adversary_model": "ind-cpa"},
        {"scheme": "BFV", "decryption_oracle": False, "adversary_model": "ind-cpa-d"},
    ],
)
def test_cheon_skipped_when_no_oracle_exposure(params):
    report = run(library="openfhe", params=params, attacks=["cheon-2024-127"])
    r = report.results[0]
    assert r.status is AttackStatus.SKIPPED
    assert r.evidence["decryption_oracle"] is False


def test_cheon_does_not_apply_to_ckks():
    # Cheon 2024/127 targets exact schemes. CKKS is approximate => SKIPPED via
    # applies_to_schemes (handled by the runner before the attack runs).
    report = run(
        library="openfhe",
        params={"scheme": "CKKS", "adversary_model": "ind-cpa-d"},
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.SKIPPED


def test_cheon_overall_status_is_vulnerable_for_vulnerable_config():
    report = run(
        library="openfhe",
        params={"scheme": "BFV", "decryption_oracle": True, "noise_flooding": "none"},
        attacks=["cheon-2024-127"],
    )
    assert report.overall_status is AttackStatus.VULNERABLE
    assert report.coverage.vulnerable == 1
    assert report.coverage.implemented == 1
