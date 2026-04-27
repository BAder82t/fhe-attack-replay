# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

import json

from fhe_attack_replay import run
from fhe_attack_replay.attacks.base import AttackStatus


def test_run_against_synthetic_openfhe_target():
    report = run(
        library="openfhe",
        params={"scheme": "BFV", "constant_time_decrypt": False},
        attacks=None,
    )
    assert report.library == "openfhe"
    assert report.scheme == "BFV"
    assert len(report.results) == 5
    statuses = {r.status for r in report.results}
    assert AttackStatus.NOT_IMPLEMENTED in statuses or AttackStatus.SKIPPED in statuses


def test_run_with_subset_of_attacks():
    report = run(
        library="openfhe",
        params={"scheme": "CKKS"},
        attacks=["eprint-2025-867", "guo-qian-usenix24"],
    )
    ids = [r.attack for r in report.results]
    assert ids == ["eprint-2025-867", "guo-qian-usenix24"]
    assert report.coverage.requested == 2


def test_report_serializes_to_json():
    report = run(library="openfhe", params={"scheme": "BFV"}, attacks=["cheon-2024-127"])
    payload = json.loads(json.dumps(report.to_dict()))
    assert payload["library"] == "openfhe"
    assert payload["overall_status"] in {s.value for s in AttackStatus}
    assert payload["results"][0]["attack"] == "cheon-2024-127"
    cov = payload["coverage"]
    assert {"requested", "ran", "safe", "vulnerable", "skipped",
            "not_implemented", "errors", "implemented", "ratio"} <= set(cov)
    assert cov["requested"] == 1
    assert 0.0 <= cov["ratio"] <= 1.0


def test_skipped_when_attack_does_not_apply_to_scheme():
    # GuoQian only applies to CKKS — running with BFV should produce SKIPPED.
    report = run(library="openfhe", params={"scheme": "BFV"}, attacks=["guo-qian-usenix24"])
    assert report.results[0].status is AttackStatus.SKIPPED
    assert report.coverage.skipped == 1
    assert report.coverage.ran == 0


def test_overall_status_skipped_when_only_skips():
    report = run(library="openfhe", params={"scheme": "BFV"}, attacks=["guo-qian-usenix24"])
    assert report.overall_status is AttackStatus.SKIPPED


def test_overall_status_not_implemented_when_any_pending():
    # glitchfhe-usenix25 is still a citation-bearing scaffold.
    report = run(library="openfhe", params={"scheme": "BFV"}, attacks=["glitchfhe-usenix25"])
    assert report.overall_status is AttackStatus.NOT_IMPLEMENTED
    assert report.coverage.not_implemented == 1


def test_constant_time_decrypt_marks_eprint_2025_867_safe_and_overall_safe():
    # eprint-2025-867 short-circuits to SAFE when the adapter advertises constant-time decrypt.
    from fhe_attack_replay.adapters.base import (
        AdapterCapability,
        AdapterContext,
        LibraryAdapter,
    )
    from fhe_attack_replay.registry import register_adapter

    class _CTAdapter(LibraryAdapter):
        name = "synthetic-ct"
        capability = AdapterCapability(schemes=("BFV", "CKKS"))

        def is_available(self):
            return False

        def setup(self, scheme, params):
            return AdapterContext(library=self.name, scheme=scheme, params=params)

        def encrypt(self, ctx, plaintext): ...
        def decrypt(self, ctx, ciphertext): ...
        def evaluator_fingerprint(self, ctx):
            return {
                "implementation": "synthetic",
                "ntt_variant": "branch-free",
                "constant_time_decrypt": True,
            }

    register_adapter(_CTAdapter)
    report = run(library="synthetic-ct", params={"scheme": "BFV"}, attacks=["eprint-2025-867"])
    assert report.results[0].status is AttackStatus.SAFE
    assert report.overall_status is AttackStatus.SAFE
    assert report.coverage.safe == 1
    assert report.coverage.ran == 1
    assert report.coverage.implemented == 1
    assert report.coverage.ratio == 1.0
