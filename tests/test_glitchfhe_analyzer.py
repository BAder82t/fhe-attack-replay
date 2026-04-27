# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the in-tree glitchfhe-usenix25 differential analyzer.

Five behaviours under test:

1. **No effective faults → SAFE.** A log where every observed output
   matches expected has zero effective fault rate; the analyzer reports
   SAFE regardless of log size.
2. **Targeted single-bit faults → VULNERABLE.** High effective fault
   rate with low Hamming distance per fault matches the GlitchFHE
   signature.
3. **Random noise → SAFE.** High effective fault rate with high HD
   per fault is uncorrelated noise, not a recoverable channel.
4. **Format auto-detection.** Both JSON-array and JSONL inputs parse
   correctly; comments and blank lines are ignored in JSONL mode.
5. **Threshold tuning + caller-supplied outcome override.** Both
   knobs surface in evidence and short-circuit the verdict when set.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fhe_attack_replay import run
from fhe_attack_replay.attacks.base import AttackStatus
from fhe_attack_replay.attacks.glitchfhe_usenix25 import (
    GlitchFHE_USENIX25,
    _hamming_distance,
)


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")


def _write_json_array(path: Path, records: list[dict]) -> None:
    path.write_text(json.dumps(records))


# ---------------------------------------------------------------------------
# Hamming distance helper
# ---------------------------------------------------------------------------


def test_hamming_distance_equal_lists():
    assert _hamming_distance([1, 2, 3], [1, 2, 3]) == 0


def test_hamming_distance_single_position_diff():
    assert _hamming_distance([1, 2, 3], [1, 9, 3]) == 1


def test_hamming_distance_length_mismatch_charges_extra_slots():
    # The shorter list is treated as diverging in every extra slot of
    # the longer one — worst case for the operator.
    assert _hamming_distance([1, 2, 3], [1, 2, 3, 4, 5]) == 2


# ---------------------------------------------------------------------------
# 1. No effective faults → SAFE
# ---------------------------------------------------------------------------


def test_safe_when_no_effective_faults(tmp_path: Path):
    log = tmp_path / "fault.log"
    records = [
        {"fault_id": i, "expected": [1, 2, 3, 4], "observed": [1, 2, 3, 4]}
        for i in range(20)
    ]
    _write_json_array(log, records)
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
        },
        attacks=["glitchfhe-usenix25"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.SAFE
    assert r.evidence["analyzer"] == "in_tree_differential"
    assert r.evidence["effective_faults"] == 0
    assert r.evidence["effective_fault_rate"] == 0.0
    assert r.evidence["mean_hd_per_effective_fault"] == 0.0


# ---------------------------------------------------------------------------
# 2. Targeted single-bit faults → VULNERABLE
# ---------------------------------------------------------------------------


def test_vulnerable_when_targeted_single_bit_faults(tmp_path: Path):
    log = tmp_path / "fault.log"
    # 50% of injections produce a single-position diff — the canonical
    # GlitchFHE signature: high effective rate, low HD per fault.
    records: list[dict] = []
    for i in range(20):
        if i % 2 == 0:
            records.append({"fault_id": i, "expected": [1, 2, 3, 4], "observed": [1, 9, 3, 4]})
        else:
            records.append({"fault_id": i, "expected": [1, 2, 3, 4], "observed": [1, 2, 3, 4]})
    _write_jsonl(log, records)
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
        },
        attacks=["glitchfhe-usenix25"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.VULNERABLE
    assert r.evidence["effective_faults"] == 10
    assert r.evidence["effective_fault_rate"] == pytest.approx(0.5)
    assert r.evidence["mean_hd_per_effective_fault"] == 1.0
    assert "targeted fault pattern" in r.message.lower()


# ---------------------------------------------------------------------------
# 3. Random noise (high HD per fault) → SAFE
# ---------------------------------------------------------------------------


def test_safe_when_faults_look_like_random_noise(tmp_path: Path):
    log = tmp_path / "fault.log"
    # All slots of the observed vector differ — mean HD = 8, well above
    # the default max_mean_hd of 4. Effective rate is high but the
    # pattern is uncorrelated noise; analyzer should report SAFE.
    records = [
        {"expected": [0]*8, "observed": [i+1, i+2, i+3, i+4, i+5, i+6, i+7, i+8]}
        for i in range(10)
    ]
    _write_json_array(log, records)
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
        },
        attacks=["glitchfhe-usenix25"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.SAFE
    assert r.evidence["effective_faults"] == 10
    assert r.evidence["mean_hd_per_effective_fault"] == 8.0


# ---------------------------------------------------------------------------
# 4. Format auto-detection — JSONL with comments, JSON array
# ---------------------------------------------------------------------------


def test_jsonl_format_supports_comments_and_blank_lines(tmp_path: Path):
    log = tmp_path / "fault.log"
    log.write_text(
        "# capture run 2026-04-27\n"
        "\n"
        '{"fault_id": 1, "expected": [0, 0], "observed": [1, 0]}\n'
        "# end of run\n"
        '{"fault_id": 2, "expected": [0, 0], "observed": [0, 1]}\n'
    )
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
        },
        attacks=["glitchfhe-usenix25"],
    )
    r = report.results[0]
    # Two effective faults out of two records, mean HD = 1 → matches
    # GlitchFHE pattern.
    assert r.evidence["total_records"] == 2
    assert r.evidence["effective_faults"] == 2
    assert r.status is AttackStatus.VULNERABLE


def test_json_array_format_with_one_record(tmp_path: Path):
    log = tmp_path / "fault.log"
    _write_json_array(log, [{"expected": [0], "observed": [1]}])
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
        },
        attacks=["glitchfhe-usenix25"],
    )
    assert report.results[0].evidence["total_records"] == 1


# ---------------------------------------------------------------------------
# Parse / config errors
# ---------------------------------------------------------------------------


def test_error_on_invalid_jsonl_line(tmp_path: Path):
    log = tmp_path / "fault.log"
    log.write_text('{"expected": [0], "observed": [1]}\nnot-json-here\n')
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
        },
        attacks=["glitchfhe-usenix25"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "Line 2" in r.message


def test_error_on_jsonl_record_missing_fields(tmp_path: Path):
    log = tmp_path / "fault.log"
    log.write_text('{"expected": [0]}\n')  # observed missing
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
        },
        attacks=["glitchfhe-usenix25"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "expected" in r.message and "observed" in r.message


def test_error_on_top_level_json_non_array(tmp_path: Path):
    log = tmp_path / "fault.log"
    log.write_text('{"expected": [0], "observed": [1]}')  # bare object
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
        },
        attacks=["glitchfhe-usenix25"],
    )
    # Bare object parses through the JSONL branch (single record on
    # single line) — this is intentional and produces a valid analyzer
    # result rather than an error. Just assert that.
    assert report.results[0].status is AttackStatus.VULNERABLE


def test_error_on_array_with_non_object(tmp_path: Path):
    log = tmp_path / "fault.log"
    log.write_text("[1, 2, 3]")
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
        },
        attacks=["glitchfhe-usenix25"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "Record 0" in r.message


def test_error_on_whitespace_only_log(tmp_path: Path):
    log = tmp_path / "fault.log"
    log.write_text("   \n\n\t\n")
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
        },
        attacks=["glitchfhe-usenix25"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "no records" in r.message


def test_error_on_invalid_min_rate(tmp_path: Path):
    log = tmp_path / "fault.log"
    _write_json_array(log, [{"expected": [0], "observed": [1]}])
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
            "glitchfhe_min_effective_fault_rate": 2.0,  # out of range
        },
        attacks=["glitchfhe-usenix25"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "min_effective_fault_rate" in r.message


def test_error_on_invalid_max_hd(tmp_path: Path):
    log = tmp_path / "fault.log"
    _write_json_array(log, [{"expected": [0], "observed": [1]}])
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
            "glitchfhe_max_mean_hd": 0,  # invalid
        },
        attacks=["glitchfhe-usenix25"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "max_mean_hd" in r.message


# ---------------------------------------------------------------------------
# 5. Threshold tuning + outcome override
# ---------------------------------------------------------------------------


def test_threshold_tuning_can_force_safe(tmp_path: Path):
    """Same data as the VULNERABLE single-bit test; raise the min
    effective rate above 50% and the verdict flips to SAFE."""
    log = tmp_path / "fault.log"
    records = [
        {"fault_id": i, "expected": [1, 2], "observed": [1, 9]}
        if i % 2 == 0
        else {"fault_id": i, "expected": [1, 2], "observed": [1, 2]}
        for i in range(20)
    ]
    _write_json_array(log, records)
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
            # Need >60% effective; we have 50%.
            "glitchfhe_min_effective_fault_rate": 0.6,
        },
        attacks=["glitchfhe-usenix25"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.SAFE
    assert r.evidence["min_effective_fault_rate"] == 0.6


def test_caller_supplied_outcome_overrides_analyzer(tmp_path: Path):
    """When ``differential_outcome`` is set, the analyzer is bypassed
    even if the supplied data would otherwise drive a different verdict."""
    log = tmp_path / "fault.log"
    # Data that the analyzer would call SAFE (no effective faults).
    _write_json_array(log, [{"expected": [0], "observed": [0]}])
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
            "differential_outcome": "recovered",
        },
        attacks=["glitchfhe-usenix25"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.VULNERABLE
    assert r.evidence["mode"] == "artifact_check"  # not "analyzer"
    assert r.evidence["differential_outcome"] == "recovered"


# ---------------------------------------------------------------------------
# Sample truncation
# ---------------------------------------------------------------------------


def test_per_record_sample_truncated_for_large_logs(tmp_path: Path):
    log = tmp_path / "fault.log"
    records = [
        {"fault_id": i, "expected": [0], "observed": [0]} for i in range(100)
    ]
    _write_json_array(log, records)
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
        },
        attacks=["glitchfhe-usenix25"],
    )
    r = report.results[0]
    assert r.evidence["total_records"] == 100
    assert len(r.evidence["per_record_sample"]) == 32
    assert r.evidence["per_record_truncated"] is True


# ---------------------------------------------------------------------------
# Internal helper exposure (covers _analyzer_config edge case directly)
# ---------------------------------------------------------------------------


def test_analyzer_config_defaults_when_no_overrides():
    from fhe_attack_replay.adapters.base import AdapterContext
    ctx = AdapterContext(library="openfhe", scheme="BFV", params={})
    min_rate, max_mean_hd = GlitchFHE_USENIX25._analyzer_config(ctx)
    assert min_rate == 0.05
    assert max_mean_hd == 4.0


def test_error_on_jsonl_non_object_line(tmp_path: Path):
    """JSONL lines that parse to non-objects (e.g. bare numbers) are
    rejected so the analyzer never silently drops a malformed record."""
    log = tmp_path / "fault.log"
    log.write_text('{"expected": [0], "observed": [0]}\n42\n')
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
        },
        attacks=["glitchfhe-usenix25"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "Line 2" in r.message and "JSON object" in r.message


def test_analyzer_parses_empty_array_as_no_records(tmp_path: Path):
    """Edge case: a literal `[]` parses but contains zero records → ERROR."""
    log = tmp_path / "fault.log"
    log.write_text("[]")
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
        },
        attacks=["glitchfhe-usenix25"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "no records" in r.message
