# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the modules promoted out of NOT_IMPLEMENTED scaffold.

Covers:
- guo-qian-usenix24 RiskCheck (average-case vs worst-case flooding strategies).
- eprint-2025-867 RiskCheck against the OpenFHE Harvey-butterfly NTT.
- ArtifactCheck plumbing (CLI --evidence flag, runner pass-through, attack
  body short-circuits).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fhe_attack_replay import run
from fhe_attack_replay.attacks.base import AttackIntent, AttackStatus
from fhe_attack_replay.cli import EXIT_USAGE, _parse_evidence, main

# --- guo-qian-usenix24 RiskCheck ------------------------------------------


@pytest.mark.parametrize(
    "strategy",
    [
        "li-micciancio",
        "Li_Micciancio",  # case + underscore variants
        "AVERAGE-CASE",
        "average_case_noise_flooding",
        "eprint-2020-1533",
    ],
)
def test_guo_qian_vulnerable_for_average_case_flooding(strategy):
    report = run(
        library="seal",
        params={
            "scheme": "CKKS",
            "adversary_model": "ind-cpa-d",
            "noise_flooding_strategy": strategy,
        },
        attacks=["guo-qian-usenix24"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.VULNERABLE
    assert r.intent is AttackIntent.RISK_CHECK
    assert r.evidence["average_case_bound"] is True
    assert r.evidence["worst_case_bound"] is False


@pytest.mark.parametrize(
    "strategy",
    [
        "worst-case",
        "WORST_CASE",
        "openfhe-NOISE_FLOODING_DECRYPT",
        "eprint-2024-424",
        "modulus-switching-2025-1627",
        "hint-lwe-2025-1618",
    ],
)
def test_guo_qian_safe_for_worst_case_flooding(strategy):
    report = run(
        library="seal",
        params={
            "scheme": "CKKS",
            "adversary_model": "ind-cpa-d",
            "noise_flooding_strategy": strategy,
        },
        attacks=["guo-qian-usenix24"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.SAFE
    assert r.evidence["worst_case_bound"] is True


def test_guo_qian_skipped_when_no_oracle_exposure():
    report = run(
        library="seal",
        params={"scheme": "CKKS", "noise_flooding_strategy": "li-micciancio"},
        attacks=["guo-qian-usenix24"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.SKIPPED
    assert "out of scope" in r.message.lower()


def test_guo_qian_skipped_when_no_recognized_flooding():
    report = run(
        library="seal",
        params={
            "scheme": "CKKS",
            "adversary_model": "ind-cpa-d",
            "noise_flooding_strategy": "homemade-flooding-v3",
        },
        attacks=["guo-qian-usenix24"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.SKIPPED
    assert "specifically targets" in r.message.lower() or "no recognized" in r.message.lower()


def test_guo_qian_falls_back_to_noise_flooding_param_when_strategy_absent():
    # Configs written for cheon-2024-127 set `noise_flooding`. Guo-Qian
    # should pick that up too.
    report = run(
        library="seal",
        params={
            "scheme": "CKKS",
            "decryption_oracle": True,
            "noise_flooding": "li-micciancio",
        },
        attacks=["guo-qian-usenix24"],
    )
    assert report.results[0].status is AttackStatus.VULNERABLE


def test_guo_qian_does_not_apply_to_bfv():
    # Cheon-Hong-Kim 2024/127 covers exact schemes; Guo-Qian is CKKS-only.
    report = run(
        library="seal",
        params={"scheme": "BFV", "adversary_model": "ind-cpa-d"},
        attacks=["guo-qian-usenix24"],
    )
    assert report.results[0].status is AttackStatus.SKIPPED


# --- OpenFHE NTT fingerprint feeds eprint-2025-867 -------------------------


def test_eprint_2025_867_marks_openfhe_vulnerable_by_fingerprint():
    pytest.importorskip("openfhe")
    report = run(
        library="openfhe",
        params={"scheme": "BFV", "constant_time_decrypt": False},
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.VULNERABLE
    fp = r.evidence["evaluator_fingerprint"]
    assert fp["ntt_variant"] == "harvey-butterfly"
    assert "OpenFHE" in r.evidence["known_surface"]


def test_eprint_2025_867_openfhe_safe_when_constant_time_decrypt_overridden():
    pytest.importorskip("openfhe")
    report = run(
        library="openfhe",
        params={"scheme": "BFV", "constant_time_decrypt": True},
        attacks=["eprint-2025-867"],
    )
    assert report.results[0].status is AttackStatus.SAFE


# --- ArtifactCheck plumbing ----------------------------------------------


def test_parse_evidence_returns_path_dict(tmp_path: Path):
    f1 = tmp_path / "trace.npy"
    f1.write_bytes(b"\x00")
    f2 = tmp_path / "fault.log"
    f2.write_text("data")
    parsed = _parse_evidence([f"trace={f1}", f"fault_log={f2}"])
    assert parsed == {"trace": f1, "fault_log": f2}


def test_parse_evidence_rejects_missing_equals():
    with pytest.raises(ValueError, match="KEY=PATH"):
        _parse_evidence(["traceonly"])


def test_parse_evidence_rejects_empty_key(tmp_path: Path):
    f = tmp_path / "x"
    f.write_text("data")
    with pytest.raises(ValueError, match="key is empty"):
        _parse_evidence([f"={f}"])


def test_parse_evidence_rejects_duplicate_key(tmp_path: Path):
    f = tmp_path / "x"
    f.write_text("data")
    with pytest.raises(ValueError, match="declared more than once"):
        _parse_evidence([f"trace={f}", f"trace={f}"])


def test_parse_evidence_rejects_missing_file(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        _parse_evidence([f"trace={tmp_path / 'nope.npy'}"])


def test_cli_evidence_flag_propagates_into_params(tmp_path: Path):
    params = tmp_path / "p.json"
    params.write_text(json.dumps({"scheme": "BFV"}))
    fault_log = tmp_path / "fault.log"
    fault_log.write_text("data")
    out = tmp_path / "report.json"
    rc = main(
        [
            "run",
            "--lib",
            "openfhe",
            "--params",
            str(params),
            "--attacks",
            "glitchfhe-usenix25",
            "--evidence",
            f"fault_log={fault_log}",
            "--output-json",
            str(out),
            "--allow-not-implemented",
            "--quiet",
        ]
    )
    payload = json.loads(out.read_text())
    assert rc == 0
    paths = payload["results"][0]["evidence"]["evidence_paths"]
    assert paths["fault_log"].endswith("fault.log")


def test_cli_evidence_invalid_format_returns_usage_error(tmp_path: Path):
    params = tmp_path / "p.json"
    params.write_text(json.dumps({"scheme": "BFV"}))
    rc = main(
        [
            "run",
            "--lib",
            "openfhe",
            "--params",
            str(params),
            "--attacks",
            "glitchfhe-usenix25",
            "--evidence",
            "no-equals-sign",
            "--quiet",
        ]
    )
    assert rc == EXIT_USAGE


# --- reveal-2023-1128 ArtifactCheck body ----------------------------------


def test_reveal_skipped_when_no_trace_evidence():
    report = run(
        library="seal",
        params={"scheme": "BFV"},
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.SKIPPED
    assert r.intent is AttackIntent.ARTIFACT_CHECK
    assert "trace" in r.message.lower()


def test_reveal_error_when_trace_path_missing(tmp_path: Path):
    nonexistent = tmp_path / "missing.npy"
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(nonexistent)},
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "not found" in r.message


def test_reveal_error_when_trace_empty(tmp_path: Path):
    empty = tmp_path / "empty.npy"
    empty.write_text("")
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(empty)},
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "empty" in r.message.lower()


def test_reveal_vulnerable_when_signature_recovered(tmp_path: Path):
    trace = tmp_path / "trace.npy"
    trace.write_bytes(b"\x00\x01" * 4096)
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
            "hamming_weight_signature": "RECOVERED",
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.VULNERABLE
    assert r.evidence["hamming_weight_signature"] == "recovered"
    assert r.evidence["trace_size_bytes"] == 8192


def test_reveal_safe_when_signature_clean(tmp_path: Path):
    trace = tmp_path / "trace.npy"
    trace.write_bytes(b"\x00")
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
            "hamming_weight_signature": "clean",
        },
        attacks=["reveal-2023-1128"],
    )
    assert report.results[0].status is AttackStatus.SAFE


def test_reveal_not_implemented_when_signature_not_declared(tmp_path: Path):
    trace = tmp_path / "trace.npy"
    trace.write_bytes(b"\x00")
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["reveal-2023-1128"],
    )
    assert report.results[0].status is AttackStatus.NOT_IMPLEMENTED


# --- glitchfhe-usenix25 ArtifactCheck body --------------------------------


def test_glitchfhe_skipped_when_no_fault_log():
    report = run(
        library="openfhe",
        params={"scheme": "BFV"},
        attacks=["glitchfhe-usenix25"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.SKIPPED
    assert "fault" in r.message.lower()


def test_glitchfhe_error_when_fault_log_missing(tmp_path: Path):
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(tmp_path / "missing.log")},
        },
        attacks=["glitchfhe-usenix25"],
    )
    assert report.results[0].status is AttackStatus.ERROR


def test_glitchfhe_error_when_fault_log_empty(tmp_path: Path):
    empty = tmp_path / "fault.log"
    empty.write_text("")
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(empty)},
        },
        attacks=["glitchfhe-usenix25"],
    )
    assert report.results[0].status is AttackStatus.ERROR


def test_glitchfhe_vulnerable_when_outcome_recovered(tmp_path: Path):
    log = tmp_path / "fault.log"
    log.write_text("differential capture")
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
            "fault_model": "voltage-glitch-ntt",
            "differential_outcome": "recovered",
        },
        attacks=["glitchfhe-usenix25"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.VULNERABLE
    assert r.evidence["fault_model"] == "voltage-glitch-ntt"


def test_glitchfhe_safe_when_outcome_resistant(tmp_path: Path):
    log = tmp_path / "fault.log"
    log.write_text("differential capture")
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
            "differential_outcome": "RESISTANT",
        },
        attacks=["glitchfhe-usenix25"],
    )
    assert report.results[0].status is AttackStatus.SAFE


def test_glitchfhe_not_implemented_when_outcome_undeclared(tmp_path: Path):
    log = tmp_path / "fault.log"
    log.write_text("data")
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"fault_log": str(log)},
        },
        attacks=["glitchfhe-usenix25"],
    )
    assert report.results[0].status is AttackStatus.NOT_IMPLEMENTED
