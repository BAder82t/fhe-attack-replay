# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the in-tree eprint-2025-867 ArtifactCheck path.

Same Pearson |ρ| analyzer as reveal-2023-1128 (shared via
``attacks._correlation``); this file pins the eprint-867-specific
verdict surface (precedence over the live timing distinguisher when a
trace is supplied; signature override; threshold-tuning knob).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fhe_attack_replay import run
from fhe_attack_replay.attacks.base import AttackStatus


def _write_trace(path: Path, samples: list[float], models: list[dict]) -> None:
    path.write_text(json.dumps({"samples": samples, "model": models}))


def test_artifact_check_vulnerable_on_high_correlation(tmp_path: Path):
    trace = tmp_path / "leaky.json"
    samples = list(range(40))
    _write_trace(
        trace,
        samples=samples,
        models=[
            {"label": "ntt_tap_3", "predictions": [s * 2 + 1 for s in samples]},
            {"label": "noise", "predictions": [(s % 7) - 3 for s in samples]},
        ],
    )
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.evidence["mode"] == "artifact_check"
    assert r.evidence["intent_actual"] == "artifact_check"
    assert r.evidence["analyzer"] == "in_tree_pearson_correlation"
    assert r.evidence["best_model"] == "ntt_tap_3"
    assert abs(r.evidence["best_correlation"]) > 0.99
    assert r.status is AttackStatus.VULNERABLE


def test_artifact_check_safe_on_low_correlation(tmp_path: Path):
    trace = tmp_path / "clean.json"
    # Pseudo-random samples + orthogonal-ish model predictions: |ρ| stays low.
    samples = [1, -1, 2, -2, 3, -3, 4, -4, 5, -5, 6, -6, 7, -7, 8, -8]
    _write_trace(
        trace,
        samples=samples,
        models=[
            # Small drift, no monotonic relationship to samples.
            {"label": "candidate_a", "predictions": [(i % 3) for i in range(16)]},
        ],
    )
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.evidence["mode"] == "artifact_check"
    assert r.status is AttackStatus.SAFE


def test_artifact_check_takes_precedence_over_live_timing(tmp_path: Path):
    # OpenFHE is live-oracle capable and would normally drive the live
    # timing distinguisher. Supplying a trace switches the dispatch to
    # ArtifactCheck without ever touching the adapter.
    pytest.importorskip("openfhe", reason="optional openfhe-python skip when missing")
    trace = tmp_path / "trace.json"
    samples = list(range(30))
    _write_trace(
        trace,
        samples=samples,
        models=[{"label": "tap", "predictions": [s * 1.5 for s in samples]}],
    )
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.evidence["mode"] == "artifact_check"
    assert r.status is AttackStatus.VULNERABLE


def test_artifact_check_caller_signature_recovered_overrides_analyzer(tmp_path: Path):
    trace = tmp_path / "trace.json"
    # Write a trace that the analyzer would otherwise rate as no-leak,
    # then override with the analyst's "recovered" signature.
    _write_trace(
        trace,
        samples=[0.1, 0.2, 0.3, 0.4],
        models=[{"label": "noise", "predictions": [9, 9, 9, 9]}],
    )
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
            "ntt_leakage_signature": "recovered",
        },
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.evidence["ntt_leakage_signature"] == "recovered"
    assert r.status is AttackStatus.VULNERABLE


def test_artifact_check_caller_signature_clean_overrides_analyzer(tmp_path: Path):
    trace = tmp_path / "trace.json"
    samples = list(range(10))
    _write_trace(
        trace,
        samples=samples,
        models=[{"label": "perfect", "predictions": [s * 1.0 for s in samples]}],
    )
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
            "ntt_leakage_signature": "clean",
        },
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.evidence["ntt_leakage_signature"] == "clean"
    assert r.status is AttackStatus.SAFE


def test_artifact_check_threshold_tuning_flips_verdict(tmp_path: Path):
    trace = tmp_path / "trace.json"
    # Construct a model with |ρ| around 0.6 (positive correlation but
    # not perfect). Threshold 0.5 → VULNERABLE; threshold 0.9 → SAFE.
    samples = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 5.5, 4.5, 3.5, 2.5]
    predictions = [1.0, 1.5, 2.5, 3.0, 4.0, 5.0, 6.0, 5.0, 4.5, 4.0]
    _write_trace(
        trace,
        samples=samples,
        models=[{"label": "partial", "predictions": predictions}],
    )

    strict = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
            "eprint_867_correlation_threshold": 0.5,
        },
        attacks=["eprint-2025-867"],
    )
    lax = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
            "eprint_867_correlation_threshold": 0.99,
        },
        attacks=["eprint-2025-867"],
    )
    assert strict.results[0].status is AttackStatus.VULNERABLE
    assert lax.results[0].status is AttackStatus.SAFE


def test_artifact_check_missing_trace_file_returns_error(tmp_path: Path):
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(tmp_path / "no-such-file.json")},
        },
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "not found" in r.message.lower()


def test_artifact_check_empty_trace_returns_error(tmp_path: Path):
    trace = tmp_path / "empty.json"
    trace.write_text("")
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "empty" in r.message.lower()


def test_artifact_check_malformed_json_returns_error(tmp_path: Path):
    trace = tmp_path / "bad.json"
    trace.write_text("{not valid json")
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "valid json" in r.message.lower() or "parse" in r.message.lower()


def test_artifact_check_invalid_threshold_returns_error(tmp_path: Path):
    trace = tmp_path / "trace.json"
    _write_trace(
        trace,
        samples=[1.0, 2.0, 3.0],
        models=[{"label": "m", "predictions": [1.0, 2.0, 3.0]}],
    )
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
            "eprint_867_correlation_threshold": 1.5,
        },
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "(0, 1]" in r.message


def test_no_evidence_falls_back_to_existing_dispatch():
    # Without --evidence trace=PATH, the run() call should reach the
    # fingerprint risk-check / live-timing path that v0.1+ already
    # ships. SEAL's TenSEAL fingerprint flags VULNERABLE for non-
    # constant-time builds; we just pin that the new ArtifactCheck
    # doesn't hijack the existing path.
    report = run(
        library="seal",
        params={"scheme": "BFV"},
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.evidence["mode"] != "artifact_check"
