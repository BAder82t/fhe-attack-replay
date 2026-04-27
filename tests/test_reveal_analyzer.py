# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the in-tree reveal-2023-1128 single-trace correlation analyzer.

The shipped analyzer computes Pearson |ρ| between the trace samples
and each candidate-leakage model's predictions. Verdict logic:

    max |ρ| > correlation_threshold  → VULNERABLE
    max |ρ| ≤ correlation_threshold  → SAFE

Tests cover the full surface:

- Pearson math in isolation (perfect correlation, anti-correlation,
  uncorrelated noise, zero variance);
- analyzer end-to-end against synthetic JSON traces (leaky vs clean);
- model selection across multiple candidates picks the strongest
  correlation;
- threshold tuning flips the verdict;
- caller-supplied ``hamming_weight_signature`` overrides the analyzer;
- every parse / config error surfaces as ``ERROR`` with a precise
  diagnostic.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from fhe_attack_replay import run
from fhe_attack_replay.adapters.base import AdapterContext
from fhe_attack_replay.attacks.base import AttackStatus
from fhe_attack_replay.attacks.reveal_2023_1128 import (
    RevEAL_2023_1128,
    _pearson_correlation,
)


def _write_trace(path: Path, samples: list[float], models: list[dict]) -> None:
    path.write_text(json.dumps({"samples": samples, "model": models}))


# ---------------------------------------------------------------------------
# Pearson helper
# ---------------------------------------------------------------------------


def test_pearson_perfect_positive_correlation():
    rho, degenerate = _pearson_correlation([1, 2, 3, 4], [10, 20, 30, 40])
    assert math.isclose(rho, 1.0, abs_tol=1e-9)
    assert degenerate is False


def test_pearson_perfect_negative_correlation():
    rho, _ = _pearson_correlation([1, 2, 3, 4], [40, 30, 20, 10])
    assert math.isclose(rho, -1.0, abs_tol=1e-9)


def test_pearson_zero_variance_in_x():
    rho, degenerate = _pearson_correlation([5, 5, 5, 5], [1, 2, 3, 4])
    assert rho == 0.0
    assert degenerate is True


def test_pearson_zero_variance_in_y():
    rho, degenerate = _pearson_correlation([1, 2, 3, 4], [7, 7, 7, 7])
    assert rho == 0.0
    assert degenerate is True


def test_pearson_orthogonal_signals():
    # Mean-zero orthogonal vectors: ρ = 0 (numerator vanishes).
    x = [1, -1, 1, -1]
    y = [1, 1, -1, -1]
    rho, _ = _pearson_correlation(x, y)
    assert math.isclose(rho, 0.0, abs_tol=1e-9)


# ---------------------------------------------------------------------------
# End-to-end — leaky trace → VULNERABLE
# ---------------------------------------------------------------------------


def test_vulnerable_when_trace_correlates_with_a_model(tmp_path: Path):
    trace = tmp_path / "trace.json"
    samples = [0.10, 0.21, 0.30, 0.41, 0.49, 0.61, 0.70, 0.79]
    # Predictions perfectly track samples → |ρ| ≈ 1.
    _write_trace(
        trace,
        samples,
        [
            {"label": "key_bit=0", "predictions": [0]*8},  # noise
            {"label": "key_bit=1", "predictions": samples},
        ],
    )
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.VULNERABLE
    assert r.evidence["analyzer"] == "in_tree_pearson_correlation"
    assert r.evidence["best_model"] == "key_bit=1"
    assert r.evidence["best_correlation"] == pytest.approx(1.0, abs=1e-6)
    assert r.evidence["n_samples"] == 8
    assert r.evidence["n_models"] == 2


def test_vulnerable_picks_strongest_model(tmp_path: Path):
    """Multiple candidates: analyzer reports the one with the largest |ρ|."""
    trace = tmp_path / "trace.json"
    samples = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
    _write_trace(
        trace,
        samples,
        [
            {"label": "weak", "predictions": [1, 2, 3, 4, 5, 6, 7, 8]},
            {"label": "anti", "predictions": [8, 7, 6, 5, 4, 3, 2, 1]},
            # Add a no-signal model to verify it doesn't get picked.
            {"label": "flat", "predictions": [0]*8},
        ],
    )
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    # ``weak`` and ``anti`` both have |ρ|=1. Sort is stable on ties → ``weak``.
    assert r.evidence["best_model"] == "weak"
    assert r.status is AttackStatus.VULNERABLE
    # The flat model's degenerate flag is recorded for auditing.
    flat = next(s for s in r.evidence["all_model_scores"] if s["label"] == "flat")
    assert flat["degenerate"] is True


# ---------------------------------------------------------------------------
# End-to-end — clean trace → SAFE
# ---------------------------------------------------------------------------


def test_safe_when_trace_uncorrelated_with_models(tmp_path: Path):
    trace = tmp_path / "trace.json"
    # Mean-zero orthogonal signals → ρ = 0 against both models.
    samples = [1, -1, 1, -1, 1, -1, 1, -1]
    _write_trace(
        trace,
        samples,
        [
            {"label": "ortho1", "predictions": [1, 1, -1, -1, 1, 1, -1, -1]},
            {"label": "ortho2", "predictions": [1, 1, 1, 1, -1, -1, -1, -1]},
        ],
    )
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.SAFE
    assert abs(r.evidence["best_correlation"]) < 0.5


# ---------------------------------------------------------------------------
# Threshold tuning + outcome override
# ---------------------------------------------------------------------------


def test_threshold_tuning_can_flip_vulnerable_to_safe(tmp_path: Path):
    trace = tmp_path / "trace.json"
    samples = [1.0, 2.0, 3.0, 4.0]
    _write_trace(
        trace, samples,
        [{"label": "exact", "predictions": [1.0, 2.0, 3.0, 4.0]}],
    )
    # Default threshold is 0.5; the perfect ρ=1 hits VULNERABLE. Bump
    # threshold above 1.0 is invalid; threshold = 0.9999 still reports
    # VULNERABLE because ρ=1.0 > 0.9999. Use threshold=1.0 — analyzer
    # reports SAFE (strict >, not ≥).
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
            "reveal_correlation_threshold": 1.0,
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.SAFE
    assert r.evidence["correlation_threshold"] == 1.0


def test_signature_override_recovered_skips_analyzer(tmp_path: Path):
    trace = tmp_path / "trace.json"
    # Data the analyzer would call SAFE if it ran (no model defined →
    # would actually ERROR; but the signature override short-circuits
    # before any parsing happens).
    trace.write_text("not even json")
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
            "hamming_weight_signature": "recovered",
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.VULNERABLE
    assert r.evidence["mode"] == "artifact_check"
    assert r.evidence["hamming_weight_signature"] == "recovered"


def test_signature_override_clean_skips_analyzer(tmp_path: Path):
    trace = tmp_path / "trace.json"
    trace.write_text("not even json")
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
            "hamming_weight_signature": "CLEAN",
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.SAFE


# ---------------------------------------------------------------------------
# Parse / config errors
# ---------------------------------------------------------------------------


def test_error_on_invalid_json(tmp_path: Path):
    trace = tmp_path / "trace.json"
    trace.write_text("not-json{")
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "not valid JSON" in r.message


def test_error_on_top_level_non_object(tmp_path: Path):
    trace = tmp_path / "trace.json"
    trace.write_text("[1, 2, 3]")
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "JSON object" in r.message


def test_error_when_samples_missing(tmp_path: Path):
    trace = tmp_path / "trace.json"
    trace.write_text(json.dumps({"model": [{"label": "x", "predictions": [1]}]}))
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "samples" in r.message


def test_error_when_samples_empty(tmp_path: Path):
    trace = tmp_path / "trace.json"
    _write_trace(trace, [], [{"label": "x", "predictions": []}])
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "non-empty" in r.message


def test_error_when_models_missing(tmp_path: Path):
    trace = tmp_path / "trace.json"
    trace.write_text(json.dumps({"samples": [1, 2, 3]}))
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "model" in r.message


def test_error_when_model_predictions_wrong_length(tmp_path: Path):
    trace = tmp_path / "trace.json"
    _write_trace(
        trace,
        [1, 2, 3, 4],
        [{"label": "shorty", "predictions": [1, 2]}],
    )
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "does not match" in r.message


def test_error_when_model_missing_predictions_field(tmp_path: Path):
    trace = tmp_path / "trace.json"
    trace.write_text(
        json.dumps(
            {
                "samples": [1, 2, 3],
                "model": [{"label": "broken"}],
            }
        )
    )
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "predictions" in r.message


def test_error_when_model_is_not_an_object(tmp_path: Path):
    trace = tmp_path / "trace.json"
    trace.write_text(
        json.dumps({"samples": [1, 2, 3], "model": [42]})
    )
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "Model 0" in r.message


def test_error_when_samples_contain_non_numeric(tmp_path: Path):
    trace = tmp_path / "trace.json"
    trace.write_text(
        json.dumps({"samples": [1, "two", 3], "model": [{"label": "x", "predictions": [1, 2, 3]}]})
    )
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "non-numeric" in r.message


def test_error_when_predictions_contain_non_numeric(tmp_path: Path):
    trace = tmp_path / "trace.json"
    trace.write_text(
        json.dumps(
            {
                "samples": [1, 2, 3],
                "model": [{"label": "x", "predictions": [1, None, 3]}],
            }
        )
    )
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "non-numeric" in r.message


def test_error_on_invalid_threshold(tmp_path: Path):
    trace = tmp_path / "trace.json"
    _write_trace(trace, [1, 2, 3], [{"label": "x", "predictions": [1, 2, 3]}])
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
            "reveal_correlation_threshold": 1.5,
        },
        attacks=["reveal-2023-1128"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "correlation_threshold" in r.message


# ---------------------------------------------------------------------------
# Existing skip / error paths still work
# ---------------------------------------------------------------------------


def test_skipped_when_no_trace_path():
    report = run(
        library="seal",
        params={"scheme": "BFV"},
        attacks=["reveal-2023-1128"],
    )
    assert report.results[0].status is AttackStatus.SKIPPED


def test_error_when_trace_missing(tmp_path: Path):
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(tmp_path / "nope.json")},
        },
        attacks=["reveal-2023-1128"],
    )
    assert report.results[0].status is AttackStatus.ERROR


def test_error_when_trace_empty(tmp_path: Path):
    trace = tmp_path / "trace.json"
    trace.write_text("")
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "evidence_paths": {"trace": str(trace)},
        },
        attacks=["reveal-2023-1128"],
    )
    assert report.results[0].status is AttackStatus.ERROR


# ---------------------------------------------------------------------------
# Internal helper coverage
# ---------------------------------------------------------------------------


def test_analyzer_config_defaults_when_no_overrides():
    ctx = AdapterContext(library="seal", scheme="BFV", params={})
    assert RevEAL_2023_1128._analyzer_config(ctx) == 0.5


def test_analyzer_config_rejects_zero():
    ctx = AdapterContext(library="seal", scheme="BFV", params={"reveal_correlation_threshold": 0})
    with pytest.raises(ValueError, match="correlation_threshold"):
        RevEAL_2023_1128._analyzer_config(ctx)
