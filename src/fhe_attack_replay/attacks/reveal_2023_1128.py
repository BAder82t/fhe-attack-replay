# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from fhe_attack_replay.adapters.base import AdapterContext, LibraryAdapter
from fhe_attack_replay.attacks._correlation import (
    analyze_models,
    parse_trace_file,
)
from fhe_attack_replay.attacks._correlation import (
    pearson_correlation as _pearson_correlation,
)
from fhe_attack_replay.attacks.base import (
    Attack,
    AttackIntent,
    AttackResult,
    AttackStatus,
    Citation,
)

# Re-export under the test-suite-stable name. ``test_reveal_analyzer.py``
# imports ``_pearson_correlation`` from this module.
__all__ = ["RevEAL_2023_1128", "_pearson_correlation"]

# Default Pearson |ρ| above which the analyzer concludes the trace
# leaks the modelled intermediate. The published RevEAL attack reports
# correlations well above 0.5 on real SEAL traces; 0.5 is the
# conservative floor below which any signal is plausibly noise on a
# single trace.
_DEFAULT_CORRELATION_THRESHOLD = 0.5


class RevEAL_2023_1128(Attack):
    """Single-trace side-channel leakage of the SEAL homomorphic encryption library.

    Reference: Aydin, Karabulut, Potluri, Alkim, Aysu — "RevEAL:
    Single-Trace Side-Channel Leakage of the SEAL Homomorphic
    Encryption Library." DATE 2022 / IACR **ePrint 2022/204** (the
    follow-up "Leaking Secrets in HE with Side-Channel Attacks" is
    ePrint 2023/1128 and gives this module its slug for catalog
    stability). The attack recovers secret-key Hamming weights via a
    single power trace of the modular reduction inside SEAL's NTT.

    ArtifactCheck contract:

    - ``params['evidence_paths']['trace']`` (or CLI
      ``--evidence trace=PATH``) points to the user-supplied power /
      timing trace plus the analyst's leakage model. Without a trace,
      the verdict is ``SKIPPED``.
    - ``params['hamming_weight_signature']`` (optional) — bypasses the
      analyzer with the analyst's external decision: ``"recovered"`` →
      ``VULNERABLE``, ``"clean"`` → ``SAFE``.

    **Trace file format (JSON).** A top-level object with two keys:

    - ``samples``: list[float] — the trace measurements (power /
      timing samples), one per timestep;
    - ``model``: list[{label, predictions}] — one or more candidate
      leakage models. Each model carries a free-form ``label`` string
      and a ``predictions`` array of the same length as ``samples``,
      typically Hamming weights of the intermediate value at each
      timestep under one key-bit hypothesis.

    The in-tree analyzer computes Pearson correlation between
    ``samples`` and each model's ``predictions`` and reports
    ``VULNERABLE`` when the maximum |ρ| exceeds
    ``reveal_correlation_threshold`` (default 0.5). Below threshold →
    ``SAFE``. Models with zero variance in either samples or
    predictions are skipped with a note in evidence (correlation is
    undefined).

    Tunable params (all optional):

    - ``reveal_correlation_threshold``: float in (0, 1] — Pearson
      |ρ| above which leakage is declared. Default 0.5.
    - ``hamming_weight_signature``: str — analyst override.
    """

    id = "reveal-2023-1128"
    title = "RevEAL: Single-Trace SCA on SEAL (Aydin, Karabulut et al.)"
    applies_to_schemes = ("BFV", "CKKS", "BGV")
    intent = AttackIntent.ARTIFACT_CHECK
    citation = Citation(
        title=(
            "RevEAL: Single-Trace Side-Channel Leakage of the SEAL "
            "Homomorphic Encryption Library"
        ),
        authors="F. Aydin, E. Karabulut, S. Potluri, E. Alkim, A. Aysu",
        venue="DATE 2022 / IACR ePrint 2022/204 (follow-up: 2023/1128)",
        year=2022,
        url="https://eprint.iacr.org/2022/204",
        eprint="2022/204",
    )

    def run(self, adapter: LibraryAdapter, ctx: AdapterContext) -> AttackResult:
        started = time.monotonic()
        evidence_paths = ctx.params.get("evidence_paths") or {}
        trace_path_raw = evidence_paths.get("trace")
        signature = str(ctx.params.get("hamming_weight_signature") or "").strip().lower()

        common_evidence: dict[str, Any] = {
            "mode": "artifact_check",
            "intent_actual": AttackIntent.ARTIFACT_CHECK.value,
            "evidence_paths": {k: str(v) for k, v in evidence_paths.items()},
            "trace_source": "user-supplied via --evidence trace=PATH",
            "citation": self.citation.url if self.citation else "",
        }

        if not trace_path_raw:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.SKIPPED,
                duration_seconds=time.monotonic() - started,
                evidence=common_evidence,
                message=(
                    "ArtifactCheck requires a power/timing trace. Pass "
                    "--evidence trace=<path> on the CLI or set "
                    "params['evidence_paths']['trace'] in the Python API."
                ),
            )

        trace_path = Path(str(trace_path_raw)).expanduser()
        if not trace_path.exists():
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.ERROR,
                duration_seconds=time.monotonic() - started,
                evidence={**common_evidence, "trace_path": str(trace_path)},
                message=f"Trace file not found at {trace_path!s}.",
            )

        size_bytes = trace_path.stat().st_size
        common_evidence.update(
            {"trace_path": str(trace_path), "trace_size_bytes": size_bytes}
        )

        if size_bytes == 0:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.ERROR,
                duration_seconds=time.monotonic() - started,
                evidence=common_evidence,
                message=f"Trace file at {trace_path!s} is empty.",
            )

        # Caller-supplied signature short-circuits the analyzer (preserved
        # for users with their own external analysis pipeline).
        if signature == "recovered":
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.VULNERABLE,
                duration_seconds=time.monotonic() - started,
                evidence={**common_evidence, "hamming_weight_signature": "recovered"},
                message=(
                    "ArtifactCheck: caller declares the supplied trace "
                    "matches the RevEAL Hamming-weight leakage signature. "
                    "Treat the SEAL/TenSEAL build as vulnerable until a "
                    "constant-time NTT replacement lands."
                ),
            )
        if signature == "clean":
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.SAFE,
                duration_seconds=time.monotonic() - started,
                evidence={**common_evidence, "hamming_weight_signature": "clean"},
                message=(
                    "ArtifactCheck: caller declares the supplied trace does "
                    "not exhibit the RevEAL Hamming-weight leakage. Verdict "
                    "is only as strong as the user-side analysis."
                ),
            )

        # No analyst override → run the in-tree correlation analyzer.
        try:
            samples, models = parse_trace_file(trace_path)
        except (ValueError, json.JSONDecodeError) as exc:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.ERROR,
                duration_seconds=time.monotonic() - started,
                evidence=common_evidence,
                message=f"Failed to parse trace {trace_path!s}: {exc}",
            )

        try:
            threshold = self._analyzer_config(ctx)
        except ValueError as exc:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.ERROR,
                duration_seconds=time.monotonic() - started,
                evidence=common_evidence,
                message=str(exc),
            )

        scores = analyze_models(samples, models)
        # Best score = the model with the largest |ρ|; ties are broken
        # by encounter order so callers see a stable winner.
        ranked = sorted(scores, key=lambda s: abs(s["correlation"]), reverse=True)
        best = ranked[0]
        leakage_detected = abs(best["correlation"]) > threshold
        analyzer_evidence = {
            **common_evidence,
            "mode": "analyzer",
            "intent_actual": AttackIntent.ARTIFACT_CHECK.value,
            "analyzer": "in_tree_pearson_correlation",
            "n_samples": len(samples),
            "n_models": len(models),
            "correlation_threshold": threshold,
            "best_model": best["label"],
            "best_correlation": best["correlation"],
            "all_model_scores": scores,
        }

        if leakage_detected:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.VULNERABLE,
                duration_seconds=time.monotonic() - started,
                evidence=analyzer_evidence,
                message=(
                    f"In-tree single-trace correlation analyzer: best model "
                    f"{best['label']!r} matched the trace with Pearson "
                    f"|ρ|={abs(best['correlation']):.3f} (> {threshold:.3f} "
                    "threshold). Trace exhibits RevEAL Hamming-weight "
                    "leakage; treat the SEAL/TenSEAL build as vulnerable "
                    "until a constant-time NTT replacement lands."
                ),
            )

        return AttackResult(
            attack=self.id,
            library=adapter.name,
            scheme=ctx.scheme,
            status=AttackStatus.SAFE,
            duration_seconds=time.monotonic() - started,
            evidence=analyzer_evidence,
            message=(
                f"In-tree single-trace correlation analyzer: best model "
                f"{best['label']!r} achieved Pearson |ρ|="
                f"{abs(best['correlation']):.3f} (≤ {threshold:.3f} "
                "threshold). No exploitable single-trace leakage observed "
                "in this run. Tune ``reveal_correlation_threshold`` if the "
                "target is known to leak more weakly."
            ),
        )

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _analyzer_config(ctx: AdapterContext) -> float:
        threshold = float(
            ctx.params.get("reveal_correlation_threshold", _DEFAULT_CORRELATION_THRESHOLD)
        )
        if not 0.0 < threshold <= 1.0:
            raise ValueError(
                "reveal_correlation_threshold must be in (0, 1]; got "
                f"{threshold!r}."
            )
        return threshold

