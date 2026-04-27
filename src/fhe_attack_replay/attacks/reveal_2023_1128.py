# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import math
import time
from pathlib import Path
from typing import Any

from fhe_attack_replay.adapters.base import AdapterContext, LibraryAdapter
from fhe_attack_replay.attacks.base import (
    Attack,
    AttackIntent,
    AttackResult,
    AttackStatus,
    Citation,
)

# Default Pearson |ρ| above which the analyzer concludes the trace
# leaks the modelled intermediate. The published RevEAL attack reports
# correlations well above 0.5 on real SEAL traces; 0.5 is the
# conservative floor below which any signal is plausibly noise on a
# single trace.
_DEFAULT_CORRELATION_THRESHOLD = 0.5


class RevEAL_2023_1128(Attack):
    """Single-trace side-channel leakage of the SEAL homomorphic encryption library.

    Reference: Aydin, Karabulut et al. — "RevEAL: Single-Trace Side-Channel
    Leakage of the SEAL Homomorphic Encryption Library." DATE 2022 / IACR
    ePrint 2023/1128. The attack recovers secret-key Hamming weights via a
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
        authors="F. Aydin, E. Karabulut, et al.",
        venue="DATE 2022 / IACR ePrint 2023/1128",
        year=2023,
        url="https://eprint.iacr.org/2023/1128",
        eprint="2023/1128",
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
            samples, models = self._parse_trace(trace_path)
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

        scores = self._analyze(samples, models)
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

    @staticmethod
    def _parse_trace(path: Path) -> tuple[list[float], list[dict[str, Any]]]:
        """Parse a trace JSON file into ``(samples, models)``.

        Raises :class:`ValueError` with a precise diagnostic when the
        document violates the expected schema. Length consistency
        between ``samples`` and each model's ``predictions`` is enforced
        here so the analyzer body can assume well-formed inputs.
        """
        text = path.read_text(encoding="utf-8")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"trace is not valid JSON: {exc.msg}") from exc
        if not isinstance(payload, dict):
            raise ValueError("trace must be a JSON object with 'samples' and 'model'.")
        samples_raw = payload.get("samples")
        models_raw = payload.get("model")
        if not isinstance(samples_raw, list) or not samples_raw:
            raise ValueError("trace 'samples' must be a non-empty array of numbers.")
        if not isinstance(models_raw, list) or not models_raw:
            raise ValueError("trace 'model' must be a non-empty array of model objects.")
        try:
            samples = [float(s) for s in samples_raw]
        except (TypeError, ValueError) as exc:
            raise ValueError(f"trace 'samples' contains a non-numeric value: {exc}") from exc

        models: list[dict[str, Any]] = []
        for idx, raw in enumerate(models_raw):
            if not isinstance(raw, dict):
                raise ValueError(f"Model {idx} must be an object.")
            label = str(raw.get("label") or f"model_{idx}")
            predictions_raw = raw.get("predictions")
            if not isinstance(predictions_raw, list):
                raise ValueError(f"Model {idx} ({label!r}) is missing 'predictions' array.")
            if len(predictions_raw) != len(samples):
                raise ValueError(
                    f"Model {idx} ({label!r}) prediction length "
                    f"{len(predictions_raw)} does not match samples length "
                    f"{len(samples)}."
                )
            try:
                predictions = [float(p) for p in predictions_raw]
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Model {idx} ({label!r}) predictions contain a "
                    f"non-numeric value: {exc}"
                ) from exc
            models.append({"label": label, "predictions": predictions})
        return samples, models

    @staticmethod
    def _analyze(
        samples: list[float], models: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Pearson |ρ| between ``samples`` and each model's predictions.

        Models with zero variance (constant samples or constant
        predictions) get a correlation of 0 and a ``"degenerate":
        true`` flag — Pearson is undefined in that case but treating it
        as no signal keeps the verdict logic monotonic.
        """
        scores: list[dict[str, Any]] = []
        for model in models:
            rho, degenerate = _pearson_correlation(samples, model["predictions"])
            scores.append(
                {
                    "label": model["label"],
                    "correlation": rho,
                    "degenerate": degenerate,
                }
            )
        return scores


def _pearson_correlation(x: list[float], y: list[float]) -> tuple[float, bool]:
    """Return ``(rho, degenerate)`` for two equal-length numeric arrays.

    ``degenerate=True`` means one of the inputs had zero variance and
    Pearson correlation is undefined; the function then returns
    ``rho=0.0`` so callers can treat the result as no signal.
    """
    n = len(x)
    # Mean
    mx = sum(x) / n
    my = sum(y) / n
    cov = 0.0
    var_x = 0.0
    var_y = 0.0
    for xi, yi in zip(x, y, strict=True):
        dx = xi - mx
        dy = yi - my
        cov += dx * dy
        var_x += dx * dx
        var_y += dy * dy
    denom = math.sqrt(var_x * var_y)
    if denom == 0.0:
        return 0.0, True
    return cov / denom, False
