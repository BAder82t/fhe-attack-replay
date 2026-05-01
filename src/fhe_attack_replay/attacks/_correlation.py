# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Shared Pearson-correlation trace analyzer.

Both ``reveal-2023-1128`` (single-trace SCA on SEAL) and
``eprint-2025-867`` (RevEAL follow-up on SEAL/OpenFHE NTT) consume
power / EM / timing traces in the same JSON schema and run the same
Pearson |ρ| discriminator. The published attacks differ only in
*which* leakage model the analyst supplies — the analyzer body is
identical, so it lives here to keep the per-attack modules thin.

Trace file format (JSON, same as reveal-2023-1128):

    {
      "samples": [float, ...],          # one measurement per timestep
      "model":   [
        {
          "label":       "<free-form>",
          "predictions": [float, ...]   # same length as samples
        },
        ...
      ]
    }
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


def parse_trace_file(path: Path) -> tuple[list[float], list[dict[str, Any]]]:
    """Parse a trace JSON file into ``(samples, models)``.

    Raises :class:`ValueError` with a precise diagnostic when the
    document violates the expected schema. Length consistency between
    ``samples`` and each model's ``predictions`` is enforced here so
    the analyzer body can assume well-formed inputs.
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


def analyze_models(
    samples: list[float], models: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Pearson |ρ| between ``samples`` and each model's predictions.

    Models with zero variance (constant samples or constant predictions)
    get ``correlation=0.0`` and ``degenerate=True``. Pearson is
    undefined in that case but treating it as no signal keeps the
    verdict logic monotonic.
    """
    scores: list[dict[str, Any]] = []
    for model in models:
        rho, degenerate = pearson_correlation(samples, model["predictions"])
        scores.append(
            {
                "label": model["label"],
                "correlation": rho,
                "degenerate": degenerate,
            }
        )
    return scores


def pearson_correlation(x: list[float], y: list[float]) -> tuple[float, bool]:
    """Return ``(rho, degenerate)`` for two equal-length numeric arrays.

    ``degenerate=True`` means one of the inputs had zero variance and
    Pearson correlation is undefined; the function then returns
    ``rho=0.0`` so callers can treat the result as no signal.
    """
    n = len(x)
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
