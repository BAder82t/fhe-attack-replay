# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
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

# Default analyzer thresholds. Tunable via params; see ``_analyzer_config``.
# Both defaults are deliberately conservative — better to flag a borderline
# accelerator as VULNERABLE and let the operator widen the bounds than to
# silently SAFE-classify a real fault-recoverable target.
_DEFAULT_MIN_EFFECTIVE_FAULT_RATE = 0.05
_DEFAULT_MAX_MEAN_HD = 4.0


class GlitchFHE_USENIX25(Attack):
    """Fault-injection (glitch) attack against FHE accelerators.

    Reference: Mankali et al. — "GlitchFHE." USENIX Security 2025.
    Demonstrates voltage/clock fault injection against the NTT and
    key-switching pipelines of FHE accelerators, recovering secret-key
    material from a small number of faulted decryptions.

    ArtifactCheck contract:

    - ``params['evidence_paths']['fault_log']`` (or CLI ``--evidence
      fault_log=PATH``) points to a user-supplied capture of faulted
      decryptions and their original-vs-faulted output pairs. Without a
      fault log, the verdict is SKIPPED.
    - ``params['fault_model']`` (optional) describes the injection model
      (e.g. ``voltage-glitch-ntt``, ``clock-glitch-keyswitch``); surfaced
      in evidence for audit but not used to decide the verdict.
    - ``params['differential_outcome']`` (optional) — overrides the
      in-tree analyzer with the analyst's external decision. Accepted
      values: ``"recovered"`` → VULNERABLE; ``"resistant"`` → SAFE.

    **Fault log format (JSON or JSONL).** Each record is an object with
    at least ``expected`` and ``observed`` arrays of integers (the
    unfaulted vs faulted decryption outputs of one trial). Optional
    ``fault_id`` and ``fault_model`` are surfaced in evidence. Example
    JSONL line::

        {"fault_id": 7, "expected": [1, 2, 3, 4], "observed": [1, 2, 99, 4]}

    The in-tree analyzer reports ``VULNERABLE`` when the **effective
    fault rate** (records with any expected/observed mismatch) is at
    least ``glitchfhe_min_effective_fault_rate`` (default 0.05) **and**
    the mean Hamming distance per effective fault is at most
    ``glitchfhe_max_mean_hd`` (default 4) — high effective rates with
    low Hamming distance per fault are the GlitchFHE signature of
    targeted, recoverable faults; high distance per fault is noise.

    Tunable params (all optional):

    - ``glitchfhe_min_effective_fault_rate``: float (default 0.05) —
      minimum fraction of injections that produced any output diff
      before key recovery is plausible;
    - ``glitchfhe_max_mean_hd``: float (default 4.0) — upper bound on
      mean Hamming distance per effective fault. High = noise; low =
      structured (recoverable);
    - ``differential_outcome``: str — bypass the analyzer entirely.
    """

    id = "glitchfhe-usenix25"
    title = "GlitchFHE: Fault-Injection Attack on FHE Accelerators (Mankali et al. USENIX'25)"
    applies_to_schemes = ("BFV", "CKKS", "BGV", "TFHE")
    intent = AttackIntent.ARTIFACT_CHECK
    citation = Citation(
        title="GlitchFHE",
        authors="A. Mankali, et al.",
        venue="USENIX Security 2025",
        year=2025,
        url="https://www.usenix.org/system/files/usenixsecurity25-mankali.pdf",
    )

    def run(self, adapter: LibraryAdapter, ctx: AdapterContext) -> AttackResult:
        started = time.monotonic()
        evidence_paths = ctx.params.get("evidence_paths") or {}
        fault_log_raw = evidence_paths.get("fault_log")
        fault_model = str(ctx.params.get("fault_model") or "unspecified")
        outcome = str(ctx.params.get("differential_outcome") or "").strip().lower()

        common_evidence: dict[str, Any] = {
            "mode": "artifact_check",
            "intent_actual": AttackIntent.ARTIFACT_CHECK.value,
            "evidence_paths": {k: str(v) for k, v in evidence_paths.items()},
            "fault_model": fault_model,
            "citation": self.citation.url if self.citation else "",
        }

        if not fault_log_raw:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.SKIPPED,
                duration_seconds=time.monotonic() - started,
                evidence=common_evidence,
                message=(
                    "ArtifactCheck requires a fault-injection log. Pass "
                    "--evidence fault_log=<path> on the CLI or set "
                    "params['evidence_paths']['fault_log'] in the Python API."
                ),
            )

        fault_log = Path(str(fault_log_raw)).expanduser()
        if not fault_log.exists():
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.ERROR,
                duration_seconds=time.monotonic() - started,
                evidence={**common_evidence, "fault_log_path": str(fault_log)},
                message=f"Fault log not found at {fault_log!s}.",
            )

        size_bytes = fault_log.stat().st_size
        common_evidence.update(
            {"fault_log_path": str(fault_log), "fault_log_size_bytes": size_bytes}
        )
        if size_bytes == 0:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.ERROR,
                duration_seconds=time.monotonic() - started,
                evidence=common_evidence,
                message=f"Fault log at {fault_log!s} is empty.",
            )

        # Caller-supplied differential_outcome short-circuits the
        # analyzer — preserved for users with their own decision pipeline.
        if outcome == "recovered":
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.VULNERABLE,
                duration_seconds=time.monotonic() - started,
                evidence={**common_evidence, "differential_outcome": "recovered"},
                message=(
                    "ArtifactCheck: caller declares the supplied fault log "
                    "yields key-recovering differentials per the GlitchFHE "
                    "USENIX'25 procedure. Treat the accelerator pipeline as "
                    "vulnerable to fault injection."
                ),
            )
        if outcome == "resistant":
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.SAFE,
                duration_seconds=time.monotonic() - started,
                evidence={**common_evidence, "differential_outcome": "resistant"},
                message=(
                    "ArtifactCheck: caller declares the supplied fault log "
                    "shows no exploitable differentials. Verdict is only as "
                    "strong as the user-side analysis."
                ),
            )

        # Outcome was not declared → run the in-tree analyzer.
        try:
            records = self._parse_fault_log(fault_log)
        except (ValueError, json.JSONDecodeError) as exc:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.ERROR,
                duration_seconds=time.monotonic() - started,
                evidence=common_evidence,
                message=f"Failed to parse fault log {fault_log!s}: {exc}",
            )

        if not records:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.ERROR,
                duration_seconds=time.monotonic() - started,
                evidence=common_evidence,
                message=f"Fault log {fault_log!s} contained no records.",
            )

        try:
            min_rate, max_mean_hd = self._analyzer_config(ctx)
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

        stats = self._analyze(records)
        leakage_detected = (
            stats["effective_fault_rate"] >= min_rate
            and stats["mean_hd_per_effective_fault"] <= max_mean_hd
        )
        analyzer_evidence = {
            **common_evidence,
            "mode": "analyzer",
            "intent_actual": AttackIntent.ARTIFACT_CHECK.value,
            "analyzer": "in_tree_differential",
            "min_effective_fault_rate": min_rate,
            "max_mean_hd": max_mean_hd,
            **stats,
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
                    f"In-tree differential analyzer: "
                    f"{stats['effective_faults']}/{stats['total_records']} "
                    f"injections produced output differences "
                    f"({stats['effective_fault_rate']*100:.1f}% effective, "
                    f"≥ {min_rate*100:.1f}% threshold), with mean Hamming "
                    f"distance {stats['mean_hd_per_effective_fault']:.2f} per "
                    f"effective fault (≤ {max_mean_hd:.2f} threshold). "
                    "Targeted fault pattern matches GlitchFHE USENIX'25 — "
                    "treat the accelerator pipeline as vulnerable."
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
                f"In-tree differential analyzer: "
                f"{stats['effective_faults']}/{stats['total_records']} "
                f"effective faults ({stats['effective_fault_rate']*100:.1f}%); "
                f"mean Hamming distance per effective fault "
                f"{stats['mean_hd_per_effective_fault']:.2f}. "
                "Pattern does not match the GlitchFHE signature under the "
                "current thresholds — no recoverable differentials in this "
                "log. Tune ``glitchfhe_min_effective_fault_rate`` / "
                "``glitchfhe_max_mean_hd`` if the accelerator is known to "
                "fault more aggressively."
            ),
        )

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _analyzer_config(ctx: AdapterContext) -> tuple[float, float]:
        params = ctx.params
        min_rate = float(params.get(
            "glitchfhe_min_effective_fault_rate", _DEFAULT_MIN_EFFECTIVE_FAULT_RATE,
        ))
        if not 0.0 < min_rate <= 1.0:
            raise ValueError(
                "glitchfhe_min_effective_fault_rate must be in (0, 1]; got "
                f"{min_rate!r}."
            )
        max_mean_hd = float(params.get("glitchfhe_max_mean_hd", _DEFAULT_MAX_MEAN_HD))
        if max_mean_hd <= 0:
            raise ValueError(
                "glitchfhe_max_mean_hd must be > 0; got "
                f"{max_mean_hd!r}."
            )
        return min_rate, max_mean_hd

    @staticmethod
    def _parse_fault_log(path: Path) -> list[dict[str, Any]]:
        """Parse a fault log as either a JSON array or a JSONL stream.

        The format is auto-detected from the first non-whitespace
        character: ``[`` → array, anything else → JSONL. Lines starting
        with ``#`` are treated as comments in JSONL mode so user logs
        can carry annotations.
        """
        text = path.read_text(encoding="utf-8")
        stripped = text.lstrip()
        if not stripped:
            return []
        if stripped.startswith("["):
            data = json.loads(stripped)
            # ``json.loads`` of a string starting with ``[`` either returns
            # a list or raises ``JSONDecodeError`` — so no isinstance check
            # is needed here. Records that are non-objects are caught in
            # the loop below.
            records: list[dict[str, Any]] = []
            for idx, raw in enumerate(data):
                if not isinstance(raw, dict):
                    raise ValueError(f"Record {idx} is not an object.")
                records.append(raw)
            return records
        records = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith("#"):
                continue
            try:
                obj = json.loads(stripped_line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Line {line_no} is not valid JSON: {exc.msg}"
                ) from exc
            if not isinstance(obj, dict):
                raise ValueError(f"Line {line_no} is not a JSON object.")
            records.append(obj)
        return records

    @staticmethod
    def _analyze(records: list[dict[str, Any]]) -> dict[str, Any]:
        """Compute the effective-fault-rate + mean-HD statistics.

        A record is *effective* when its ``observed`` array differs from
        ``expected`` in at least one position. Hamming distance is the
        count of differing positions; mismatched lengths are treated as
        differences in every extra slot (worst case for the operator,
        best case for the attacker).
        """
        total = len(records)
        effective = 0
        total_hd = 0
        per_record: list[dict[str, Any]] = []
        for idx, rec in enumerate(records):
            expected = rec.get("expected")
            observed = rec.get("observed")
            if not isinstance(expected, list) or not isinstance(observed, list):
                raise ValueError(
                    f"Record {idx} missing list-typed 'expected' / 'observed' "
                    "fields."
                )
            hd = _hamming_distance(expected, observed)
            if hd > 0:
                effective += 1
                total_hd += hd
            per_record.append(
                {
                    "fault_id": rec.get("fault_id", idx),
                    "hamming_distance": hd,
                    "fault_model": rec.get("fault_model"),
                }
            )
        # Cap the per-record list in evidence to avoid blowing up the
        # JSON report on multi-million-record logs; the summary stats are
        # always exact.
        sample_cap = 32
        return {
            "total_records": total,
            "effective_faults": effective,
            "effective_fault_rate": (effective / total) if total else 0.0,
            "total_hd": total_hd,
            "mean_hd_per_effective_fault": (total_hd / effective) if effective else 0.0,
            "per_record_sample": per_record[:sample_cap],
            "per_record_truncated": total > sample_cap,
        }


def _hamming_distance(a: list[Any], b: list[Any]) -> int:
    """Position-wise inequality count plus length-mismatch slots."""
    common = min(len(a), len(b))
    diffs = sum(1 for i in range(common) if a[i] != b[i])
    diffs += abs(len(a) - len(b))
    return diffs
