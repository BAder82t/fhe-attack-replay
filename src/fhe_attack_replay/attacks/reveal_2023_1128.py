# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

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


class RevEAL_2023_1128(Attack):
    """Single-trace side-channel leakage of the SEAL homomorphic encryption library.

    Reference: Aydin, Karabulut et al. — "RevEAL: Single-Trace Side-Channel
    Leakage of the SEAL Homomorphic Encryption Library." DATE 2022 / IACR
    ePrint 2023/1128. The attack recovers secret-key Hamming weights via a
    single power trace of the modular reduction inside SEAL's NTT.

    ArtifactCheck contract:
      - ``params['evidence_paths']['trace']`` (or CLI ``--evidence trace=PATH``)
        points to the user-supplied power/timing trace. Without a trace,
        the verdict is SKIPPED — the attack cannot run on params alone.
      - ``params['hamming_weight_signature']`` (optional) — declares the
        analyst's expected leakage outcome. If set to ``"recovered"`` and
        the trace file exists and is non-empty, the verdict is VULNERABLE
        (the analyst is asserting the trace evidence matches the published
        leakage signature). If set to ``"clean"``, the verdict is SAFE.

    The actual single-trace correlation analyzer is intentionally not yet
    bundled — implementing it inside this Apache-2.0 project requires
    either porting the published reference (subject to its own license) or
    re-deriving the distinguisher from the paper. Until that lands, the
    module classifies user-supplied evidence rather than running the
    statistical analysis itself.
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
                duration_seconds=0.0,
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
                duration_seconds=0.0,
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
                duration_seconds=0.0,
                evidence=common_evidence,
                message=f"Trace file at {trace_path!s} is empty.",
            )

        if signature == "recovered":
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.VULNERABLE,
                duration_seconds=0.0,
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
                duration_seconds=0.0,
                evidence={**common_evidence, "hamming_weight_signature": "clean"},
                message=(
                    "ArtifactCheck: caller declares the supplied trace does "
                    "not exhibit the RevEAL Hamming-weight leakage. Verdict "
                    "is only as strong as the user-side analysis."
                ),
            )

        return AttackResult(
            attack=self.id,
            library=adapter.name,
            scheme=ctx.scheme,
            status=AttackStatus.NOT_IMPLEMENTED,
            duration_seconds=0.0,
            evidence=common_evidence,
            message=(
                "Trace evidence accepted but the in-tree single-trace "
                "correlation analyzer is not yet bundled. Set "
                "params['hamming_weight_signature'] = 'recovered' or "
                "'clean' to record the result of an external analysis, or "
                "wait for a future release to ship the distinguisher."
            ),
        )
