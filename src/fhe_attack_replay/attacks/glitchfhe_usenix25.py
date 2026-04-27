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
      - ``params['differential_outcome']`` (optional) — declares the
        analyst's outcome from external differential analysis. If set to
        ``"recovered"`` and the fault log is non-empty, the verdict is
        VULNERABLE; ``"resistant"`` produces SAFE.

    The differential analyzer that turns a fault log into a key-recovery
    decision is not yet bundled in this Apache-2.0 project. Until then,
    this module only structures the evidence and surfaces the analyst's
    declared outcome.
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
                duration_seconds=0.0,
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
                duration_seconds=0.0,
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
                duration_seconds=0.0,
                evidence=common_evidence,
                message=f"Fault log at {fault_log!s} is empty.",
            )

        if outcome == "recovered":
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.VULNERABLE,
                duration_seconds=0.0,
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
                duration_seconds=0.0,
                evidence={**common_evidence, "differential_outcome": "resistant"},
                message=(
                    "ArtifactCheck: caller declares the supplied fault log "
                    "shows no exploitable differentials. Verdict is only as "
                    "strong as the user-side analysis."
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
                "Fault log accepted but the in-tree differential analyzer is "
                "not yet bundled. Set params['differential_outcome'] = "
                "'recovered' or 'resistant' to record the result of an "
                "external analysis, or wait for a future release to ship "
                "the analyzer."
            ),
        )
