# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from fhe_attack_replay.adapters.base import AdapterContext, LibraryAdapter
from fhe_attack_replay.attacks.base import (
    Attack,
    AttackIntent,
    AttackResult,
    AttackStatus,
    Citation,
)


class Eprint2025_867(Attack):
    """Side-channel analysis in homomorphic encryption (RevEAL follow-up).

    Reference: IACR ePrint 2025/867 — "Side Channel Analysis in Homomorphic
    Encryption." A 98%+ accurate single-trace attack against SEAL `guard` and
    `mul_root` routines on the NTT path.

    RiskCheck strategy: probe the evaluator fingerprint reported by the
    adapter. If the target is SEAL/TenSEAL with a known non-constant NTT
    variant, report the configuration as vulnerable to the published
    side-channel class. If the adapter advertises a constant-time decrypt
    path, report SAFE. Other fingerprints remain NOT_IMPLEMENTED until a
    live trace distinguisher or adapter-specific evidence lands.
    """

    id = "eprint-2025-867"
    title = "Side Channel Analysis in Homomorphic Encryption (RevEAL follow-up)"
    applies_to_schemes = ("BFV", "CKKS", "BGV")
    intent = AttackIntent.RISK_CHECK
    citation = Citation(
        title="Side Channel Analysis in Homomorphic Encryption",
        authors="anonymous (IACR ePrint 2025/867)",
        venue="IACR ePrint 2025/867",
        year=2025,
        url="https://eprint.iacr.org/2025/867",
        eprint="2025/867",
    )

    def run(self, adapter: LibraryAdapter, ctx: AdapterContext) -> AttackResult:
        fp = adapter.evaluator_fingerprint(ctx)
        constant_time = bool(fp.get("constant_time_decrypt", False))
        implementation = str(fp.get("implementation", "")).lower()
        ntt_variant = str(fp.get("ntt_variant", "")).lower()
        if constant_time:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.SAFE,
                duration_seconds=0.0,
                evidence={
                    "evaluator_fingerprint": fp,
                    "rationale": "Adapter advertises constant-time decrypt path.",
                },
                message="Target advertises constant-time decrypt; no leak surface for this attack.",
            )
        if ("seal" in implementation or "tenseal" in implementation) and ntt_variant in {
            "harvey-butterfly",
            "guard",
            "mul_root",
        }:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.VULNERABLE,
                duration_seconds=0.0,
                evidence={
                    "mode": "risk_check",
                    "evaluator_fingerprint": fp,
                    "known_surface": "SEAL NTT guard/mul_root non-constant-time path",
                    "citation": self.citation.url if self.citation else "",
                },
                message=(
                    "RiskCheck: target fingerprint matches the SEAL/TenSEAL "
                    "non-constant NTT surface described by ePrint 2025/867. "
                    "Use a hardened constant-time build or provide trace "
                    "evidence before treating this configuration as safe."
                ),
            )
        return AttackResult(
            attack=self.id,
            library=adapter.name,
            scheme=ctx.scheme,
            status=AttackStatus.NOT_IMPLEMENTED,
            duration_seconds=0.0,
            evidence={
                "evaluator_fingerprint": fp,
                "citation": self.citation.url if self.citation else "",
            },
            message="Distinguisher pending; scaffold only.",
        )
