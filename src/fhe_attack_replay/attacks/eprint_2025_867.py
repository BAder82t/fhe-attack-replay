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
    Encryption." A 98%+ accurate single-trace attack against SEAL `guard`
    and `mul_root` routines on the NTT path.

    RiskCheck strategy: probe the evaluator fingerprint reported by the
    adapter. The published exploit was demonstrated on SEAL/TenSEAL, but
    the same Harvey-butterfly NTT family runs in OpenFHE's ``NativeMath``
    layer and exposes equivalent guard / mul_root surfaces unless the
    library is built with constant-time flags. The matcher therefore flags
    *any* implementation whose fingerprint advertises a Harvey-butterfly
    NTT and does not advertise constant-time decrypt — users on a hardened
    build should set ``params["constant_time_decrypt"] = True``.

    Other fingerprints remain NOT_IMPLEMENTED until a live trace
    distinguisher or adapter-specific evidence lands.
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
        non_constant_ntts = {"harvey-butterfly", "guard", "mul_root"}
        seal_family = "seal" in implementation or "tenseal" in implementation
        openfhe_family = "openfhe" in implementation
        in_scope = seal_family or openfhe_family
        if in_scope and ntt_variant in non_constant_ntts:
            known_surface = (
                "SEAL NTT guard/mul_root non-constant-time path"
                if seal_family
                else "OpenFHE NativeMath Harvey-butterfly NTT (equivalent guard/mul_root surface)"
            )
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.VULNERABLE,
                duration_seconds=0.0,
                evidence={
                    "mode": "risk_check",
                    "evaluator_fingerprint": fp,
                    "known_surface": known_surface,
                    "citation": self.citation.url if self.citation else "",
                },
                message=(
                    "RiskCheck: target fingerprint matches the non-constant "
                    "Harvey-butterfly NTT surface described by ePrint "
                    "2025/867. Use a hardened constant-time build (set "
                    "params['constant_time_decrypt'] = true) or provide "
                    "trace evidence before treating this configuration as "
                    "safe."
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
