# Copyright 2026 Vaultbytes (Bader Issaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from fhe_attack_replay.adapters.base import AdapterContext, LibraryAdapter
from fhe_attack_replay.attacks.base import Attack, AttackResult, AttackStatus, Citation


class Eprint2025_867(Attack):
    """Side-channel analysis in homomorphic encryption (RevEAL follow-up).

    Reference: IACR ePrint 2025/867 — "Side Channel Analysis in Homomorphic
    Encryption." A 98%+ accurate single-trace attack against SEAL `guard` and
    `mul_root` routines on the NTT path.

    Replay strategy: probe the evaluator fingerprint reported by the adapter;
    if the evaluator advertises a non-constant-time NTT inverse path, run the
    published distinguisher and report whether secret coefficients leak.
    """

    id = "eprint-2025-867"
    title = "Side Channel Analysis in Homomorphic Encryption (RevEAL follow-up)"
    applies_to_schemes = ("BFV", "CKKS", "BGV")
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
