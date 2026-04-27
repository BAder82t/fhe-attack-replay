# Copyright 2026 Vaultbytes (Bader Issaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from fhe_attack_replay.adapters.base import AdapterContext, LibraryAdapter
from fhe_attack_replay.attacks.base import Attack, AttackResult, AttackStatus, Citation


class GuoQian_USENIX24(Attack):
    """Key-recovery against approximate HE with non-worst-case noise flooding.

    Reference: Guo, Qian et al. — "Key Recovery Attacks on Approximate
    Homomorphic Encryption with Non-Worst-Case Noise Flooding Countermeasures."
    USENIX Security 2024.

    The attack defeats noise-flooding countermeasures whose flooding bound is
    derived from average-case noise rather than worst-case noise. Replay
    strategy: instantiate the adapter with the configured noise-flooding
    strategy, query the decryption oracle ~N times, and report whether the
    statistical key-recovery procedure of Guo-Qian succeeds.
    """

    id = "guo-qian-usenix24"
    title = "Key Recovery on Approximate HE w/ Non-Worst-Case Noise Flooding (Guo-Qian USENIX'24)"
    applies_to_schemes = ("CKKS",)
    citation = Citation(
        title=(
            "Key Recovery Attacks on Approximate Homomorphic Encryption "
            "with Non-Worst-Case Noise Flooding Countermeasures"
        ),
        authors="Q. Guo, et al.",
        venue="USENIX Security 2024",
        year=2024,
        url="https://www.usenix.org/system/files/usenixsecurity24-guo-qian_1.pdf",
    )

    def run(self, adapter: LibraryAdapter, ctx: AdapterContext) -> AttackResult:
        return AttackResult(
            attack=self.id,
            library=adapter.name,
            scheme=ctx.scheme,
            status=AttackStatus.NOT_IMPLEMENTED,
            duration_seconds=0.0,
            evidence={
                "citation": self.citation.url if self.citation else "",
                "noise_flooding_strategy": ctx.params.get("noise_flooding", "unspecified"),
            },
            message="Replay logic pending; scaffold only.",
        )
