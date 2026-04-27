# Copyright 2026 Vaultbytes (Bader Issaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from fhe_attack_replay.adapters.base import AdapterContext, LibraryAdapter
from fhe_attack_replay.attacks.base import Attack, AttackResult, AttackStatus, Citation


class Cheon2024_127(Attack):
    """IND-CPA-D key-recovery attack against exact FHE schemes.

    Reference: Cheon, Hong, Kim — "Attacks Against the IND-CPA-D Security of
    Exact FHE Schemes" (IACR ePrint 2024/127). The attack queries the decryption
    oracle on adversarially-crafted ciphertexts whose decryption error toggles
    based on a target secret bit, recovering the secret key.

    Reference PoC: hmchoe0528/INDCPAD_HE_ThresFHE.

    Replay strategy: build a vulnerable-vs-mitigated parameter pair, query the
    decryption oracle ~N times, statistically test bit recovery against the
    secret. Mitigated configurations (noise-flooding decrypt) should suppress
    the leak below the recovery threshold.
    """

    id = "cheon-2024-127"
    title = "IND-CPA-D Key Recovery (Cheon, Hong, Kim 2024)"
    applies_to_schemes = ("BFV", "BGV")
    citation = Citation(
        title="Attacks Against the IND-CPA-D Security of Exact FHE Schemes",
        authors="J. H. Cheon, S. Hong, D. Kim",
        venue="IACR ePrint 2024/127",
        year=2024,
        url="https://eprint.iacr.org/2024/127",
        eprint="2024/127",
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
                "reference_poc": "https://github.com/hmchoe0528/INDCPAD_HE_ThresFHE",
            },
            message="Replay logic pending; scaffold only.",
        )
