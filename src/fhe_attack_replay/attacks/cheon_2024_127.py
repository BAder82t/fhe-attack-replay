# Copyright 2026 Vaultbytes (Bader Issaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any

from fhe_attack_replay.adapters.base import AdapterContext, LibraryAdapter
from fhe_attack_replay.attacks.base import (
    Attack,
    AttackIntent,
    AttackResult,
    AttackStatus,
    Citation,
)

# Adversary models under which the Cheon-Hong-Kim attack applies.
# IND-CPA-D extends IND-CPA with a decryption oracle. Threshold and multi-party
# FHE deployments expose decryptions to non-trusted participants by construction.
_ORACLE_ADVERSARY_MODELS = frozenset(
    {"ind-cpa-d", "ind-cpa^d", "indcpad", "threshold", "multi-party", "mpc"}
)

# Mitigations recognized as effective against the Cheon-Hong-Kim attack.
# - openfhe-NOISE_FLOODING_DECRYPT: OpenFHE's CKKS noise-flooding mode (also
#   covers BFV/BGV deployments that opt into the same flooding bound).
# - eprint-2024-424: noise-flooding bound revisited.
# - eprint-2025-1627: modulus-switching IND-CPA-D fix.
# - eprint-2025-1618: HintLWE-reduced-noise approach.
# - "noise-flooding": generic flag for users who declare a custom flooding fix.
_RECOGNIZED_MITIGATIONS = frozenset(
    {
        "openfhe-noise_flooding_decrypt",
        "eprint-2024-424",
        "modulus-switching-2025-1627",
        "eprint-2025-1627",
        "hint-lwe-2025-1618",
        "eprint-2025-1618",
        "noise-flooding",
    }
)


def _normalize(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


class Cheon2024_127(Attack):
    """IND-CPA-D key-recovery attack against exact FHE schemes.

    Reference: Cheon, Hong, Kim — "Attacks Against the IND-CPA-D Security of
    Exact FHE Schemes" (IACR ePrint 2024/127). The attack queries the
    decryption oracle on adversarially-crafted ciphertexts whose decryption
    error toggles based on a target secret bit, recovering the secret key.

    This module ships as a **risk check**: it inspects the supplied params
    against the threat model of the original paper and returns VULNERABLE
    when the configuration matches a known-vulnerable pattern, SAFE when a
    recognized mitigation is declared, and SKIPPED when the threat model does
    not apply (no decryption oracle exposure).

    A full **replay** that issues live oracle queries against an OpenFHE BFV
    target will land alongside the OpenFHE adapter wiring; until then the
    risk check is the strongest available signal.

    Reference PoC: hmchoe0528/INDCPAD_HE_ThresFHE.

    Parameter contract (params dict, all optional unless noted):
      - adversary_model: "ind-cpa" | "ind-cpa-d" | "threshold" | "multi-party"
      - decryption_oracle: bool — overrides adversary_model when True/False
      - noise_flooding: see _RECOGNIZED_MITIGATIONS or "none"

    Decision rule:

        oracle_access := decryption_oracle is True
                       OR adversary_model in {ind-cpa-d, threshold, multi-party}
        mitigated    := noise_flooding in _RECOGNIZED_MITIGATIONS
        if not oracle_access:        SKIPPED  (threat model does not apply)
        if mitigated:                SAFE
        else:                        VULNERABLE
    """

    id = "cheon-2024-127"
    title = "IND-CPA-D Key Recovery (Cheon, Hong, Kim 2024)"
    applies_to_schemes = ("BFV", "BGV")
    intent = AttackIntent.RISK_CHECK
    citation = Citation(
        title="Attacks Against the IND-CPA-D Security of Exact FHE Schemes",
        authors="J. H. Cheon, S. Hong, D. Kim",
        venue="IACR ePrint 2024/127",
        year=2024,
        url="https://eprint.iacr.org/2024/127",
        eprint="2024/127",
    )

    def run(self, adapter: LibraryAdapter, ctx: AdapterContext) -> AttackResult:
        params = ctx.params
        adversary_model = _normalize(params.get("adversary_model"))
        decryption_oracle = params.get("decryption_oracle")
        noise_flooding = _normalize(params.get("noise_flooding"))

        if isinstance(decryption_oracle, bool):
            oracle_access = decryption_oracle
        else:
            oracle_access = adversary_model in _ORACLE_ADVERSARY_MODELS

        mitigated = noise_flooding in _RECOGNIZED_MITIGATIONS

        evidence: dict[str, Any] = {
            "decision_rule": "oracle_access AND not mitigated => VULNERABLE",
            "adversary_model": adversary_model or "unspecified",
            "decryption_oracle": oracle_access,
            "noise_flooding": noise_flooding or "unspecified",
            "mitigation_recognized": mitigated,
            "scheme": ctx.scheme,
            "citation": self.citation.url if self.citation else "",
            "reference_poc": "https://github.com/hmchoe0528/INDCPAD_HE_ThresFHE",
        }

        if not oracle_access:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.SKIPPED,
                duration_seconds=0.0,
                evidence=evidence,
                message=(
                    "No decryption-oracle exposure declared (adversary_model "
                    "not in {ind-cpa-d, threshold, multi-party} and "
                    "decryption_oracle is not True). Cheon 2024/127 threat "
                    "model does not apply to this configuration."
                ),
            )

        if mitigated:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.SAFE,
                duration_seconds=0.0,
                evidence=evidence,
                message=(
                    f"Recognized mitigation declared: noise_flooding="
                    f"{noise_flooding!r}. Risk-check verdict; a live-oracle "
                    "replay would still be required for end-to-end assurance."
                ),
            )

        return AttackResult(
            attack=self.id,
            library=adapter.name,
            scheme=ctx.scheme,
            status=AttackStatus.VULNERABLE,
            duration_seconds=0.0,
            evidence=evidence,
            message=(
                "Decryption-oracle exposure declared and no recognized "
                "IND-CPA-D mitigation present. Configuration matches the "
                "Cheon-Hong-Kim 2024 known-vulnerable pattern; expect key "
                "recovery under the published attack."
            ),
        )
