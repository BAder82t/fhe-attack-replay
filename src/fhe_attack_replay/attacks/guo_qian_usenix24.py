# Copyright 2026 Vaultbytes (Bader Alissaei)
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

# Average-case-bound flooding strategies that the Guo-Qian USENIX'24 paper
# proves insufficient for IND-CPA-D-style decryption oracles in CKKS.
# Stored in the same canonical hyphenated form as cheon-2024-127.
_AVERAGE_CASE_FLOODING = frozenset(
    {
        "li-micciancio",
        "li-micciancio-2021",
        "average-case",
        "average-case-noise-flooding",
        "eprint-2020-1533",  # Li-Micciancio "On the security of HE on real numbers"
    }
)

# Worst-case-bound flooding constructions that survive the Guo-Qian analysis.
# `openfhe-noise-flooding-decrypt` historically uses worst-case flooding when
# `EXEC_NOISE_FLOODING` is enabled (post Cheon-Hong-Kim 2024/127 hardening).
_WORST_CASE_FLOODING = frozenset(
    {
        "worst-case",
        "worst-case-noise-flooding",
        "openfhe-noise-flooding-decrypt",
        "eprint-2024-424",  # Cheon-Choe-Hong-Park worst-case flooding
        "eprint-2025-1627",
        "modulus-switching-2025-1627",
        "eprint-2025-1618",
        "hint-lwe-2025-1618",
    }
)


def _normalize(value: Any) -> str:
    """Lowercase + collapse `_`/whitespace to `-`. Mirrors cheon-2024-127."""
    if value is None:
        return ""
    text = str(value).strip().lower()
    out: list[str] = []
    prev_dash = False
    for ch in text:
        if ch in {"_", " ", "\t"}:
            if not prev_dash:
                out.append("-")
                prev_dash = True
        else:
            out.append(ch)
            prev_dash = ch == "-"
    return "".join(out)


class GuoQian_USENIX24(Attack):
    """Key-recovery against approximate HE with non-worst-case noise flooding.

    Reference: Guo, Qian et al. — "Key Recovery Attacks on Approximate
    Homomorphic Encryption with Non-Worst-Case Noise Flooding Countermeasures."
    USENIX Security 2024.

    Threat model: a CKKS deployment with a noise-flooding decryption oracle
    whose flooding bound is derived from *average-case* noise estimates
    (e.g. the Li-Micciancio construction). Guo-Qian show that the residual
    bias is enough to recover the secret key in polynomial queries.

    This module operates as a **RiskCheck**: it inspects the declared
    flooding strategy in the params dict and decides VULNERABLE / SAFE /
    SKIPPED against the published threat model. The attack does not yet
    drive a live oracle — when one lands, declare ``intent_actual=replay``
    in evidence the way ``cheon-2024-127`` does.

    Parameter contract:
      - ``noise_flooding_strategy`` (preferred) or ``noise_flooding`` —
        identifies the flooding construction. Recognized labels are stored
        in ``_AVERAGE_CASE_FLOODING`` (vulnerable) and ``_WORST_CASE_FLOODING``
        (safe).
      - ``decryption_oracle`` (bool) and/or ``adversary_model`` — same
        semantics as cheon-2024-127. Without oracle exposure the threat
        model is moot.
    """

    id = "guo-qian-usenix24"
    title = (
        "Key Recovery on Approximate HE w/ Non-Worst-Case Noise Flooding "
        "(Guo-Qian USENIX'24)"
    )
    applies_to_schemes = ("CKKS",)
    intent = AttackIntent.RISK_CHECK
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
        params = ctx.params
        # Prefer the explicit `noise_flooding_strategy` key — falls back to
        # `noise_flooding` so configs written for cheon-2024-127 work too.
        strategy = _normalize(
            params.get("noise_flooding_strategy")
            or params.get("noise_flooding")
        )
        adversary_model = _normalize(params.get("adversary_model"))
        decryption_oracle = params.get("decryption_oracle")

        oracle_models = {"ind-cpa-d", "ind-cpa^d", "indcpad", "threshold", "multi-party", "mpc"}
        if isinstance(decryption_oracle, bool):
            oracle_access = decryption_oracle
        else:
            oracle_access = adversary_model in oracle_models

        is_average_case = strategy in _AVERAGE_CASE_FLOODING
        is_worst_case = strategy in _WORST_CASE_FLOODING

        evidence: dict[str, Any] = {
            "mode": "risk_check",
            "intent_actual": AttackIntent.RISK_CHECK.value,
            "decision_rule": (
                "oracle_access AND average-case-bound flooding => VULNERABLE; "
                "worst-case-bound flooding => SAFE; "
                "no flooding declared on a CKKS oracle => SKIPPED "
                "(threat model targets *flooded* configurations)."
            ),
            "scheme": ctx.scheme,
            "adversary_model": adversary_model or "unspecified",
            "decryption_oracle": oracle_access,
            "noise_flooding_strategy": strategy or "unspecified",
            "average_case_bound": is_average_case,
            "worst_case_bound": is_worst_case,
            "citation": self.citation.url if self.citation else "",
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
                    "No decryption-oracle exposure declared. Guo-Qian "
                    "USENIX'24 threat model assumes IND-CPA-D / threshold / "
                    "multi-party access; this configuration is out of scope."
                ),
            )

        if not (is_average_case or is_worst_case):
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.SKIPPED,
                duration_seconds=0.0,
                evidence=evidence,
                message=(
                    "Guo-Qian USENIX'24 specifically targets noise-flooded "
                    "CKKS deployments. No recognized flooding strategy was "
                    "declared (got "
                    f"{strategy!r}); other CKKS attacks may still apply."
                ),
            )

        if is_average_case:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.VULNERABLE,
                duration_seconds=0.0,
                evidence=evidence,
                message=(
                    f"Declared flooding strategy {strategy!r} is an "
                    "average-case-bound construction. Guo-Qian USENIX'24 "
                    "shows polynomial-query key recovery against this class "
                    "of mitigations. Switch to a worst-case-bound "
                    "construction (e.g. eprint-2024-424, "
                    "openfhe-NOISE_FLOODING_DECRYPT)."
                ),
            )

        return AttackResult(
            attack=self.id,
            library=adapter.name,
            scheme=ctx.scheme,
            status=AttackStatus.SAFE,
            duration_seconds=0.0,
            evidence=evidence,
            message=(
                f"Declared flooding strategy {strategy!r} is a recognized "
                "worst-case-bound construction. Guo-Qian USENIX'24 "
                "non-worst-case-noise-flooding attack does not apply. "
                "RiskCheck verdict; an end-to-end replay would still be "
                "required for full assurance."
            ),
        )
