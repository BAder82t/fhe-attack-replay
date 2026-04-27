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

# Adversary models under which the Cheon-Hong-Kim attack applies.
# IND-CPA-D extends IND-CPA with a decryption oracle. Threshold and multi-party
# FHE deployments expose decryptions to non-trusted participants by construction.
_ORACLE_ADVERSARY_MODELS = frozenset(
    {"ind-cpa-d", "ind-cpa^d", "indcpad", "threshold", "multi-party", "mpc"}
)

# Mitigations recognized as effective against the Cheon-Hong-Kim attack.
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

# Adapters that expose live encrypt/decrypt and can therefore drive the
# end-to-end Replay path. Other adapters fall back to the static RiskCheck.
_REPLAY_CAPABLE_ADAPTERS = frozenset({"toy-lwe", "openfhe"})

# Default Replay configuration. The bisection rounds and trial count
# determine the statistical strength of the discriminator.
_REPLAY_TRIALS = 8
_REPLAY_BISECT_ROUNDS = 20
# A SAFE verdict requires the bisection-recovered noise estimates to vary by
# at least this fraction of the encoding scale `delta` across trials.
_REPLAY_VARIANCE_MIN_FRAC_DELTA = 0.05


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

    This module operates in two modes:

    - **Replay (live oracle)**: when the adapter exposes live encrypt/decrypt
      primitives (currently ``toy-lwe`` always, ``openfhe`` when
      ``openfhe-python`` is importable), the module encrypts ``0``, runs
      a binary search on the decryption oracle to recover the encryption
      noise, and repeats the procedure across multiple trials. Without
      noise-flooding decrypt, the recovered noise is a fixed leak across
      trials → VULNERABLE. With noise flooding, the recovered noise is a
      random variable across trials → SAFE.
    - **Risk check (static)**: when the adapter cannot drive a live oracle,
      the module inspects the supplied params against the threat model of
      the original paper and returns VULNERABLE / SAFE / SKIPPED.

    Reference PoC: hmchoe0528/INDCPAD_HE_ThresFHE.

    Parameter contract (params dict, all optional unless noted):
      - adversary_model: "ind-cpa" | "ind-cpa-d" | "threshold" | "multi-party"
      - decryption_oracle: bool — overrides adversary_model when True/False
      - noise_flooding: see _RECOGNIZED_MITIGATIONS or "none"
      - noise_flooding_sigma: float — only consumed by toy-lwe; non-zero
        triggers the in-tree noise-flooding path that mitigates the attack.

    A SAFE verdict from the live Replay against a *toy* adapter is a
    correctness check on this module, not a production audit. See
    ``DISCLAIMER.md``.
    """

    id = "cheon-2024-127"
    title = "IND-CPA-D Key Recovery (Cheon, Hong, Kim 2024)"
    applies_to_schemes = ("BFV", "BGV", "LWE")
    intent = AttackIntent.RISK_CHECK  # default; replay path overrides via evidence
    citation = Citation(
        title="Attacks Against the IND-CPA-D Security of Exact FHE Schemes",
        authors="J. H. Cheon, S. Hong, D. Kim",
        venue="IACR ePrint 2024/127",
        year=2024,
        url="https://eprint.iacr.org/2024/127",
        eprint="2024/127",
    )

    def run(self, adapter: LibraryAdapter, ctx: AdapterContext) -> AttackResult:
        if adapter.name in _REPLAY_CAPABLE_ADAPTERS and adapter.is_available():
            try:
                if adapter.name == "openfhe":
                    return self._run_replay_openfhe(adapter, ctx)
                return self._run_replay(adapter, ctx)
            except NotImplementedError:
                # Adapter advertised the name but cannot actually run primitives
                # (e.g. openfhe-python missing the C++ extension). Fall back.
                pass
            except Exception as exc:  # pragma: no cover  - defensive
                return AttackResult(
                    attack=self.id,
                    library=adapter.name,
                    scheme=ctx.scheme,
                    status=AttackStatus.ERROR,
                    duration_seconds=0.0,
                    evidence={"replay_failure": repr(exc)},
                    message=f"Replay path errored, did not fall back: {exc!r}",
                )
        return self._run_risk_check(adapter, ctx)

    # ------------------------------------------------------ openfhe replay --
    def _run_replay_openfhe(
        self, adapter: LibraryAdapter, ctx: AdapterContext
    ) -> AttackResult:
        """Decryption-oracle-determinism replay against OpenFHE.

        The full Cheon-Hong-Kim 2024/127 attack constructs a ciphertext at
        the rounding boundary and observes structured decryption errors
        across queries. ``openfhe-python`` does not expose the DCRTPoly
        primitives needed for fine-grained ciphertext perturbation, so we
        run the *necessary precondition* of the attack instead: query the
        decryption oracle on the same ciphertext repeatedly and observe
        whether the oracle is deterministic. A deterministic oracle is
        precisely what the published attack relies on; a randomized
        oracle (e.g. CKKS NOISE_FLOODING_DECRYPT) breaks the noise-recovery
        primitive at the source.
        """
        ct = adapter.encrypt(ctx, [0])
        decryptions: list[tuple[Any, ...]] = []
        for _ in range(_REPLAY_TRIALS):
            pt = adapter.decrypt(ctx, ct)
            # Truncate packed slots so the comparison is bounded.
            decryptions.append(tuple(list(pt)[:8]))
        unique = len({d for d in decryptions})
        deterministic = unique == 1

        evidence: dict[str, Any] = {
            "mode": "replay",
            "intent_actual": AttackIntent.REPLAY.value,
            "trials": _REPLAY_TRIALS,
            "test": "decryption_oracle_determinism",
            "unique_decryptions": unique,
            "deterministic_oracle": deterministic,
            "decryption_sample": list(decryptions[0]) if decryptions else [],
            "citation": self.citation.url if self.citation else "",
            "reference_poc": "https://github.com/hmchoe0528/INDCPAD_HE_ThresFHE",
            "library": adapter.name,
            "library_class": "production",
            "note": (
                "Subset of the Cheon-Hong-Kim attack precondition. "
                "Polynomial-domain bisection requires DCRTPoly access not "
                "exposed by openfhe-python; see "
                "src/fhe_attack_replay/attacks/cheon_2024_127.py."
            ),
        }

        if deterministic:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.VULNERABLE,
                duration_seconds=0.0,
                evidence=evidence,
                message=(
                    f"Live-oracle replay against {adapter.name}: the "
                    f"decryption oracle returned identical plaintext across "
                    f"{_REPLAY_TRIALS} queries on the same ciphertext. The "
                    "oracle is deterministic — the Cheon-Hong-Kim 2024/127 "
                    "noise-recovery primitive applies. Enable a noise-flooded "
                    "decrypt mode (e.g. OpenFHE NOISE_FLOODING_DECRYPT for "
                    "CKKS in EXEC_EVALUATION) to mitigate."
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
                f"Live-oracle replay against {adapter.name}: the decryption "
                f"oracle returned {unique} distinct plaintexts across "
                f"{_REPLAY_TRIALS} queries on the same ciphertext. The oracle "
                "is randomized; the Cheon-Hong-Kim 2024/127 noise-recovery "
                "primitive does not converge."
            ),
        )

    # --------------------------------------------------------------- replay --
    def _run_replay(self, adapter: LibraryAdapter, ctx: AdapterContext) -> AttackResult:
        import numpy as np  # local import keeps numpy out of import-time critical path

        ct_zero = adapter.encrypt(ctx, 0)
        # Recover the encryption-noise boundary independently in each trial.
        # Without noise flooding, the boundary is fixed (deterministic decrypt).
        # With noise flooding, the boundary is a random variable.
        boundaries: list[int] = []
        for _ in range(_REPLAY_TRIALS):
            boundaries.append(self._bisect_boundary(adapter, ctx, ct_zero))

        boundaries_arr = np.asarray(boundaries, dtype=np.float64)
        delta = self._delta_for(ctx)
        mean_b = float(boundaries_arr.mean())
        std_b = float(boundaries_arr.std(ddof=0))
        threshold = max(1.0, _REPLAY_VARIANCE_MIN_FRAC_DELTA * float(delta))
        deterministic = std_b < threshold

        evidence: dict[str, Any] = {
            "mode": "replay",
            "intent_actual": AttackIntent.REPLAY.value,
            "trials": _REPLAY_TRIALS,
            "bisect_rounds": _REPLAY_BISECT_ROUNDS,
            "delta": int(delta),
            "boundary_mean": mean_b,
            "boundary_std": std_b,
            "variance_threshold": threshold,
            "deterministic_oracle": deterministic,
            "boundaries_sample": [int(b) for b in boundaries],
            "citation": self.citation.url if self.citation else "",
            "reference_poc": "https://github.com/hmchoe0528/INDCPAD_HE_ThresFHE",
            "library": adapter.name,
            "library_class": (
                "toy"
                if adapter.name == "toy-lwe"
                else "production"
            ),
        }

        if deterministic:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.VULNERABLE,
                duration_seconds=0.0,
                evidence=evidence,
                message=(
                    "Live-oracle replay: bisection recovered the encryption "
                    f"noise boundary deterministically (std={std_b:.2f} < "
                    f"threshold={threshold:.2f}). The decryption oracle "
                    "leaks the encryption noise; with O(n) such queries the "
                    "Cheon-Hong-Kim 2024/127 procedure recovers the secret "
                    "key. Enable noise-flooding decrypt to mitigate."
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
                "Live-oracle replay: bisection-recovered noise boundary "
                f"varied across trials (std={std_b:.2f} >= threshold="
                f"{threshold:.2f}). The decryption oracle is randomized; "
                "the Cheon-Hong-Kim 2024/127 noise-recovery primitive does "
                "not converge."
            ),
        )

    def _bisect_boundary(
        self,
        adapter: LibraryAdapter,
        ctx: AdapterContext,
        ct_zero: Any,
    ) -> int:
        """Binary-search the smallest positive offset that flips decryption.

        Implemented in terms of the adapter's primitives so the same logic
        works against both the toy-lwe adapter and a real OpenFHE/SEAL build
        (subject to those adapters exposing a ``perturb`` operation; the
        toy-lwe adapter exposes it directly via ctx.handles).
        """
        if adapter.name == "toy-lwe":
            return self._bisect_boundary_toy_lwe(ctx, ct_zero)
        # OpenFHE polynomial-domain perturbation requires C++ access to the
        # underlying DCRTPoly that openfhe-python does not expose. We fall
        # back to a different but valid form of the Cheon attack —
        # decryption-oracle determinism — handled in _run_replay_openfhe.
        raise NotImplementedError(
            f"Live-bisect not yet wired for adapter {adapter.name!r}."
        )

    def _bisect_boundary_toy_lwe(
        self, ctx: AdapterContext, ct_zero: Any
    ) -> int:
        from fhe_attack_replay.lab.toy_lwe import bisect_decrypt_boundary

        toy = ctx.handles["toy"]
        keys = ctx.handles["keys"]
        rng = ctx.handles["rng"]
        return bisect_decrypt_boundary(
            toy, keys, ct_zero, rng, rounds=_REPLAY_BISECT_ROUNDS
        )

    def _delta_for(self, ctx: AdapterContext) -> int:
        toy = ctx.handles.get("toy") if ctx.handles else None
        if toy is not None:
            return int(toy.delta)
        # Fallback: arbitrary unit when delta is not available — the
        # threshold becomes effectively 1.0 in raw integer-modulus units.
        return 1

    # ------------------------------------------------------------ risk check -
    def _run_risk_check(
        self, adapter: LibraryAdapter, ctx: AdapterContext
    ) -> AttackResult:
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
            "mode": "risk_check",
            "intent_actual": AttackIntent.RISK_CHECK.value,
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
