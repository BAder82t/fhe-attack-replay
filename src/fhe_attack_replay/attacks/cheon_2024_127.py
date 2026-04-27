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
# All entries are stored in canonical hyphenated form (no underscores) — the
# `_normalize` helper coerces user input into the same shape, so any of
# `openfhe-NOISE_FLOODING_DECRYPT`, `openfhe-noise_flooding_decrypt`, or
# `openfhe-noise-flooding-decrypt` resolve to the same key.
_RECOGNIZED_MITIGATIONS = frozenset(
    {
        "openfhe-noise-flooding-decrypt",
        "eprint-2024-424",
        "modulus-switching-2025-1627",
        "eprint-2025-1627",
        "hint-lwe-2025-1618",
        "eprint-2025-1618",
        "noise-flooding",
    }
)

# Adapter names whose bisection wiring this module knows how to drive
# directly. The set of *capable* adapters is computed dynamically (see
# AdapterCapability.live_oracle); this constant only marks which adapters
# the bisect dispatcher in this file can route to today.
_LIVE_BISECT_DISPATCH = frozenset({"toy-lwe", "openfhe"})

# Default Replay configuration. The bisection rounds and trial count
# determine the statistical strength of the discriminator.
_REPLAY_TRIALS = 8
_REPLAY_BISECT_ROUNDS = 20
# A SAFE verdict requires the bisection-recovered noise estimates to vary by
# at least this fraction of the encoding scale `delta` across trials.
_REPLAY_VARIANCE_MIN_FRAC_DELTA = 0.05


def _normalize(value: Any) -> str:
    """Lowercase + collapse `_` and whitespace into `-`.

    Lets `IND_CPA_D`, `ind cpa d`, and `ind-cpa-d` all map to the same key
    so users do not need to memorise a single canonical spelling.
    """
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


class Cheon2024_127(Attack):
    """IND-CPA-D key-recovery attack against exact FHE schemes.

    Reference: Cheon, Hong, Kim — "Attacks Against the IND-CPA-D Security of
    Exact FHE Schemes" (IACR ePrint 2024/127). The attack queries the
    decryption oracle on adversarially-crafted ciphertexts whose decryption
    error toggles based on a target secret bit, recovering the secret key.

    This module operates in two modes:

    - **Replay (live oracle)**: when the adapter exposes live encrypt/decrypt
      primitives (currently ``toy-lwe`` always, ``openfhe`` when
      ``openfhe-python`` is importable), the module encrypts ``0``, perturbs
      the ciphertext polynomial toward the decryption rounding boundary, runs
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
        live_capable = (
            adapter.capability.live_oracle
            and adapter.supports(ctx.scheme)
            and adapter.name in _LIVE_BISECT_DISPATCH
            and adapter.is_available()
        )
        if live_capable:
            try:
                return self._run_replay(adapter, ctx)
            except NotImplementedError:
                # Adapter advertised the name but cannot actually run primitives
                # (e.g. openfhe-python missing the C++ extension). Fall back.
                pass
        return self._run_risk_check(adapter, ctx)

    # --------------------------------------------------------------- replay --
    def _run_replay(self, adapter: LibraryAdapter, ctx: AdapterContext) -> AttackResult:
        import numpy as np  # local import keeps numpy out of import-time critical path

        ct_zero = adapter.encrypt(ctx, 0)
        trials = self._replay_trials_for(ctx)
        delta = self._delta_for(adapter, ctx, ct_zero)
        bisect_rounds = self._bisect_rounds_for(ctx, delta)
        # Recover the encryption-noise boundary independently in each trial.
        # Without noise flooding, the boundary is fixed (deterministic decrypt).
        # With noise flooding, the boundary is a random variable.
        boundaries: list[int] = []
        for _ in range(trials):
            boundaries.append(
                self._bisect_boundary(
                    adapter, ctx, ct_zero, rounds=bisect_rounds, delta=delta
                )
            )

        boundaries_arr = np.asarray(boundaries, dtype=np.float64)
        mean_b = float(boundaries_arr.mean())
        std_b = float(boundaries_arr.std(ddof=0))
        variance_frac = self._variance_frac_for(ctx)
        threshold = max(1.0, variance_frac * float(delta))
        deterministic = std_b < threshold

        evidence: dict[str, Any] = {
            "mode": "replay",
            "intent_actual": AttackIntent.REPLAY.value,
            "trials": trials,
            "bisect_rounds": bisect_rounds,
            "delta": int(delta),
            "boundary_mean": mean_b,
            "boundary_std": std_b,
            "variance_threshold": threshold,
            "variance_frac_delta": variance_frac,
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
        if adapter.name == "openfhe":
            metadata = adapter.polynomial_replay_metadata(ctx, ct_zero)  # type: ignore[attr-defined]
            evidence.update(
                {
                    "test": "polynomial_domain_bisection",
                    "polynomial_component": 0,
                    **metadata,
                }
            )
        else:
            evidence["test"] = "decrypt_boundary_bisection"

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
        *,
        rounds: int,
        delta: int,
    ) -> int:
        """Binary-search the smallest positive offset that flips decryption.

        Implemented in terms of the adapter's primitives so the same logic
        works against both the toy-lwe adapter and a real OpenFHE/SEAL build
        (subject to those adapters exposing a ``perturb`` operation; the
        toy-lwe adapter exposes it directly via ctx.handles).
        """
        if adapter.name == "toy-lwe":
            return self._bisect_boundary_toy_lwe(ctx, ct_zero, rounds=rounds)
        if adapter.name == "openfhe":
            return self._bisect_boundary_openfhe(adapter, ctx, ct_zero, rounds, delta)
        raise NotImplementedError(
            f"Live-bisect not yet wired for adapter {adapter.name!r}."
        )

    def _bisect_boundary_toy_lwe(
        self, ctx: AdapterContext, ct_zero: Any, *, rounds: int
    ) -> int:
        from fhe_attack_replay.lab.toy_lwe import bisect_decrypt_boundary

        toy = ctx.handles["toy"]
        keys = ctx.handles["keys"]
        rng = ctx.handles["rng"]
        return bisect_decrypt_boundary(
            toy, keys, ct_zero, rng, rounds=rounds
        )

    def _bisect_boundary_openfhe(
        self,
        adapter: LibraryAdapter,
        ctx: AdapterContext,
        ct_zero: Any,
        rounds: int,
        delta: int,
    ) -> int:
        perturb = getattr(adapter, "perturb_ciphertext_constant", None)
        if perturb is None:
            raise NotImplementedError("OpenFHE adapter lacks ciphertext perturbation.")

        baseline = tuple(list(adapter.decrypt(ctx, ct_zero))[:8])
        if not baseline:
            raise NotImplementedError("OpenFHE replay requires packed decrypt output.")

        def flips(offset: int) -> bool:
            perturbed = perturb(ctx, ct_zero, offset, component=0)
            decrypted = tuple(list(adapter.decrypt(ctx, perturbed))[: len(baseline)])
            return decrypted != baseline

        low = 0
        high = max(1, int(delta))
        for _ in range(8):
            if flips(high):
                break
            high *= 2
        else:
            # Genuine runtime divergence (perturbation never crossed the
            # rounding boundary within 8 doublings of delta). Raise
            # RuntimeError so the harness reports ERROR with traceback rather
            # than NOT_IMPLEMENTED, which would be misleading.
            raise RuntimeError(
                "OpenFHE polynomial perturbation did not cross the decrypt "
                f"boundary within 8 doublings of delta={int(delta)}; the "
                "configured ciphertext modulus or noise level may be outside "
                "the bisection module's supported range."
            )

        for _ in range(rounds):
            mid = (low + high) // 2
            if flips(mid):
                high = mid
            else:
                low = mid
        return high

    def _delta_for(
        self, adapter: LibraryAdapter, ctx: AdapterContext, ct_zero: Any
    ) -> int:
        toy = ctx.handles.get("toy") if ctx.handles else None
        if toy is not None:
            return int(toy.delta)
        if adapter.name == "openfhe":
            plaintext_delta = getattr(adapter, "plaintext_delta", None)
            if plaintext_delta is None:
                raise NotImplementedError("OpenFHE adapter lacks plaintext_delta().")
            return int(plaintext_delta(ctx, ct_zero))
        # Fallback: arbitrary unit when delta is not available — the
        # threshold becomes effectively 1.0 in raw integer-modulus units.
        return 1

    def _replay_trials_for(self, ctx: AdapterContext) -> int:
        return max(1, int(ctx.params.get("replay_trials", _REPLAY_TRIALS)))

    def _bisect_rounds_for(self, ctx: AdapterContext, delta: int) -> int:
        configured = ctx.params.get("bisect_rounds")
        if configured is not None:
            return max(1, int(configured))
        return max(_REPLAY_BISECT_ROUNDS, int(delta).bit_length())

    def _variance_frac_for(self, ctx: AdapterContext) -> float:
        """Return the SAFE-verdict variance threshold as a fraction of delta.

        Defaults to 0.05 (the value used to validate the replay against
        toy-lwe). Tunable per-target via ``params["safe_variance_frac_delta"]``;
        higher values bias toward false-VULNERABLE, lower values toward
        false-SAFE. See docs/status-semantics.md for the tradeoff.
        """
        configured = ctx.params.get("safe_variance_frac_delta")
        if configured is None:
            return _REPLAY_VARIANCE_MIN_FRAC_DELTA
        value = float(configured)
        if value <= 0:
            raise ValueError(
                "safe_variance_frac_delta must be > 0; got "
                f"{configured!r}."
            )
        return value

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
