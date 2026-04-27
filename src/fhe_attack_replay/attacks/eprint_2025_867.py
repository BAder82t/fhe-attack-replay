# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import statistics
import time
from typing import Any

from fhe_attack_replay.adapters.base import AdapterContext, LibraryAdapter
from fhe_attack_replay.attacks.base import (
    Attack,
    AttackIntent,
    AttackResult,
    AttackStatus,
    Citation,
)

# NTT variants documented in the paper as exposing data-dependent
# guard / mul_root branches. ``harvey-butterfly`` is the umbrella label
# used by SEAL and OpenFHE NativeMath; ``guard`` and ``mul_root`` are
# legacy aliases some adapters may emit. Stored lowercase.
_NON_CONSTANT_NTTS = frozenset({"harvey-butterfly", "guard", "mul_root"})

# Default replay configuration. Tunable via params; see ``_replay_config``.
_DEFAULT_TIMING_REPEATS = 64
_DEFAULT_TIMING_STIMULI = (
    # Two contrasting plaintexts are enough for the discriminator: the
    # difference in mean decrypt time between them is the leak signal.
    # The values are deliberately in opposite halves of the typical BFV
    # plaintext space so the NTT path exercises different guard /
    # mul_root branches between groups.
    [0, 0, 0, 0, 0, 0, 0, 0],
    [1, 1, 1, 1, 1, 1, 1, 1],
)
# Coefficient-of-variation threshold separating SAFE from VULNERABLE.
# 5% of the slower group's mean is a conservative floor that stays above
# the per-call jitter floor of even slow CI runners (≈1µs).
_DEFAULT_TIMING_CV_THRESHOLD = 0.05


class Eprint2025_867(Attack):
    """Side-channel analysis in homomorphic encryption (RevEAL follow-up).

    Reference: IACR ePrint 2025/867 — "Side Channel Analysis in Homomorphic
    Encryption." A 98%+ accurate single-trace attack against SEAL ``guard``
    and ``mul_root`` routines on the NTT path.

    The module operates in three layers:

    1. **Constant-time short-circuit**: if the adapter's
       :meth:`evaluator_fingerprint` advertises ``constant_time_decrypt``
       the verdict is ``SAFE`` immediately — there is no leak surface to
       measure.
    2. **Live timing replay**: when the adapter is live-oracle capable and
       the fingerprint advertises an in-scope non-constant NTT (Harvey
       butterfly / SEAL ``guard`` / ``mul_root``), the module times
       :meth:`adapter.decrypt` against multiple stimulus plaintexts. If the
       per-stimulus mean times differ by more than
       ``safe_timing_cv_threshold`` of the slower group's mean, the
       decrypt path is leaking → ``VULNERABLE``. Otherwise → ``SAFE``.
    3. **Fingerprint risk-check**: when no live oracle is available, the
       fingerprint alone determines a SEAL/OpenFHE non-constant build →
       ``VULNERABLE``; anything else falls to ``NOT_IMPLEMENTED`` so users
       supplying side-channel traces can plug in artifact evidence later.

    Tunable params (all optional):

    - ``constant_time_decrypt``: bool — short-circuit override (e.g. for
      hardened builds);
    - ``disable_live_replay``: bool — skip the live timing distinguisher
      and force the conservative fingerprint risk-check verdict
      (useful in CI environments where timing measurements are too
      noisy to be trustworthy);
    - ``replay_timing_repeats``: int — calls per stimulus (default 64);
    - ``replay_timing_stimuli``: list[list[int|float]] — plaintexts to
      compare; default is two contrasting BFV-friendly vectors;
    - ``safe_timing_cv_threshold``: float — coefficient-of-variation
      threshold (default 0.05). Lower = stricter (more false-VULNERABLE);
    - ``replay_seed``: int — recorded in evidence for reproducibility.

    A ``VULNERABLE`` verdict from the live distinguisher is stronger than
    one from the fingerprint risk-check; the ``intent_actual`` field in
    evidence makes the distinction explicit.
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
            return self._safe_constant_time(adapter, ctx, fp)

        seal_family = "seal" in implementation or "tenseal" in implementation
        openfhe_family = "openfhe" in implementation
        in_scope = (seal_family or openfhe_family) and ntt_variant in _NON_CONSTANT_NTTS

        live_disabled = bool(ctx.params.get("disable_live_replay", False))
        if in_scope and not live_disabled and self._can_live_replay(adapter, ctx):
            try:
                return self._run_replay(adapter, ctx, fp, seal_family=seal_family)
            except NotImplementedError:
                # Adapter advertised live capability but cannot actually
                # encrypt/decrypt the chosen stimuli (e.g. CKKS-only adapter
                # with integer-only stimuli). Fall back to the fingerprint
                # risk-check verdict instead of reporting ERROR.
                pass

        if in_scope:
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
                    "intent_actual": AttackIntent.RISK_CHECK.value,
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

    # --------------------------------------------------------------- helpers
    def _safe_constant_time(
        self,
        adapter: LibraryAdapter,
        ctx: AdapterContext,
        fp: dict[str, Any],
    ) -> AttackResult:
        return AttackResult(
            attack=self.id,
            library=adapter.name,
            scheme=ctx.scheme,
            status=AttackStatus.SAFE,
            duration_seconds=0.0,
            evidence={
                "mode": "risk_check",
                "intent_actual": AttackIntent.RISK_CHECK.value,
                "evaluator_fingerprint": fp,
                "rationale": "Adapter advertises constant-time decrypt path.",
            },
            message="Target advertises constant-time decrypt; no leak surface for this attack.",
        )

    @staticmethod
    def _can_live_replay(adapter: LibraryAdapter, ctx: AdapterContext) -> bool:
        """Return True when ``adapter`` can drive the live timing replay."""
        cap = getattr(adapter, "capability", None)
        if cap is None or not getattr(cap, "live_oracle", False):
            return False
        if not adapter.supports(ctx.scheme):
            return False
        if not adapter.is_available():
            return False
        return True

    # ------------------------------------------------------- live replay --
    def _replay_config(
        self, ctx: AdapterContext
    ) -> tuple[int, tuple[Any, ...], float, int | None]:
        params = ctx.params
        repeats = max(2, int(params.get("replay_timing_repeats", _DEFAULT_TIMING_REPEATS)))
        stimuli_raw = params.get("replay_timing_stimuli", _DEFAULT_TIMING_STIMULI)
        stimuli = tuple(stimuli_raw)
        if len(stimuli) < 2:
            raise ValueError(
                "replay_timing_stimuli must contain at least two stimulus "
                "plaintexts so the discriminator has groups to compare."
            )
        cv_threshold = float(params.get("safe_timing_cv_threshold", _DEFAULT_TIMING_CV_THRESHOLD))
        if cv_threshold <= 0:
            raise ValueError(
                "safe_timing_cv_threshold must be > 0; got "
                f"{params['safe_timing_cv_threshold']!r}."
            )
        seed_raw = params.get("replay_seed")
        seed = int(seed_raw) if seed_raw is not None else None
        return repeats, stimuli, cv_threshold, seed

    def _run_replay(
        self,
        adapter: LibraryAdapter,
        ctx: AdapterContext,
        fp: dict[str, Any],
        *,
        seal_family: bool,
    ) -> AttackResult:
        started = time.monotonic()
        repeats, stimuli, cv_threshold, seed = self._replay_config(ctx)

        # Encrypt each stimulus once; reuse the same ciphertext across
        # repeats so timing variance reflects the decrypt path, not the
        # adapter's encrypt RNG. The Cheon attack uses a similar trick.
        ciphertexts = [adapter.encrypt(ctx, list(stim)) for stim in stimuli]

        # Warm up: the first decrypt() call typically pays JIT / cache /
        # allocator costs that swamp the leak signal. Drop two warmups
        # per ciphertext from the timed sample.
        for ct in ciphertexts:
            adapter.decrypt(ctx, ct)
            adapter.decrypt(ctx, ct)

        per_stim_means: list[float] = []
        per_stim_stdevs: list[float] = []
        per_stim_samples: list[list[float]] = []
        for ct in ciphertexts:
            samples_ns: list[int] = []
            for _ in range(repeats):
                t0 = time.perf_counter_ns()
                adapter.decrypt(ctx, ct)
                samples_ns.append(time.perf_counter_ns() - t0)
            samples_s = [s / 1e9 for s in samples_ns]
            per_stim_samples.append(samples_s)
            per_stim_means.append(statistics.fmean(samples_s))
            per_stim_stdevs.append(
                statistics.pstdev(samples_s) if len(samples_s) > 1 else 0.0
            )

        slower = max(per_stim_means)
        spread = max(per_stim_means) - min(per_stim_means)
        cv_observed = spread / slower if slower > 0 else 0.0
        leakage_detected = cv_observed > cv_threshold
        duration = time.monotonic() - started

        evidence: dict[str, Any] = {
            "mode": "replay",
            "intent_actual": AttackIntent.REPLAY.value,
            "evaluator_fingerprint": fp,
            "test": "decrypt_timing_distinguisher",
            "repeats_per_stimulus": repeats,
            "n_stimuli": len(stimuli),
            "stimuli_summary": [self._summarize_stimulus(s) for s in stimuli],
            "per_stimulus_mean_seconds": per_stim_means,
            "per_stimulus_stdev_seconds": per_stim_stdevs,
            "spread_seconds": spread,
            "cv_observed": cv_observed,
            "cv_threshold": cv_threshold,
            "leakage_detected": leakage_detected,
            "replay_seed": seed,
            "library": adapter.name,
            "library_class": "production",
            "citation": self.citation.url if self.citation else "",
        }

        if leakage_detected:
            known_surface = (
                "SEAL NTT guard/mul_root non-constant-time path"
                if seal_family
                else "OpenFHE NativeMath Harvey-butterfly NTT"
            )
            evidence["known_surface"] = known_surface
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.VULNERABLE,
                duration_seconds=duration,
                evidence=evidence,
                message=(
                    "Live timing distinguisher: per-stimulus mean decrypt "
                    f"times differ by {spread*1e6:.1f}µs ({cv_observed*100:.1f}% "
                    f"of the slower group's mean), exceeding the "
                    f"{cv_threshold*100:.1f}% safe threshold. Decrypt path "
                    "leaks data-dependent timing — matches the ePrint "
                    "2025/867 SEAL/OpenFHE NTT guard/mul_root surface."
                ),
            )

        return AttackResult(
            attack=self.id,
            library=adapter.name,
            scheme=ctx.scheme,
            status=AttackStatus.SAFE,
            duration_seconds=duration,
            evidence=evidence,
            message=(
                "Live timing distinguisher: per-stimulus mean decrypt times "
                f"differ by only {cv_observed*100:.2f}% of the slower group's "
                f"mean (threshold={cv_threshold*100:.1f}%); no exploitable "
                "data-dependent timing observed in this run. Repeat with "
                "more stimuli or higher repeats for stronger assurance."
            ),
        )

    @staticmethod
    def _summarize_stimulus(stim: Any) -> dict[str, Any]:
        """Return a small JSON-safe summary of a stimulus plaintext."""
        try:
            length = len(stim)
        except TypeError:
            length = None
        return {
            "type": type(stim).__name__,
            "length": length,
            "first": stim[0] if length else None,
            "last": stim[-1] if length else None,
        }
