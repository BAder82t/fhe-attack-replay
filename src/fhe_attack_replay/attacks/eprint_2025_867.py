# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import statistics
import time
from pathlib import Path
from typing import Any

from fhe_attack_replay.adapters.base import AdapterContext, LibraryAdapter
from fhe_attack_replay.attacks._correlation import analyze_models, parse_trace_file
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

# Pearson |ρ| above which the ArtifactCheck analyzer concludes the
# trace leaks the modelled NTT-tap intermediate. Same conservative
# floor as reveal-2023-1128; the published 2025/867 paper reports
# correlations well above 0.7 on FPGA / Cortex-M targets.
_DEFAULT_ARTIFACT_CORR_THRESHOLD = 0.5


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

    **Scope of the live distinguisher.** This module times either
    :meth:`adapter.decrypt` (default) or
    ``Evaluator.transform_to_ntt_inplace`` (when the adapter exposes a
    ``transform_to_ntt`` method and its fingerprint advertises
    ``exposes_per_ntt_timing``) — today only the ``seal-python``
    adapter offers the per-NTT primitive; ``openfhe-python`` and
    ``TenSEAL`` (verified against openfhe-python ``v1.5.1.0`` / upstream
    HEAD 2026-04-10 and TenSEAL 0.3.16) do not expose a comparable
    surface, so the eprint-2025-867 replay falls back to whole-decrypt
    timing for those backends. None of the three Python bindings
    expose **per-NTT-butterfly** granularity (the level the published
    paper actually attacks); upstream ``TimeVar``/``TIC``/``TOC``
    instrumentation in OpenFHE is confined to standalone benchmark
    executables in ``src/core/extras/`` and SEAL has no equivalent.

    Note that the published RevEAL (ePrint 2022/204) and ePrint
    2025/867 attacks are **power / EM side channels** captured on
    FPGA / Cortex-M targets — not software-timing attacks. This
    module's live distinguisher is a software-timing analog: a
    ``VULNERABLE`` verdict shows the implementation has a measurable
    data-dependent timing channel; a ``SAFE`` verdict only attests
    that the timing channel was flat across the supplied stimuli on
    this run. For hardware-grade evidence at the published
    methodology's resolution, capture traces externally and feed them
    to :class:`reveal-2023-1128` via ``--evidence trace=PATH`` —
    that module ships an in-tree Pearson correlation analyzer that
    consumes the same trace formats real SCA rigs produce.
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
        # ArtifactCheck path takes precedence: when the analyst supplies
        # a power/EM trace, that's stronger evidence than the live
        # software-timing distinguisher (which is only an analog of the
        # published power/EM attacks). The analyzer body is the shared
        # Pearson |ρ| from `attacks._correlation`, same as reveal.
        if self._artifact_path_available(ctx):
            return self._run_artifact_check(adapter, ctx)

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

        # Prefer per-NTT-call timing when the adapter exposes
        # ``transform_to_ntt`` (today: seal-python). The whole-decrypt
        # fallback stays as the default; the seal-python path delivers
        # ~10⁵× finer granularity by isolating the NTT phase from the
        # rest of decrypt.
        ntt_op = getattr(adapter, "transform_to_ntt", None)
        ntt_capable = callable(ntt_op) and bool(
            fp.get("exposes_per_ntt_timing", False)
        )

        # Encrypt each stimulus once; reuse the same ciphertext across
        # repeats so timing variance reflects the measured operation,
        # not the adapter's encrypt RNG.
        ciphertexts = [adapter.encrypt(ctx, list(stim)) for stim in stimuli]

        # Choose the per-trial measurement primitive.
        if ntt_capable:
            test_label = "transform_to_ntt_timing_distinguisher"
            measured_op = "Evaluator.transform_to_ntt_inplace"

            def _time_one(ct: Any) -> int:
                t0 = time.perf_counter_ns()
                ntt_op(ctx, ct)
                return time.perf_counter_ns() - t0
        else:
            test_label = "decrypt_timing_distinguisher"
            measured_op = "adapter.decrypt"

            def _time_one(ct: Any) -> int:
                t0 = time.perf_counter_ns()
                adapter.decrypt(ctx, ct)
                return time.perf_counter_ns() - t0

        # Warm up: the first call typically pays JIT / cache / allocator
        # costs that swamp the leak signal. Drop two warmups per
        # ciphertext from the timed sample.
        for ct in ciphertexts:
            _time_one(ct)
            _time_one(ct)

        per_stim_means: list[float] = []
        per_stim_stdevs: list[float] = []
        per_stim_samples: list[list[float]] = []
        for ct in ciphertexts:
            samples_ns = [_time_one(ct) for _ in range(repeats)]
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
            "test": test_label,
            "measured_op": measured_op,
            "ntt_capable": ntt_capable,
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

        op_label = "NTT" if ntt_capable else "decrypt"

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
                    f"Live timing distinguisher ({measured_op}): per-stimulus "
                    f"mean {op_label} times differ by {spread*1e6:.1f}µs "
                    f"({cv_observed*100:.1f}% of the slower group's mean), "
                    f"exceeding the {cv_threshold*100:.1f}% safe threshold. "
                    f"{op_label} path leaks data-dependent timing — matches "
                    "the ePrint 2025/867 SEAL/OpenFHE NTT guard/mul_root "
                    "surface."
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
                f"Live timing distinguisher ({measured_op}): per-stimulus "
                f"mean {op_label} times differ by only {cv_observed*100:.2f}% "
                f"of the slower group's mean (threshold="
                f"{cv_threshold*100:.1f}%); no exploitable data-dependent "
                "timing observed in this run. Repeat with more stimuli or "
                "higher repeats for stronger assurance."
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

    # ---------------------------------------------------- artifact check --
    @staticmethod
    def _artifact_path_available(ctx: AdapterContext) -> bool:
        """True iff a `--evidence trace=PATH` was supplied for this run."""
        evidence_paths = ctx.params.get("evidence_paths") or {}
        return bool(evidence_paths.get("trace"))

    def _run_artifact_check(
        self, adapter: LibraryAdapter, ctx: AdapterContext
    ) -> AttackResult:
        """Pearson |ρ| analyzer over a user-supplied power/EM trace.

        The published 2025/867 attack is a power / EM single-trace
        attack against SEAL/OpenFHE NTT guard / mul_root surfaces.
        When the analyst captures such a trace externally and supplies
        the leakage-model intermediates as ``predictions`` arrays, this
        method runs the same Pearson |ρ| discriminator that
        ``reveal-2023-1128`` uses (shared via ``attacks._correlation``).

        Trace schema is identical to reveal-2023-1128:

            {
              "samples": [float, ...],
              "model": [{"label": "...", "predictions": [float, ...]}, ...]
            }

        Verdict logic:

            max |ρ| > correlation_threshold  → VULNERABLE
            max |ρ| ≤ correlation_threshold  → SAFE
        """
        started = time.monotonic()
        evidence_paths = ctx.params.get("evidence_paths") or {}
        trace_path_raw = evidence_paths["trace"]
        signature = (
            str(ctx.params.get("ntt_leakage_signature") or "").strip().lower()
        )

        common_evidence: dict[str, Any] = {
            "mode": "artifact_check",
            "intent_actual": AttackIntent.ARTIFACT_CHECK.value,
            "evidence_paths": {k: str(v) for k, v in evidence_paths.items()},
            "trace_source": "user-supplied via --evidence trace=PATH",
            "citation": self.citation.url if self.citation else "",
        }

        trace_path = Path(str(trace_path_raw)).expanduser()
        if not trace_path.exists():
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.ERROR,
                duration_seconds=time.monotonic() - started,
                evidence={**common_evidence, "trace_path": str(trace_path)},
                message=f"Trace file not found at {trace_path!s}.",
            )
        size_bytes = trace_path.stat().st_size
        common_evidence.update(
            {"trace_path": str(trace_path), "trace_size_bytes": size_bytes}
        )
        if size_bytes == 0:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.ERROR,
                duration_seconds=time.monotonic() - started,
                evidence=common_evidence,
                message=f"Trace file at {trace_path!s} is empty.",
            )

        # Caller-supplied signature short-circuits the analyzer for
        # users with their own external pipeline (matches reveal's
        # `hamming_weight_signature` semantics).
        if signature == "recovered":
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.VULNERABLE,
                duration_seconds=time.monotonic() - started,
                evidence={**common_evidence, "ntt_leakage_signature": "recovered"},
                message=(
                    "ArtifactCheck: caller declares the supplied trace "
                    "exhibits the ePrint 2025/867 NTT guard/mul_root "
                    "leakage signature. Treat the SEAL/OpenFHE build as "
                    "vulnerable until a constant-time NTT replacement "
                    "lands."
                ),
            )
        if signature == "clean":
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.SAFE,
                duration_seconds=time.monotonic() - started,
                evidence={**common_evidence, "ntt_leakage_signature": "clean"},
                message=(
                    "ArtifactCheck: caller declares the supplied trace does "
                    "not exhibit the ePrint 2025/867 NTT leakage. Verdict "
                    "is only as strong as the user-side analysis."
                ),
            )

        try:
            samples, models = parse_trace_file(trace_path)
        except (ValueError, json.JSONDecodeError) as exc:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.ERROR,
                duration_seconds=time.monotonic() - started,
                evidence=common_evidence,
                message=f"Failed to parse trace {trace_path!s}: {exc}",
            )

        try:
            threshold = self._artifact_threshold(ctx)
        except ValueError as exc:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.ERROR,
                duration_seconds=time.monotonic() - started,
                evidence=common_evidence,
                message=str(exc),
            )

        scores = analyze_models(samples, models)
        ranked = sorted(scores, key=lambda s: abs(s["correlation"]), reverse=True)
        best = ranked[0]
        leakage_detected = abs(best["correlation"]) > threshold
        analyzer_evidence = {
            **common_evidence,
            "analyzer": "in_tree_pearson_correlation",
            "n_samples": len(samples),
            "n_models": len(models),
            "correlation_threshold": threshold,
            "best_model": best["label"],
            "best_correlation": best["correlation"],
            "all_model_scores": scores,
        }

        if leakage_detected:
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.VULNERABLE,
                duration_seconds=time.monotonic() - started,
                evidence=analyzer_evidence,
                message=(
                    "ArtifactCheck Pearson |ρ| analyzer: best model "
                    f"{best['label']!r} matched the trace with "
                    f"|ρ|={abs(best['correlation']):.3f} (> "
                    f"{threshold:.3f} threshold). Trace exhibits the "
                    "ePrint 2025/867 NTT-tap leakage signature; treat the "
                    "SEAL/OpenFHE build as vulnerable until a "
                    "constant-time NTT replacement lands."
                ),
            )

        return AttackResult(
            attack=self.id,
            library=adapter.name,
            scheme=ctx.scheme,
            status=AttackStatus.SAFE,
            duration_seconds=time.monotonic() - started,
            evidence=analyzer_evidence,
            message=(
                "ArtifactCheck Pearson |ρ| analyzer: best model "
                f"{best['label']!r} achieved |ρ|="
                f"{abs(best['correlation']):.3f} (≤ {threshold:.3f} "
                "threshold). No exploitable single-trace leakage "
                "observed for the supplied models. Tune "
                "``eprint_867_correlation_threshold`` if the target is "
                "known to leak more weakly."
            ),
        )

    @staticmethod
    def _artifact_threshold(ctx: AdapterContext) -> float:
        threshold = float(
            ctx.params.get(
                "eprint_867_correlation_threshold", _DEFAULT_ARTIFACT_CORR_THRESHOLD
            )
        )
        if not 0.0 < threshold <= 1.0:
            raise ValueError(
                "eprint_867_correlation_threshold must be in (0, 1]; got "
                f"{threshold!r}."
            )
        return threshold
