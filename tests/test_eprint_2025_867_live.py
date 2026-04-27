# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Live-replay tests for eprint-2025-867.

The module ships three behaviours that need exercising:

1. Constant-time fingerprint short-circuits to ``SAFE`` (was already
   covered; reasserted here for completeness).
2. Live timing distinguisher reports ``VULNERABLE`` when per-stimulus
   decrypt times diverge beyond ``safe_timing_cv_threshold``.
3. Live distinguisher reports ``SAFE`` when decrypt timings are flat,
   even on a fingerprint that the conservative risk-check would mark
   ``VULNERABLE``.

The CI tests use synthetic in-tree adapters with controllable decrypt
timings — wall-clock noise on shared CI runners is unavoidable, so
relying on real OpenFHE timing for the discriminator's correctness
would make this suite flaky. The real-OpenFHE smoke test exists but
only asserts that the live path runs end-to-end and records evidence.
"""

from __future__ import annotations

import time

import pytest

from fhe_attack_replay import run
from fhe_attack_replay.adapters.base import (
    AdapterCapability,
    AdapterContext,
    LibraryAdapter,
)
from fhe_attack_replay.attacks.base import AttackIntent, AttackStatus
from fhe_attack_replay.attacks.eprint_2025_867 import Eprint2025_867
from fhe_attack_replay.registry import _ADAPTERS


class _FakeNTTAdapter(LibraryAdapter):
    """Synthetic adapter that fakes a SEAL-flavoured NTT fingerprint.

    Two knobs control the in-test discriminator behaviour:

    - ``leak_per_unit_seconds`` — extra wall-clock time injected into
      ``decrypt`` per unit of ``ciphertext[0]``. Non-zero values create
      a data-dependent timing channel that the live distinguisher
      should detect.
    - ``base_decrypt_seconds`` — constant time floor so the test is
      independent of how fast the host CPU is.

    The fake fingerprint advertises the SEAL family + Harvey-butterfly
    NTT so the module's in-scope check fires; ``constant_time_decrypt``
    stays ``False`` so the live path is reached.
    """

    name = "fake-seal-nttt"
    capability = AdapterCapability(
        schemes=("BFV",), live_oracle=True, requires_native=False,
    )
    leak_per_unit_seconds: float = 0.0
    base_decrypt_seconds: float = 0.001

    def is_available(self) -> bool:
        return True

    def setup(self, scheme: str, params: dict) -> AdapterContext:
        return AdapterContext(
            library=self.name, scheme=scheme, params=params, handles={},
        )

    def encrypt(self, ctx: AdapterContext, plaintext) -> list[int]:
        # The "ciphertext" is just the plaintext list — keeps decrypt
        # arithmetic trivial so timing reflects only the sleep call.
        return list(plaintext)

    def decrypt(self, ctx: AdapterContext, ciphertext) -> list[int]:
        first = float(ciphertext[0]) if ciphertext else 0.0
        time.sleep(self.base_decrypt_seconds + self.leak_per_unit_seconds * first)
        return list(ciphertext)

    def evaluator_fingerprint(self, ctx: AdapterContext) -> dict:
        # Mirrors the real adapters' pattern: ``constant_time_decrypt``
        # is sourced from the user's params so hardened-build overrides
        # work uniformly across adapter implementations.
        return {
            "implementation": "microsoft/SEAL via tenseal",
            "ntt_variant": "harvey-butterfly",
            "constant_time_decrypt": bool(
                ctx.params.get("constant_time_decrypt", False)
            ),
            "scheme": ctx.scheme,
        }


@pytest.fixture()
def install_fake_adapter():
    """Register a fresh fake-adapter class in the global registry per test.

    The registry stores adapter classes (callables that produce an
    instance on demand) so we install ``_FakeNTTAdapter`` itself rather
    than an instance. To keep timing knobs tweakable per-test we make
    the class attributes mutable; tests assign on the yielded class.
    Restored on teardown so other tests see the original registry.
    """
    original = _ADAPTERS.get(_FakeNTTAdapter.name)

    # Reset class-level knobs to defaults each test for isolation.
    _FakeNTTAdapter.leak_per_unit_seconds = 0.0
    _FakeNTTAdapter.base_decrypt_seconds = 0.001
    _ADAPTERS[_FakeNTTAdapter.name] = _FakeNTTAdapter
    try:
        yield _FakeNTTAdapter
    finally:
        if original is None:
            _ADAPTERS.pop(_FakeNTTAdapter.name, None)
        else:
            _ADAPTERS[_FakeNTTAdapter.name] = original


# ---------------------------------------------------------------------------
# Live distinguisher — VULNERABLE when timing leaks beyond threshold
# ---------------------------------------------------------------------------


def test_live_distinguisher_marks_leaky_decrypt_vulnerable(install_fake_adapter):
    """A fake adapter whose decrypt time grows with ciphertext value
    crosses the 5% CV threshold and the live path reports VULNERABLE."""
    install_fake_adapter.base_decrypt_seconds = 0.001
    # 1 unit of ciphertext[0] adds 0.5ms — well above 5% of 1ms.
    install_fake_adapter.leak_per_unit_seconds = 0.0005
    report = run(
        library=install_fake_adapter.name,
        params={
            "scheme": "BFV",
            "replay_timing_repeats": 8,
            # Two stimuli with very different first elements.
            "replay_timing_stimuli": [[0, 0, 0, 0], [10, 0, 0, 0]],
        },
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.evidence["mode"] == "replay"
    assert r.evidence["intent_actual"] == AttackIntent.REPLAY.value
    assert r.evidence["test"] == "decrypt_timing_distinguisher"
    assert r.evidence["leakage_detected"] is True
    assert r.status is AttackStatus.VULNERABLE
    assert "known_surface" in r.evidence


def test_live_distinguisher_marks_constant_decrypt_safe(install_fake_adapter):
    """Adapter with no per-unit leak shows flat per-stimulus means → SAFE."""
    install_fake_adapter.base_decrypt_seconds = 0.0005
    install_fake_adapter.leak_per_unit_seconds = 0.0  # no leak
    report = run(
        library=install_fake_adapter.name,
        params={
            "scheme": "BFV",
            "replay_timing_repeats": 16,
            "replay_timing_stimuli": [[0, 0, 0, 0], [255, 0, 0, 0]],
            # Tighten the threshold so this test is sensitive but stays
            # above the host's per-call jitter floor (≈10–50µs on CI).
            "safe_timing_cv_threshold": 0.20,
        },
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.evidence["mode"] == "replay"
    assert r.evidence["leakage_detected"] is False
    assert r.status is AttackStatus.SAFE


# ---------------------------------------------------------------------------
# Configuration — disable_live_replay falls through to risk-check
# ---------------------------------------------------------------------------


def test_disable_live_replay_falls_through_to_risk_check(install_fake_adapter):
    install_fake_adapter.leak_per_unit_seconds = 0.0005
    report = run(
        library=install_fake_adapter.name,
        params={
            "scheme": "BFV",
            "disable_live_replay": True,
        },
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.evidence["mode"] == "risk_check"
    assert r.status is AttackStatus.VULNERABLE


# ---------------------------------------------------------------------------
# Configuration — invalid params raise ValueError before any timing
# ---------------------------------------------------------------------------


def test_replay_rejects_single_stimulus(install_fake_adapter):
    report = run(
        library=install_fake_adapter.name,
        params={
            "scheme": "BFV",
            "replay_timing_stimuli": [[0, 0, 0, 0]],
            "replay_timing_repeats": 4,
        },
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    # The runner wraps ValueError as ERROR; module did not silently fall
    # through to risk-check, so users misconfiguring stimuli get a clear
    # signal rather than a misleading SAFE/VULNERABLE.
    assert r.status is AttackStatus.ERROR
    assert "two stimulus" in r.message


def test_replay_rejects_zero_threshold(install_fake_adapter):
    report = run(
        library=install_fake_adapter.name,
        params={
            "scheme": "BFV",
            "safe_timing_cv_threshold": 0.0,
        },
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.ERROR
    assert "must be > 0" in r.message


# ---------------------------------------------------------------------------
# Constant-time short-circuit still works (regression guard)
# ---------------------------------------------------------------------------


def test_constant_time_overrides_live_distinguisher(install_fake_adapter):
    install_fake_adapter.leak_per_unit_seconds = 0.001  # huge leak
    report = run(
        library=install_fake_adapter.name,
        params={
            "scheme": "BFV",
            "constant_time_decrypt": True,
        },
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.SAFE
    assert r.evidence["mode"] == "risk_check"
    assert "constant-time" in r.evidence["rationale"]


# ---------------------------------------------------------------------------
# Out-of-scope adapter (e.g. toy-lwe) does not engage the live path
# ---------------------------------------------------------------------------


def test_toy_lwe_does_not_engage_live_distinguisher():
    """Toy-LWE's fingerprint advertises ``ntt_variant=n/a`` so the
    in-scope check fails before the live path; module returns
    NOT_IMPLEMENTED."""
    report = run(
        library="toy-lwe",
        params={"scheme": "LWE"},
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    # eprint-2025-867 only applies to BFV/BGV/CKKS — the runner short-
    # circuits to SKIPPED before the attack even runs because LWE is not
    # in applies_to_schemes.
    assert r.status is AttackStatus.SKIPPED


# ---------------------------------------------------------------------------
# Real OpenFHE smoke test — runs the live path end-to-end
# ---------------------------------------------------------------------------


def test_live_distinguisher_runs_against_real_openfhe():
    """Smoke-test the live timing distinguisher against real OpenFHE BFV.

    Only asserts evidence shape, not the verdict — wall-clock timing on
    shared CI is too noisy for a deterministic VULNERABLE/SAFE check.
    The unit-test fakes above exercise both verdicts deterministically.
    """
    pytest.importorskip("openfhe")
    report = run(
        library="openfhe",
        params={
            "scheme": "BFV",
            "constant_time_decrypt": False,
            "replay_timing_repeats": 16,
        },
        attacks=["eprint-2025-867"],
    )
    r = report.results[0]
    assert r.evidence["mode"] == "replay"
    assert r.evidence["test"] == "decrypt_timing_distinguisher"
    assert r.evidence["repeats_per_stimulus"] == 16
    assert r.evidence["n_stimuli"] >= 2
    assert len(r.evidence["per_stimulus_mean_seconds"]) == r.evidence["n_stimuli"]
    assert isinstance(r.evidence["cv_observed"], float)
    assert r.evidence["cv_threshold"] == 0.05
    # Library + duration metadata.
    assert r.evidence["library"] == "openfhe"
    assert r.evidence["library_class"] == "production"
    assert r.duration_seconds > 0.0


# ---------------------------------------------------------------------------
# Helpers / introspection
# ---------------------------------------------------------------------------


def test_summarize_stimulus_handles_short_lists():
    summary = Eprint2025_867._summarize_stimulus([1, 2, 3])
    assert summary == {"type": "list", "length": 3, "first": 1, "last": 3}


def test_can_live_replay_false_when_capability_missing():
    class _NoCap:
        capability = None

        def is_available(self):
            return True

        def supports(self, scheme):
            return True

    assert Eprint2025_867._can_live_replay(
        _NoCap(),
        AdapterContext(library="x", scheme="BFV", params={}),
    ) is False


def test_can_live_replay_false_when_scheme_unsupported():
    class _NoScheme:
        capability = AdapterCapability(schemes=("BFV",), live_oracle=True)

        def is_available(self):
            return True

        def supports(self, scheme):
            return False

    assert Eprint2025_867._can_live_replay(
        _NoScheme(),
        AdapterContext(library="x", scheme="CKKS", params={}),
    ) is False


def test_can_live_replay_false_when_unavailable():
    class _NotAvailable:
        capability = AdapterCapability(schemes=("BFV",), live_oracle=True)

        def is_available(self):
            return False

        def supports(self, scheme):
            return True

    assert Eprint2025_867._can_live_replay(
        _NotAvailable(),
        AdapterContext(library="x", scheme="BFV", params={}),
    ) is False


def test_summarize_stimulus_handles_objects_without_len():
    """Bare ints / floats raise TypeError in ``len()``; the helper
    records ``length=None`` and skips first/last so evidence stays
    JSON-safe even if a caller passes a malformed stimulus."""
    summary = Eprint2025_867._summarize_stimulus(42)
    assert summary == {"type": "int", "length": None, "first": None, "last": None}


def test_replay_falls_back_to_risk_check_on_inner_not_implemented():
    """An adapter whose decrypt raises NotImplementedError mid-replay
    must fall through to the fingerprint risk-check, not bubble up as
    ERROR."""

    class _BrokenLiveAdapter(LibraryAdapter):
        name = "fake-broken-live"
        capability = AdapterCapability(
            schemes=("BFV",), live_oracle=True, requires_native=False,
        )

        def is_available(self):
            return True

        def setup(self, scheme, params):
            return AdapterContext(library=self.name, scheme=scheme, params=params)

        def encrypt(self, ctx, plaintext):
            return list(plaintext)

        def decrypt(self, ctx, ciphertext):
            raise NotImplementedError("decrypt unavailable in this build")

        def evaluator_fingerprint(self, ctx):
            return {
                "implementation": "openfheorg/openfhe-development via openfhe-python",
                "ntt_variant": "harvey-butterfly",
                "constant_time_decrypt": False,
            }

    original = _ADAPTERS.get("fake-broken-live")
    _ADAPTERS["fake-broken-live"] = _BrokenLiveAdapter
    try:
        report = run(
            library="fake-broken-live",
            params={"scheme": "BFV"},
            attacks=["eprint-2025-867"],
        )
    finally:
        if original is None:
            _ADAPTERS.pop("fake-broken-live", None)
        else:
            _ADAPTERS["fake-broken-live"] = original
    r = report.results[0]
    assert r.evidence["mode"] == "risk_check"
    assert r.status is AttackStatus.VULNERABLE
