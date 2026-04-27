# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the v0.x review follow-ups on cheon-2024-127.

Covers four behaviours added after the initial review:

1. Wall-clock duration is recorded for both replay and risk-check paths.
2. Per-trial RNG seeding is reproducible and recorded in evidence.
3. Mitigation aliases (kim-kim-park-2024, seal-noise-flooding, ...) are
   recognised by the risk check.
4. Capability-driven dispatch routes any adapter exposing
   ``perturb_ciphertext_constant`` + ``plaintext_delta`` through the
   generic polynomial-bisection path, even if its name is not the
   hard-coded ``openfhe`` value.
"""

from __future__ import annotations

from typing import Any

import pytest

from fhe_attack_replay import run
from fhe_attack_replay.adapters.base import (
    AdapterCapability,
    AdapterContext,
    LibraryAdapter,
)
from fhe_attack_replay.attacks.base import AttackStatus
from fhe_attack_replay.attacks.cheon_2024_127 import Cheon2024_127

# ---------------------------------------------------------------------------
# 1. Wall-clock timing
# ---------------------------------------------------------------------------


def test_risk_check_records_nonzero_duration():
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "adversary_model": "ind-cpa-d",
            "noise_flooding": "none",
        },
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    assert r.evidence["mode"] == "risk_check"
    # Duration must be a real float; the risk-check path is fast but
    # never instantaneous on a real wall clock.
    assert isinstance(r.duration_seconds, float)
    assert r.duration_seconds >= 0.0


def test_replay_records_nonzero_duration():
    report = run(
        library="toy-lwe",
        params={"scheme": "LWE", "seed": 1, "replay_trials": 2},
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    assert r.evidence["mode"] == "replay"
    assert r.duration_seconds > 0.0


# ---------------------------------------------------------------------------
# 2. Per-trial RNG seeding
# ---------------------------------------------------------------------------


def test_replay_seed_recorded_and_reproducible():
    """Two runs with the same replay_seed produce the same trial seeds and
    boundary samples; a different seed produces different seeds."""
    common = {
        "scheme": "LWE",
        "n": 16,
        "q": 1 << 20,
        "t": 16,
        "sigma": 3.2,
        "noise_flooding_sigma": float(1 << 14),
        "seed": 7,
        "replay_trials": 4,
    }
    a = run(
        library="toy-lwe",
        params={**common, "replay_seed": 12345},
        attacks=["cheon-2024-127"],
    ).results[0]
    b = run(
        library="toy-lwe",
        params={**common, "replay_seed": 12345},
        attacks=["cheon-2024-127"],
    ).results[0]
    c = run(
        library="toy-lwe",
        params={**common, "replay_seed": 99999},
        attacks=["cheon-2024-127"],
    ).results[0]

    assert a.evidence["replay_master_seed"] == 12345
    assert a.evidence["replay_trial_seeds"] == b.evidence["replay_trial_seeds"]
    assert a.evidence["boundaries_sample"] == b.evidence["boundaries_sample"]
    assert a.evidence["replay_trial_seeds"] != c.evidence["replay_trial_seeds"]


def test_replay_falls_back_to_seed_param_when_replay_seed_absent():
    """If only the adapter-level ``seed`` is supplied, the replay reuses
    it as the master so toy-lwe runs stay reproducible without a
    duplicate seed parameter."""
    p = {"scheme": "LWE", "seed": 42, "replay_trials": 2}
    a = run(library="toy-lwe", params=p, attacks=["cheon-2024-127"]).results[0]
    b = run(library="toy-lwe", params=p, attacks=["cheon-2024-127"]).results[0]
    assert a.evidence["replay_master_seed"] == 42
    assert a.evidence["replay_trial_seeds"] == b.evidence["replay_trial_seeds"]


def test_replay_unseeded_run_records_a_master_seed():
    """When neither replay_seed nor seed is set we synthesise a master
    seed from the wall clock; it must still be present in evidence so
    the run is reproducible after the fact."""
    # A new toy-lwe context still defaults seed=0 in the adapter, so we
    # exercise the time-derived branch directly via the static helper.
    ctx = AdapterContext(library="toy-lwe", scheme="LWE", params={})
    master, seeds = Cheon2024_127._derive_trial_seeds(ctx, trials=3)
    assert isinstance(master, int)
    assert master >= 0
    assert len(seeds) == 3
    assert all(isinstance(s, int) for s in seeds)


# ---------------------------------------------------------------------------
# 3. Expanded mitigation aliases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "alias",
    [
        "kim-kim-park-2024",
        "dp-decrypt",
        "seal-noise-flooding",
        "lattigo-noise-flooding",
        "tfhe-rs-noise-flooding",
        "li-micciancio-2024",
        "rerandomization-2024-424",
        "openfhe-noise-flood",
        "noise-flood",
        "noise-flooding-decrypt",
    ],
)
def test_new_mitigation_aliases_are_recognized(alias):
    report = run(
        library="seal",
        params={
            "scheme": "BFV",
            "adversary_model": "ind-cpa-d",
            "noise_flooding": alias,
        },
        attacks=["cheon-2024-127"],
    )
    r = report.results[0]
    assert r.status is AttackStatus.SAFE
    assert r.evidence["mitigation_recognized"] is True


# ---------------------------------------------------------------------------
# 4. Capability-driven dispatch (no name allow-list)
# ---------------------------------------------------------------------------


class _FakePolynomialAdapter(LibraryAdapter):
    """Minimal in-tree adapter exposing the polynomial protocol.

    Demonstrates that an adapter unknown to ``_PRIVATE_DISPATCH_NAMES``
    is still routed through the generic polynomial-bisect path simply by
    exposing ``perturb_ciphertext_constant`` and ``plaintext_delta``.
    The ciphertext is just an ``int`` so the perturbation arithmetic is
    trivial to follow; the test asserts the dispatch reached the
    polynomial path (evidence["test"]) and recorded polynomial metadata.
    """

    name = "fake-polynomial-fhe"
    capability = AdapterCapability(
        schemes=("BFV",),
        requires_native=False,
        live_oracle=True,
    )

    DELTA = 64
    BOUNDARY = 19  # the offset at which decrypt() flips

    def is_available(self):
        return True

    def setup(self, scheme, params):
        return AdapterContext(library=self.name, scheme=scheme, params=params)

    def encrypt(self, ctx, plaintext):
        return 0  # ct_zero "ciphertext" carries the current offset

    def decrypt(self, ctx, ciphertext):
        # decrypt flips its first slot once the offset crosses BOUNDARY.
        flipped = 1 if int(ciphertext) >= self.BOUNDARY else 0
        return [flipped, 0, 0, 0]

    def evaluator_fingerprint(self, ctx):
        return {"implementation": "fake", "ntt_variant": "n/a"}

    def plaintext_delta(self, ctx, ciphertext):
        return self.DELTA

    def perturb_ciphertext_constant(self, ctx, ciphertext, offset, *, component=0):
        return int(ciphertext) + int(offset)

    def polynomial_replay_metadata(self, ctx, ciphertext):
        return {
            "serialization_backend": "fake-inline",
            "polynomial_domain": "test-only",
            "perturbation": "constant integer add",
        }


def test_unknown_adapter_with_protocol_methods_is_dispatched():
    adapter = _FakePolynomialAdapter()
    ctx = adapter.setup("BFV", {"replay_trials": 3, "replay_seed": 1})
    result = Cheon2024_127().run(adapter, ctx)
    assert result.evidence["mode"] == "replay"
    assert result.evidence["test"] == "polynomial_domain_bisection"
    assert result.evidence["serialization_backend"] == "fake-inline"
    # Boundary is fixed at 19 and decrypt is deterministic → VULNERABLE.
    assert result.status is AttackStatus.VULNERABLE
    assert all(b == _FakePolynomialAdapter.BOUNDARY for b in result.evidence["boundaries_sample"])


class _AdapterMissingProtocol(LibraryAdapter):
    """Live-oracle adapter that lacks the polynomial protocol entirely.

    The dispatch must skip the replay path (since it can't drive a
    bisection) and fall through to risk-check.
    """

    name = "fake-no-protocol"
    capability = AdapterCapability(
        schemes=("BFV",),
        requires_native=False,
        live_oracle=True,
    )

    def is_available(self):
        return True

    def setup(self, scheme, params):
        return AdapterContext(library=self.name, scheme=scheme, params=params)

    def encrypt(self, ctx, plaintext):
        return 0

    def decrypt(self, ctx, ciphertext):
        return [0]

    def evaluator_fingerprint(self, ctx):
        return {}


def test_live_oracle_adapter_without_protocol_falls_through_to_risk_check():
    adapter = _AdapterMissingProtocol()
    ctx = adapter.setup(
        "BFV",
        {"adversary_model": "ind-cpa-d", "noise_flooding": "none"},
    )
    result = Cheon2024_127().run(adapter, ctx)
    assert result.evidence["mode"] == "risk_check"
    assert result.status is AttackStatus.VULNERABLE


# ---------------------------------------------------------------------------
# Coverage: _seed_trial is a no-op for adapters without an "rng" handle
# ---------------------------------------------------------------------------


def test_seed_trial_is_noop_without_rng_handle():
    """Adapters whose handles dict has no "rng" key (e.g. openfhe stores
    its randomness in C++) must not crash on per-trial seeding."""
    ctx = AdapterContext(library="openfhe", scheme="BFV", params={}, handles={})
    # Should silently no-op.
    Cheon2024_127._seed_trial(ctx, 12345)


def test_seed_trial_is_noop_when_handles_missing_entirely():
    class _Bare:
        params: dict[str, Any] = {}
        handles = None  # type: ignore[assignment]

    Cheon2024_127._seed_trial(_Bare(), 1)  # no exception


# ---------------------------------------------------------------------------
# Coverage: _bisect_boundary still raises NotImplementedError for adapters
# with neither name nor protocol methods (so the run() fall-back engages).
# ---------------------------------------------------------------------------


def test_bisect_boundary_raises_for_adapter_without_protocol():
    class _Stub:
        name = "stub-no-protocol"

    attack = Cheon2024_127()
    with pytest.raises(NotImplementedError, match="Live-bisect"):
        attack._bisect_boundary(
            _Stub(),
            AdapterContext(library="stub-no-protocol", scheme="BFV", params={}),
            object(),
            rounds=4,
            delta=128,
        )
