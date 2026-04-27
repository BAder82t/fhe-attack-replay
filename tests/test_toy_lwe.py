# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Round-trip and oracle-randomization tests for the toy-lwe cryptosystem."""

from __future__ import annotations

import numpy as np
import pytest

from fhe_attack_replay.lab.toy_lwe import ToyLWE, bisect_decrypt_boundary


@pytest.mark.parametrize("m", [0, 1, 2, 7, 15])
def test_round_trip_decrypts_correctly_without_flooding(m: int):
    toy = ToyLWE(n=32, q=1 << 20, t=16, sigma=3.2, noise_flooding_sigma=0.0)
    rng = np.random.default_rng(42)
    keys = toy.keygen(rng)
    ct = toy.encrypt(keys, m, rng)
    assert toy.decrypt(keys, ct) == m


def test_decrypt_is_deterministic_without_flooding():
    toy = ToyLWE(n=32, q=1 << 20, t=16, sigma=3.2, noise_flooding_sigma=0.0)
    rng = np.random.default_rng(0)
    keys = toy.keygen(rng)
    ct = toy.encrypt(keys, 5, rng)
    decryptions = {toy.decrypt(keys, ct) for _ in range(20)}
    assert decryptions == {5}


def test_bisect_recovers_consistent_boundary_without_flooding():
    toy = ToyLWE(n=32, q=1 << 20, t=16, sigma=3.2, noise_flooding_sigma=0.0)
    rng = np.random.default_rng(0)
    keys = toy.keygen(rng)
    ct0 = toy.encrypt(keys, 0, rng)
    boundaries = [bisect_decrypt_boundary(toy, keys, ct0, rng) for _ in range(8)]
    # Without noise flooding, the boundary is fully determined by the encryption
    # noise of `ct0` and is therefore identical across all trials.
    assert len(set(boundaries)) == 1


def test_bisect_varies_with_noise_flooding():
    toy = ToyLWE(n=32, q=1 << 20, t=16, sigma=3.2, noise_flooding_sigma=float(1 << 14))
    rng = np.random.default_rng(0)
    keys = toy.keygen(rng)
    ct0 = toy.encrypt(keys, 0, rng)
    boundaries = [bisect_decrypt_boundary(toy, keys, ct0, rng) for _ in range(8)]
    # With noise flooding comparable to delta/4, the recovered boundary is a
    # random variable across trials.
    assert len(set(boundaries)) > 1
