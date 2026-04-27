# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""A deliberately small LWE-style cryptosystem used to validate attack modules.

This is **not** cryptographically secure. It exists so attack modules in
``fhe-attack-replay`` can be exercised end-to-end without a native FHE
library build. The decryption oracle here mirrors the IND-CPA-D model: the
caller may issue arbitrary `decrypt(ct)` queries; an optional
``noise_flooding_sigma`` re-randomizes the oracle in the manner of OpenFHE's
``NOISE_FLOODING_DECRYPT`` mode, which is what the Cheon-Hong-Kim 2024/127
attack targets.

The construction is plain LWE rather than full ring-LWE/BFV: it is enough to
demonstrate the oracle attack against unmitigated configurations and the
mitigation effect of noise flooding, without dragging in NTT plumbing.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class ToyLWEKeys:
    sk: np.ndarray  # secret key vector (binary, length n)


@dataclass(frozen=True)
class ToyLWECiphertext:
    a: np.ndarray  # random vector in Z_q^n
    b: int         # in Z_q


class ToyLWE:
    """Toy LWE cryptosystem.

    Parameters
    ----------
    n : int
        Secret-key dimension.
    q : int
        Ciphertext modulus.
    t : int
        Plaintext modulus. ``delta = q // t`` is the encoding scale.
    sigma : float
        Standard deviation of the encryption error distribution (Gaussian
        rounded to integer).
    noise_flooding_sigma : float
        Standard deviation of the *decryption-oracle* re-randomization. ``0``
        means the oracle is deterministic (Cheon-vulnerable); a value
        comparable to ``delta`` masks the oracle leak.
    """

    def __init__(
        self,
        n: int = 32,
        q: int = 1 << 20,
        t: int = 16,
        sigma: float = 3.2,
        noise_flooding_sigma: float = 0.0,
    ) -> None:
        if q % t != 0:
            raise ValueError("ToyLWE requires q to be a multiple of t.")
        self.n = n
        self.q = q
        self.t = t
        self.delta = q // t
        self.sigma = sigma
        self.noise_flooding_sigma = noise_flooding_sigma

    def keygen(self, rng: np.random.Generator) -> ToyLWEKeys:
        sk = rng.integers(0, 2, size=self.n, dtype=np.int64)
        return ToyLWEKeys(sk=sk)

    def encrypt(
        self, keys: ToyLWEKeys, m: int, rng: np.random.Generator
    ) -> ToyLWECiphertext:
        a = rng.integers(0, self.q, size=self.n, dtype=np.int64)
        e = int(round(rng.normal(0.0, self.sigma)))
        b = int((int(a @ keys.sk) + e + self.delta * (m % self.t)) % self.q)
        return ToyLWECiphertext(a=a, b=b)

    def decrypt(
        self,
        keys: ToyLWEKeys,
        ct: ToyLWECiphertext,
        rng: np.random.Generator | None = None,
    ) -> int:
        b_eff = ct.b
        if self.noise_flooding_sigma > 0.0:
            if rng is None:
                rng = np.random.default_rng()
            b_eff = int((b_eff + int(round(rng.normal(0.0, self.noise_flooding_sigma)))) % self.q)
        m_noisy = (b_eff - int(ct.a @ keys.sk)) % self.q
        # Round-to-nearest multiple of delta, then reduce mod t.
        return int(round(m_noisy / self.delta)) % self.t

    def perturb(self, ct: ToyLWECiphertext, delta: int) -> ToyLWECiphertext:
        """Return a new ciphertext with ``b`` shifted by ``delta`` mod q."""
        return ToyLWECiphertext(a=ct.a, b=int((ct.b + delta) % self.q))


def bisect_decrypt_boundary(
    toy: ToyLWE,
    keys: ToyLWEKeys,
    ct: ToyLWECiphertext,
    rng: np.random.Generator,
    rounds: int = 20,
) -> int:
    """Binary-search the smallest positive ``delta`` for which decryption flips.

    Starting from a ciphertext that decrypts to ``0``, this is the textbook
    Cheon-Hong-Kim 2024/127 noise-recovery primitive: without
    noise-flooding decrypt, the bisection converges to a fixed boundary that
    encodes the encryption noise of ``ct``. With noise flooding the oracle
    answers vary between calls, so the recovered boundary is a random
    variable rather than a fixed leak.

    Returns the recovered boundary in Z_q.
    """
    lo, hi = 0, toy.delta
    for _ in range(rounds):
        if hi - lo <= 1:
            break
        mid = (lo + hi) // 2
        ct_perturbed = toy.perturb(ct, mid)
        m_dec = toy.decrypt(keys, ct_perturbed, rng=rng)
        if m_dec == 0:
            lo = mid
        else:
            hi = mid
    return lo
