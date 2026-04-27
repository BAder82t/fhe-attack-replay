# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any

from fhe_attack_replay.adapters.base import (
    AdapterCapability,
    AdapterContext,
    LibraryAdapter,
)
from fhe_attack_replay.lab.toy_lwe import ToyLWE, ToyLWEKeys


class ToyLWEAdapter(LibraryAdapter):
    """Adapter that wraps the in-tree toy LWE cryptosystem.

    Always available — no native dependency. Used by the harness to validate
    attack modules end-to-end in CI without an FHE library build. Verdicts
    produced against this adapter must be interpreted as a CI-level
    correctness check on the attack module, not as a production library
    audit. Modules surface this distinction in their result evidence.

    Recognized params (all optional):
      - n: secret-key dimension (default 32)
      - q: ciphertext modulus (default 2**20)
      - t: plaintext modulus (default 16)
      - sigma: encryption-error std dev (default 3.2)
      - noise_flooding_sigma: oracle re-randomization std dev (default 0.0)
        — when 0, the oracle is deterministic (Cheon-vulnerable);
        a value comparable to delta/4 mitigates the published attack.
      - seed: deterministic RNG seed (default 0)
    """

    name = "toy-lwe"
    capability = AdapterCapability(
        schemes=("LWE",),
        requires_native=False,
        live_oracle=True,
        notes=(
            "In-tree pure-Python LWE for CI validation only. Not "
            "cryptographically secure; do not use against real keys."
        ),
    )

    def is_available(self) -> bool:
        return True

    def setup(self, scheme: str, params: dict[str, Any]) -> AdapterContext:
        import numpy as np  # local import: numpy is a transitive runtime dep

        toy = ToyLWE(
            n=int(params.get("n", 32)),
            q=int(params.get("q", 1 << 20)),
            t=int(params.get("t", 16)),
            sigma=float(params.get("sigma", 3.2)),
            noise_flooding_sigma=float(params.get("noise_flooding_sigma", 0.0)),
        )
        rng = np.random.default_rng(int(params.get("seed", 0)))
        keys = toy.keygen(rng)
        return AdapterContext(
            library=self.name,
            scheme=scheme,
            params=params,
            handles={"toy": toy, "keys": keys, "rng": rng},
        )

    def encrypt(self, ctx: AdapterContext, plaintext: int) -> Any:
        toy: ToyLWE = ctx.handles["toy"]
        keys: ToyLWEKeys = ctx.handles["keys"]
        rng = ctx.handles["rng"]
        return toy.encrypt(keys, int(plaintext), rng)

    def decrypt(self, ctx: AdapterContext, ciphertext: Any) -> Any:
        toy: ToyLWE = ctx.handles["toy"]
        keys: ToyLWEKeys = ctx.handles["keys"]
        rng = ctx.handles["rng"]
        return toy.decrypt(keys, ciphertext, rng=rng)

    def evaluator_fingerprint(self, ctx: AdapterContext) -> dict[str, Any]:
        toy: ToyLWE = ctx.handles.get("toy") if ctx.handles else None
        sigma = float(getattr(toy, "noise_flooding_sigma", 0.0)) if toy else 0.0
        return {
            "implementation": "fhe-attack-replay toy-lwe (in-tree, not secure)",
            "ntt_variant": "n/a",
            "constant_time_decrypt": False,
            "noise_flooding_sigma": sigma,
        }
