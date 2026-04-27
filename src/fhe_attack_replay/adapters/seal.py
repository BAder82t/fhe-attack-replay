# Copyright 2026 Vaultbytes (Bader Issaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
from typing import Any

from fhe_attack_replay.adapters.base import (
    AdapterCapability,
    AdapterContext,
    LibraryAdapter,
)


class SEALAdapter(LibraryAdapter):
    """Adapter for microsoft/SEAL via the OpenMined TenSEAL bindings.

    Pure SEAL has no first-party Python bindings; TenSEAL provides a
    sufficiently complete CKKS/BFV surface for replay purposes.
    """

    name = "seal"
    capability = AdapterCapability(
        schemes=("BFV", "CKKS"),
        requires_native=True,
        notes="Requires `tenseal` (pip install tenseal) for SEAL bindings.",
    )

    def is_available(self) -> bool:
        return importlib.util.find_spec("tenseal") is not None

    def setup(self, scheme: str, params: dict[str, Any]) -> AdapterContext:
        if not self.is_available():
            raise RuntimeError(
                "tenseal is not installed. Run `pip install tenseal` to enable SEAL."
            )
        raise NotImplementedError(
            "SEALAdapter.setup is a scaffold; native setup wired in iteration 1."
        )

    def encrypt(self, ctx: AdapterContext, plaintext: Any) -> Any:
        raise NotImplementedError

    def decrypt(self, ctx: AdapterContext, ciphertext: Any) -> Any:
        raise NotImplementedError

    def evaluator_fingerprint(self, ctx: AdapterContext) -> dict[str, Any]:
        return {
            "implementation": "microsoft/SEAL via tenseal",
            "ntt_variant": "harvey-butterfly",
            "constant_time_decrypt": False,
        }
