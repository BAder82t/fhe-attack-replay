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


class OpenFHEAdapter(LibraryAdapter):
    """Adapter for openfheorg/openfhe-development via the openfhe-python bindings."""

    name = "openfhe"
    capability = AdapterCapability(
        schemes=("BFV", "BGV", "CKKS"),
        requires_native=True,
        notes="Requires openfhe-python (https://github.com/openfheorg/openfhe-python).",
    )

    def is_available(self) -> bool:
        return importlib.util.find_spec("openfhe") is not None

    def setup(self, scheme: str, params: dict[str, Any]) -> AdapterContext:
        if not self.is_available():
            raise RuntimeError(
                "openfhe-python is not installed. "
                "Install it from https://github.com/openfheorg/openfhe-python "
                "or run `pip install openfhe`."
            )
        raise NotImplementedError(
            "OpenFHEAdapter.setup is a scaffold; native setup wired in iteration 1."
        )

    def encrypt(self, ctx: AdapterContext, plaintext: Any) -> Any:
        raise NotImplementedError

    def decrypt(self, ctx: AdapterContext, ciphertext: Any) -> Any:
        raise NotImplementedError

    def evaluator_fingerprint(self, ctx: AdapterContext) -> dict[str, Any]:
        return {
            "implementation": "openfhe",
            "ntt_variant": "unknown",
            "constant_time_decrypt": False,
        }
