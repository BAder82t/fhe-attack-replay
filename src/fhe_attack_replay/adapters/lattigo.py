# Copyright 2026 Vaultbytes (Bader Issaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import shutil
from typing import Any

from fhe_attack_replay.adapters.base import (
    AdapterCapability,
    AdapterContext,
    LibraryAdapter,
)


class LattigoAdapter(LibraryAdapter):
    """Adapter for tuneinsight/lattigo (Go).

    Lattigo is a Go library; this adapter shells out to a Go helper binary
    bundled with the harness (`fhe-replay-lattigo-helper`) that exposes the
    primitives the harness needs over a JSON protocol on stdin/stdout.
    The helper binary is built from `vendor/lattigo-helper/` and lives on PATH.
    """

    name = "lattigo"
    capability = AdapterCapability(
        schemes=("BFV", "BGV", "CKKS"),
        requires_native=True,
        notes="Requires fhe-replay-lattigo-helper on PATH (build from vendor/lattigo-helper).",
    )

    HELPER_BINARY = "fhe-replay-lattigo-helper"

    def is_available(self) -> bool:
        return shutil.which(self.HELPER_BINARY) is not None

    def setup(self, scheme: str, params: dict[str, Any]) -> AdapterContext:
        if not self.is_available():
            raise RuntimeError(
                f"{self.HELPER_BINARY} is not on PATH. "
                "Build it from vendor/lattigo-helper or download a release binary."
            )
        raise NotImplementedError(
            "LattigoAdapter.setup is a scaffold; helper protocol wired in iteration 1."
        )

    def encrypt(self, ctx: AdapterContext, plaintext: Any) -> Any:
        raise NotImplementedError

    def decrypt(self, ctx: AdapterContext, ciphertext: Any) -> Any:
        raise NotImplementedError

    def evaluator_fingerprint(self, ctx: AdapterContext) -> dict[str, Any]:
        return {
            "implementation": "tuneinsight/lattigo",
            "ntt_variant": "unknown",
            "constant_time_decrypt": False,
        }
