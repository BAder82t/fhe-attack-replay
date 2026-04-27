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


class TfheRsAdapter(LibraryAdapter):
    """Adapter for zama-ai/tfhe-rs (Rust).

    tfhe-rs is Rust-only; this adapter shells out to a Rust helper binary
    (`fhe-replay-tfhe-rs-helper`) built from `vendor/tfhe-rs-helper/`.
    """

    name = "tfhe-rs"
    capability = AdapterCapability(
        schemes=("TFHE",),
        requires_native=True,
        notes="Requires fhe-replay-tfhe-rs-helper on PATH (build from vendor/tfhe-rs-helper).",
    )

    HELPER_BINARY = "fhe-replay-tfhe-rs-helper"

    def is_available(self) -> bool:
        return shutil.which(self.HELPER_BINARY) is not None

    def setup(self, scheme: str, params: dict[str, Any]) -> AdapterContext:
        if not self.is_available():
            raise RuntimeError(
                f"{self.HELPER_BINARY} is not on PATH. "
                "Build it from vendor/tfhe-rs-helper or download a release binary."
            )
        raise NotImplementedError(
            "TfheRsAdapter.setup is a scaffold; helper protocol wired in iteration 1."
        )

    def encrypt(self, ctx: AdapterContext, plaintext: Any) -> Any:
        raise NotImplementedError

    def decrypt(self, ctx: AdapterContext, ciphertext: Any) -> Any:
        raise NotImplementedError

    def evaluator_fingerprint(self, ctx: AdapterContext) -> dict[str, Any]:
        return {
            "implementation": "zama-ai/tfhe-rs",
            "ntt_variant": "n/a",
            "constant_time_decrypt": True,
        }
