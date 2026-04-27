# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Adapter for zama-ai/tfhe-rs (Rust).

tfhe-rs is Rust-only; this adapter shells out to a Rust helper binary
(``fhe-replay-tfhe-rs-helper``, source under ``vendor/tfhe-rs-helper/``)
that exposes the primitives the harness needs over a JSON protocol on
stdin/stdout. Same contract as the lattigo adapter — see that module's
docstring for the wire format.

**Status**: helper is currently a scaffold (only ``hello`` and
``shutdown`` are implemented). Encrypt / decrypt / perturbation ops
surface as ``RuntimeError`` and the harness reports ``ERROR``.
"""

from __future__ import annotations

import shutil
from typing import Any

from fhe_attack_replay.adapters.base import (
    AdapterCapability,
    AdapterContext,
    LibraryAdapter,
)

# Re-use the lattigo adapter's _HelperProcess + protocol guard. Same
# wire format, same error semantics, no point duplicating it.
from fhe_attack_replay.adapters.lattigo import _HelperProcess

_PROTOCOL_VERSION = "0.1.0"


class TfheRsAdapter(LibraryAdapter):
    """Adapter for zama-ai/tfhe-rs via the Rust helper binary."""

    name = "tfhe-rs"
    capability = AdapterCapability(
        schemes=("TFHE",),
        requires_native=True,
        live_oracle=False,  # flips to True once the helper's ops land
        notes=(
            "Requires fhe-replay-tfhe-rs-helper on PATH (build from "
            "vendor/tfhe-rs-helper/ via `cargo build --release`). "
            "Helper currently a scaffold — encrypt/decrypt/perturb ops "
            "surface as ERROR until tfhe-rs wiring lands."
        ),
    )

    HELPER_BINARY = "fhe-replay-tfhe-rs-helper"

    def is_available(self) -> bool:
        return shutil.which(self.HELPER_BINARY) is not None

    def setup(self, scheme: str, params: dict[str, Any]) -> AdapterContext:
        binary = shutil.which(self.HELPER_BINARY)
        if binary is None:
            raise RuntimeError(
                f"{self.HELPER_BINARY} is not on PATH. "
                "Build it from vendor/tfhe-rs-helper/ "
                "(cd vendor/tfhe-rs-helper && cargo build --release && "
                f"cp target/release/{self.HELPER_BINARY} $HOME/.local/bin/) "
                "or download a release binary."
            )
        proc = _HelperProcess(binary, label="tfhe-rs helper")
        hello = proc.request({"op": "hello"})
        if hello.get("version") != _PROTOCOL_VERSION:
            raise RuntimeError(
                f"tfhe-rs helper version {hello.get('version')!r} does not "
                f"match adapter protocol {_PROTOCOL_VERSION!r}; rebuild "
                "the helper or upgrade fhe-attack-replay."
            )
        if scheme.upper() not in {s.upper() for s in hello.get("scheme_support", [])}:
            raise NotImplementedError(
                f"tfhe-rs helper does not advertise scheme {scheme!r} "
                f"(supports: {hello.get('scheme_support', [])})."
            )
        return AdapterContext(
            library=self.name,
            scheme=scheme.upper(),
            params=params,
            handles={"helper": proc, "scheme": scheme.upper()},
        )

    def encrypt(self, ctx: AdapterContext, plaintext: Any) -> Any:
        proc: _HelperProcess = ctx.handles["helper"]
        values = plaintext if isinstance(plaintext, list) else [int(plaintext)]
        response = proc.request(
            {
                "op": "encrypt",
                "context_id": ctx.handles.get("context_id", ""),
                "values": [int(v) for v in values],
            }
        )
        return response.get("ciphertext_id")

    def decrypt(self, ctx: AdapterContext, ciphertext: Any) -> Any:
        proc: _HelperProcess = ctx.handles["helper"]
        response = proc.request(
            {
                "op": "decrypt",
                "context_id": ctx.handles.get("context_id", ""),
                "ciphertext_id": ciphertext,
            }
        )
        return response.get("values", [])

    def evaluator_fingerprint(self, ctx: AdapterContext) -> dict[str, Any]:
        return {
            "implementation": "zama-ai/tfhe-rs",
            "ntt_variant": "n/a",  # TFHE doesn't use NTT in the BFV sense
            "constant_time_decrypt": True,
        }
