# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Adapter for openfheorg/openfhe-development via the openfhe-python bindings.

The openfhe-python wheel currently ships a Linux x86_64 ``.so`` only; users
on macOS or Windows must build it from source against the C++ openfhe
library. ``is_available`` performs a real import of the native extension
(not just a metadata check) so adapters silently fall back to a synthetic
context when the native build is missing.
"""

from __future__ import annotations

import importlib
from typing import Any

from fhe_attack_replay.adapters.base import (
    AdapterCapability,
    AdapterContext,
    LibraryAdapter,
)


def _try_import_openfhe():
    """Import openfhe-python, returning the module or None on any failure.

    The PyPI ``openfhe`` package re-exports a compiled C++ extension. Any
    of: missing wheel, wrong-platform wheel, or a partial install raises a
    different exception class — this helper centralizes the catch.
    """
    try:
        return importlib.import_module("openfhe")
    except (ImportError, ModuleNotFoundError, OSError):
        return None


class OpenFHEAdapter(LibraryAdapter):
    name = "openfhe"
    capability = AdapterCapability(
        schemes=("BFV", "BGV", "CKKS"),
        requires_native=True,
        notes=(
            "Requires openfhe-python with a working C++ backend. The PyPI "
            "wheel only ships Linux x86_64; on other platforms build from "
            "https://github.com/openfheorg/openfhe-python."
        ),
    )

    def is_available(self) -> bool:
        return _try_import_openfhe() is not None

    def setup(self, scheme: str, params: dict[str, Any]) -> AdapterContext:
        of = _try_import_openfhe()
        if of is None:
            raise RuntimeError(
                "openfhe-python is not importable. Install it from "
                "https://github.com/openfheorg/openfhe-python (the PyPI "
                "wheel only supports Linux x86_64; build from source on "
                "other platforms)."
            )
        scheme_u = scheme.upper()
        if scheme_u == "BFV":
            cc, keypair = self._setup_bfv(of, params)
        elif scheme_u == "BGV":
            cc, keypair = self._setup_bgv(of, params)
        elif scheme_u == "CKKS":
            cc, keypair = self._setup_ckks(of, params)
        else:
            raise ValueError(
                f"OpenFHEAdapter does not support scheme {scheme!r}; "
                f"choose one of {self.capability.schemes}."
            )
        return AdapterContext(
            library=self.name,
            scheme=scheme_u,
            params=params,
            handles={"openfhe": of, "cc": cc, "keys": keypair, "scheme": scheme_u},
        )

    def _setup_bfv(self, of, params: dict[str, Any]):
        p = of.CCParamsBFVRNS()
        p.SetPlaintextModulus(int(params.get("plaintext_modulus", 65537)))
        p.SetMultiplicativeDepth(int(params.get("multiplicative_depth", 2)))
        if "ring_dimension" in params:
            p.SetRingDim(int(params["ring_dimension"]))
        cc = of.GenCryptoContext(p)
        cc.Enable(of.PKESchemeFeature.PKE)
        cc.Enable(of.PKESchemeFeature.LEVELEDSHE)
        return cc, cc.KeyGen()

    def _setup_bgv(self, of, params: dict[str, Any]):
        p = of.CCParamsBGVRNS()
        p.SetPlaintextModulus(int(params.get("plaintext_modulus", 65537)))
        p.SetMultiplicativeDepth(int(params.get("multiplicative_depth", 2)))
        if "ring_dimension" in params:
            p.SetRingDim(int(params["ring_dimension"]))
        cc = of.GenCryptoContext(p)
        cc.Enable(of.PKESchemeFeature.PKE)
        cc.Enable(of.PKESchemeFeature.LEVELEDSHE)
        return cc, cc.KeyGen()

    def _setup_ckks(self, of, params: dict[str, Any]):
        p = of.CCParamsCKKSRNS()
        p.SetMultiplicativeDepth(int(params.get("multiplicative_depth", 2)))
        p.SetScalingModSize(int(params.get("scale_bits", 50)))
        p.SetBatchSize(int(params.get("batch_size", 8)))
        if "ring_dimension" in params:
            p.SetRingDim(int(params["ring_dimension"]))
        cc = of.GenCryptoContext(p)
        cc.Enable(of.PKESchemeFeature.PKE)
        cc.Enable(of.PKESchemeFeature.LEVELEDSHE)
        return cc, cc.KeyGen()

    def encrypt(self, ctx: AdapterContext, plaintext: Any) -> Any:
        cc = ctx.handles["cc"]
        keys = ctx.handles["keys"]
        scheme = ctx.handles["scheme"]
        if scheme in ("BFV", "BGV"):
            values = plaintext if isinstance(plaintext, list) else [int(plaintext)]
            pt = cc.MakePackedPlaintext(values)
        else:  # CKKS
            values = plaintext if isinstance(plaintext, list) else [float(plaintext)]
            pt = cc.MakeCKKSPackedPlaintext(values)
        return cc.Encrypt(keys.publicKey, pt)

    def decrypt(self, ctx: AdapterContext, ciphertext: Any) -> Any:
        cc = ctx.handles["cc"]
        keys = ctx.handles["keys"]
        scheme = ctx.handles["scheme"]
        pt = cc.Decrypt(keys.secretKey, ciphertext)
        if scheme in ("BFV", "BGV"):
            return pt.GetPackedValue()
        return pt.GetCKKSPackedValue()

    def evaluator_fingerprint(self, ctx: AdapterContext) -> dict[str, Any]:
        cc = ctx.handles.get("cc") if ctx.handles else None
        return {
            "implementation": "openfheorg/openfhe-development via openfhe-python",
            "ring_dimension": int(cc.GetRingDimension()) if cc else None,
            "scheme": ctx.scheme,
            # OpenFHE relies on the C++ compiler for constant-time decrypt;
            # users who build against a hardened OpenFHE branch should
            # override this in their params.
            "constant_time_decrypt": bool(
                ctx.params.get("constant_time_decrypt", False)
            ),
        }
