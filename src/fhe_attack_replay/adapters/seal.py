# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Adapter for microsoft/SEAL via the OpenMined TenSEAL bindings.

Pure SEAL has no first-party Python bindings; TenSEAL wraps SEAL's BFV and
CKKS surface with a vector-oriented API that is sufficient for the harness
to build keys, encrypt sample plaintexts, decrypt them, and read parameter
metadata back out for fingerprinting. ``is_available`` performs a real
import (not just a metadata check) so adapters silently fall back to a
synthetic context when ``tenseal`` is missing.
"""

from __future__ import annotations

import importlib
from typing import Any

from fhe_attack_replay.adapters.base import (
    AdapterCapability,
    AdapterContext,
    LibraryAdapter,
)


def _try_import_tenseal():
    """Import tenseal, returning the module or None on any failure.

    The PyPI ``tenseal`` package re-exports a compiled SEAL extension. Any
    of: missing wheel, wrong-platform wheel, or partial install raises a
    different exception class — this helper centralizes the catch.
    """
    try:
        return importlib.import_module("tenseal")
    except (ImportError, ModuleNotFoundError, OSError):
        return None


_DEFAULT_BFV_POLY = 8192
_DEFAULT_BFV_PLAIN_MOD = 1032193
_DEFAULT_CKKS_POLY = 8192
_DEFAULT_CKKS_COEFF_BITS = (60, 40, 40, 60)
_DEFAULT_CKKS_SCALE_BITS = 40


class SEALAdapter(LibraryAdapter):
    name = "seal"
    capability = AdapterCapability(
        schemes=("BFV", "CKKS"),
        requires_native=True,
        notes=(
            "Requires `tenseal` (pip install 'fhe-attack-replay[seal]'). "
            "TenSEAL wraps microsoft/SEAL; pure-SEAL Python bindings do "
            "not exist."
        ),
    )

    def is_available(self) -> bool:
        return _try_import_tenseal() is not None

    def setup(self, scheme: str, params: dict[str, Any]) -> AdapterContext:
        ts = _try_import_tenseal()
        if ts is None:
            raise RuntimeError(
                "tenseal is not importable. Install with "
                "`pip install 'fhe-attack-replay[seal]'`."
            )
        scheme_u = scheme.upper()
        if scheme_u == "BFV":
            ctx = self._setup_bfv(ts, params)
        elif scheme_u == "CKKS":
            ctx = self._setup_ckks(ts, params)
        else:
            # Raise NotImplementedError (not ValueError) so the runner's
            # `_setup_or_synthetic` fallback engages and attacks that operate
            # purely on params (e.g. cheon-2024-127 risk-check on BGV) still
            # have a context to consume. TenSEAL does not expose BGV.
            raise NotImplementedError(
                f"SEALAdapter does not support scheme {scheme!r}; "
                f"choose one of {self.capability.schemes}."
            )
        return AdapterContext(
            library=self.name,
            scheme=scheme_u,
            params=params,
            handles={"tenseal": ts, "context": ctx, "scheme": scheme_u},
        )

    def _setup_bfv(self, ts, params: dict[str, Any]):
        poly = int(params.get("poly_modulus_degree", _DEFAULT_BFV_POLY))
        plain_mod = int(params.get("plaintext_modulus", _DEFAULT_BFV_PLAIN_MOD))
        ctx = ts.context(
            ts.SCHEME_TYPE.BFV,
            poly_modulus_degree=poly,
            plain_modulus=plain_mod,
        )
        if params.get("generate_galois_keys", False):
            ctx.generate_galois_keys()
        return ctx

    def _setup_ckks(self, ts, params: dict[str, Any]):
        poly = int(params.get("poly_modulus_degree", _DEFAULT_CKKS_POLY))
        coeff_bits = list(
            params.get("coeff_mod_bit_sizes", _DEFAULT_CKKS_COEFF_BITS)
        )
        scale_bits = int(params.get("scale_bits", _DEFAULT_CKKS_SCALE_BITS))
        ctx = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=poly,
            coeff_mod_bit_sizes=coeff_bits,
        )
        ctx.global_scale = 2**scale_bits
        if params.get("generate_galois_keys", False):
            ctx.generate_galois_keys()
        return ctx

    def encrypt(self, ctx: AdapterContext, plaintext: Any) -> Any:
        ts = ctx.handles["tenseal"]
        seal_ctx = ctx.handles["context"]
        scheme = ctx.handles["scheme"]
        if scheme == "BFV":
            values = plaintext if isinstance(plaintext, list) else [int(plaintext)]
            return ts.bfv_vector(seal_ctx, [int(v) for v in values])
        # CKKS
        values = plaintext if isinstance(plaintext, list) else [float(plaintext)]
        return ts.ckks_vector(seal_ctx, [float(v) for v in values])

    def decrypt(self, ctx: AdapterContext, ciphertext: Any) -> Any:
        return ciphertext.decrypt()

    def evaluator_fingerprint(self, ctx: AdapterContext) -> dict[str, Any]:
        seal_ctx = ctx.handles.get("context") if ctx.handles else None
        poly = self._read_poly_modulus_degree(seal_ctx)
        return {
            "implementation": "microsoft/SEAL via tenseal",
            # SEAL ships Harvey-butterfly NTT with non-constant-time guard
            # and mul_root paths — the surface targeted by ePrint 2025/867.
            "ntt_variant": "harvey-butterfly",
            "constant_time_decrypt": bool(
                ctx.params.get("constant_time_decrypt", False)
            ),
            "ring_dimension": poly,
            "scheme": ctx.scheme,
        }

    @staticmethod
    def _read_poly_modulus_degree(seal_ctx) -> int | None:
        if seal_ctx is None:
            return None
        try:
            parms = seal_ctx.seal_context().data.first_context_data().parms()
            return int(parms.poly_modulus_degree())
        except (AttributeError, RuntimeError):
            return None
