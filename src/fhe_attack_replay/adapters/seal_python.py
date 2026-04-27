# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Adapter for Microsoft SEAL via the Huelse/SEAL-Python pybind11 binding.

Distinct from :class:`fhe_attack_replay.adapters.seal.SEALAdapter` (which
goes through TenSEAL's high-level Vector API): seal-python is a thin
pybind wrapper that exposes the full SEAL ``Evaluator`` surface,
including ``transform_to_ntt_inplace`` / ``transform_from_ntt_inplace``.
That surface is what the eprint-2025-867 live distinguisher needs to
time individual NTT calls instead of the whole ``decrypt()`` path.

Why ship both adapters? TenSEAL ships pre-built wheels for all major
platforms; seal-python often needs a local build but exposes finer
internals. Users pick whichever fits their environment.

Recognized params (all optional):
  - ``poly_modulus_degree``: int — default 8192;
  - ``plaintext_modulus``: int — BFV/BGV only; default 1032193;
  - ``coeff_mod_bit_sizes``: list[int] — CKKS only; default
    [60, 40, 40, 60];
  - ``scale_bits``: int — CKKS only; default 40;
  - ``constant_time_decrypt``: bool — surfaced in the fingerprint so
    eprint-2025-867 can short-circuit hardened builds.
"""

from __future__ import annotations

import importlib
from typing import Any

from fhe_attack_replay.adapters.base import (
    AdapterCapability,
    AdapterContext,
    LibraryAdapter,
)


def _try_import_seal():
    """Import the seal-python binding, returning the module or None.

    The PyPI ``seal-python`` package re-exports a compiled SEAL extension.
    Any of: missing wheel, wrong-platform wheel, partial install raises a
    different exception class — this helper centralizes the catch.
    """
    try:
        return importlib.import_module("seal")
    except (ImportError, ModuleNotFoundError, OSError):
        return None


_DEFAULT_POLY = 8192
_DEFAULT_BFV_PLAIN_MOD = 1032193
_DEFAULT_CKKS_COEFF_BITS = (60, 40, 40, 60)
_DEFAULT_CKKS_SCALE_BITS = 40


class SealPythonAdapter(LibraryAdapter):
    name = "seal-python"
    capability = AdapterCapability(
        schemes=("BFV", "BGV", "CKKS"),
        requires_native=True,
        live_oracle=True,
        notes=(
            "Requires `seal-python` (pip install 'fhe-attack-replay[seal-python]'). "
            "Exposes per-NTT-call timing via Evaluator.transform_to_ntt_inplace, "
            "which the eprint-2025-867 live distinguisher uses for finer-grained "
            "side-channel measurement than the TenSEAL adapter can offer."
        ),
    )

    def is_available(self) -> bool:
        return _try_import_seal() is not None

    # ------------------------------------------------------------------ setup
    def setup(self, scheme: str, params: dict[str, Any]) -> AdapterContext:
        seal = _try_import_seal()
        if seal is None:
            raise RuntimeError(
                "seal-python is not importable. Install it with "
                "`pip install seal-python` (the PyPI wheel typically builds "
                "against system SEAL on first install)."
            )
        scheme_u = scheme.upper()
        poly = int(params.get("poly_modulus_degree", _DEFAULT_POLY))

        if scheme_u == "BFV":
            ctx, encryptor, decryptor, evaluator, encoder = self._setup_bfv_like(
                seal, params, poly, seal.scheme_type.bfv,
            )
        elif scheme_u == "BGV":
            ctx, encryptor, decryptor, evaluator, encoder = self._setup_bfv_like(
                seal, params, poly, seal.scheme_type.bgv,
            )
        elif scheme_u == "CKKS":
            ctx, encryptor, decryptor, evaluator, encoder = self._setup_ckks(
                seal, params, poly,
            )
        else:
            raise NotImplementedError(
                f"SealPythonAdapter does not support scheme {scheme!r}; "
                f"choose one of {self.capability.schemes}."
            )
        return AdapterContext(
            library=self.name,
            scheme=scheme_u,
            params=params,
            handles={
                "seal": seal,
                "context": ctx,
                "encryptor": encryptor,
                "decryptor": decryptor,
                "evaluator": evaluator,
                "encoder": encoder,
                "scheme": scheme_u,
            },
        )

    @staticmethod
    def _setup_bfv_like(seal, params: dict[str, Any], poly: int, scheme_kind):
        parms = seal.EncryptionParameters(scheme_kind)
        parms.set_poly_modulus_degree(poly)
        parms.set_coeff_modulus(seal.CoeffModulus.BFVDefault(poly))
        parms.set_plain_modulus(int(params.get("plaintext_modulus", _DEFAULT_BFV_PLAIN_MOD)))
        ctx = seal.SEALContext(parms)
        keygen = seal.KeyGenerator(ctx)
        sk = keygen.secret_key()
        pk = seal.PublicKey()
        keygen.create_public_key(pk)
        return (
            ctx,
            seal.Encryptor(ctx, pk),
            seal.Decryptor(ctx, sk),
            seal.Evaluator(ctx),
            seal.BatchEncoder(ctx),
        )

    @staticmethod
    def _setup_ckks(seal, params: dict[str, Any], poly: int):
        parms = seal.EncryptionParameters(seal.scheme_type.ckks)
        parms.set_poly_modulus_degree(poly)
        coeff_bits = list(params.get("coeff_mod_bit_sizes", _DEFAULT_CKKS_COEFF_BITS))
        parms.set_coeff_modulus(seal.CoeffModulus.Create(poly, coeff_bits))
        ctx = seal.SEALContext(parms)
        keygen = seal.KeyGenerator(ctx)
        sk = keygen.secret_key()
        pk = seal.PublicKey()
        keygen.create_public_key(pk)
        return (
            ctx,
            seal.Encryptor(ctx, pk),
            seal.Decryptor(ctx, sk),
            seal.Evaluator(ctx),
            seal.CKKSEncoder(ctx),
        )

    # ----------------------------------------------------------- crypto path
    def encrypt(self, ctx: AdapterContext, plaintext: Any) -> Any:
        scheme = ctx.handles["scheme"]
        encoder = ctx.handles["encoder"]
        encryptor = ctx.handles["encryptor"]
        if scheme in ("BFV", "BGV"):
            values = plaintext if isinstance(plaintext, list) else [int(plaintext)]
            pt = encoder.encode([int(v) for v in values])
        else:  # CKKS
            values = plaintext if isinstance(plaintext, list) else [float(plaintext)]
            scale_bits = int(ctx.params.get("scale_bits", _DEFAULT_CKKS_SCALE_BITS))
            pt = encoder.encode([float(v) for v in values], 2.0 ** scale_bits)
        return encryptor.encrypt(pt)

    def decrypt(self, ctx: AdapterContext, ciphertext: Any) -> Any:
        scheme = ctx.handles["scheme"]
        encoder = ctx.handles["encoder"]
        decryptor = ctx.handles["decryptor"]
        pt = decryptor.decrypt(ciphertext)
        if scheme in ("BFV", "BGV"):
            return list(encoder.decode(pt))
        return list(encoder.decode(pt))

    # ----------------------------------------------------- per-NTT primitive
    def transform_to_ntt(self, ctx: AdapterContext, ciphertext: Any) -> Any:
        """Run SEAL's ``Evaluator.transform_to_ntt_inplace`` on a copy.

        Returns the transformed ciphertext (the original is not mutated).
        Used by the eprint-2025-867 live distinguisher to time the NTT
        path in isolation from the rest of ``decrypt``.
        """
        seal = ctx.handles["seal"]
        evaluator = ctx.handles["evaluator"]
        # Copy so the caller can re-time against a fresh ciphertext per
        # repeat — transform_to_ntt_inplace is idempotent in form but
        # not in noise growth, and seal-python rejects double-NTT.
        clone = seal.Ciphertext(ciphertext)
        evaluator.transform_to_ntt_inplace(clone)
        return clone

    # --------------------------------------------------------- introspection
    def evaluator_fingerprint(self, ctx: AdapterContext) -> dict[str, Any]:
        seal_ctx = ctx.handles.get("context") if ctx.handles else None
        return {
            "implementation": "microsoft/SEAL via seal-python",
            "ntt_variant": "harvey-butterfly",
            "constant_time_decrypt": bool(
                ctx.params.get("constant_time_decrypt", False)
            ),
            "ring_dimension": self._read_poly_modulus_degree(seal_ctx),
            "scheme": ctx.scheme,
            "exposes_per_ntt_timing": True,
        }

    @staticmethod
    def _read_poly_modulus_degree(seal_ctx) -> int | None:
        if seal_ctx is None:
            return None
        try:
            return int(seal_ctx.first_context_data().parms().poly_modulus_degree())
        except (AttributeError, RuntimeError):
            return None
