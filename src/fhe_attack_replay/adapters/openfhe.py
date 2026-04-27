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
import json
import math
from typing import Any

from fhe_attack_replay.adapters.base import (
    AdapterCapability,
    AdapterContext,
    LibraryAdapter,
)

# Mitigation labels that this adapter knows how to wire into OpenFHE's native
# NOISE_FLOODING_DECRYPT execution mode. Stored in canonical hyphenated form;
# `_normalize_flooding_label` coerces user input into the same shape so casing
# and `_` vs `-` separators are interchangeable. Other recognized mitigations
# (eprint-2024-424, eprint-2025-1627, ...) are not native OpenFHE features
# and remain RiskCheck-only.
_OPENFHE_NATIVE_FLOODING_LABELS = frozenset(
    {"openfhe-noise-flooding-decrypt", "noise-flooding"}
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


def _normalize_flooding_label(value: Any) -> str:
    """Lowercase and collapse `_`/whitespace runs to single `-` separators."""
    if value is None:
        return ""
    text = str(value).strip().lower()
    out: list[str] = []
    prev_dash = False
    for ch in text:
        if ch in {"_", " ", "\t"}:
            if not prev_dash:
                out.append("-")
                prev_dash = True
        else:
            out.append(ch)
            prev_dash = ch == "-"
    return "".join(out)


def _apply_native_noise_flooding(of, params_obj, params: dict[str, Any]) -> bool:
    """Enable OpenFHE NOISE_FLOODING_DECRYPT on a CCParams object when requested.

    Returns True iff the native mitigation was actually wired into the
    crypto-context parameters. Raises RuntimeError when the params dict
    declares a native mitigation but the running openfhe-python build lacks
    the API surface — surfacing a clear error to the caller is preferable to
    silently building a non-flooded context that would then look VULNERABLE.
    """
    label = _normalize_flooding_label(params.get("noise_flooding"))
    if label not in _OPENFHE_NATIVE_FLOODING_LABELS:
        return False
    set_exec = getattr(params_obj, "SetExecutionMode", None)
    set_decrypt = getattr(params_obj, "SetDecryptionNoiseMode", None)
    exec_flooding = getattr(of, "EXEC_NOISE_FLOODING", None)
    decrypt_flooding = getattr(of, "NOISE_FLOODING_DECRYPT", None)
    api_complete = (
        set_exec
        and set_decrypt
        and exec_flooding is not None
        and decrypt_flooding is not None
    )
    if not api_complete:
        raise RuntimeError(
            "params.noise_flooding requested OpenFHE NOISE_FLOODING_DECRYPT "
            "but the linked openfhe-python build does not expose "
            "SetExecutionMode / SetDecryptionNoiseMode. Upgrade openfhe-python "
            "to a build that exposes the EXEC_NOISE_FLOODING execution mode."
        )
    set_exec(exec_flooding)
    set_decrypt(decrypt_flooding)
    return True


class OpenFHEAdapter(LibraryAdapter):
    name = "openfhe"
    capability = AdapterCapability(
        schemes=("BFV", "BGV", "CKKS"),
        requires_native=True,
        live_oracle=True,
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
            cc, keypair, flooding = self._setup_bfv(of, params)
        elif scheme_u == "BGV":
            cc, keypair, flooding = self._setup_bgv(of, params)
        elif scheme_u == "CKKS":
            cc, keypair, flooding = self._setup_ckks(of, params)
        else:
            raise ValueError(
                f"OpenFHEAdapter does not support scheme {scheme!r}; "
                f"choose one of {self.capability.schemes}."
            )
        return AdapterContext(
            library=self.name,
            scheme=scheme_u,
            params=params,
            handles={
                "openfhe": of,
                "cc": cc,
                "keys": keypair,
                "scheme": scheme_u,
                "native_noise_flooding": flooding,
            },
        )

    def _setup_bfv(self, of, params: dict[str, Any]):
        p = of.CCParamsBFVRNS()
        p.SetPlaintextModulus(int(params.get("plaintext_modulus", 65537)))
        p.SetMultiplicativeDepth(int(params.get("multiplicative_depth", 2)))
        if "ring_dimension" in params:
            p.SetRingDim(int(params["ring_dimension"]))
        flooding = _apply_native_noise_flooding(of, p, params)
        cc = of.GenCryptoContext(p)
        cc.Enable(of.PKESchemeFeature.PKE)
        cc.Enable(of.PKESchemeFeature.LEVELEDSHE)
        return cc, cc.KeyGen(), flooding

    def _setup_bgv(self, of, params: dict[str, Any]):
        p = of.CCParamsBGVRNS()
        p.SetPlaintextModulus(int(params.get("plaintext_modulus", 65537)))
        p.SetMultiplicativeDepth(int(params.get("multiplicative_depth", 2)))
        if "ring_dimension" in params:
            p.SetRingDim(int(params["ring_dimension"]))
        flooding = _apply_native_noise_flooding(of, p, params)
        cc = of.GenCryptoContext(p)
        cc.Enable(of.PKESchemeFeature.PKE)
        cc.Enable(of.PKESchemeFeature.LEVELEDSHE)
        return cc, cc.KeyGen(), flooding

    def _setup_ckks(self, of, params: dict[str, Any]):
        p = of.CCParamsCKKSRNS()
        p.SetMultiplicativeDepth(int(params.get("multiplicative_depth", 2)))
        p.SetScalingModSize(int(params.get("scale_bits", 50)))
        p.SetBatchSize(int(params.get("batch_size", 8)))
        if "ring_dimension" in params:
            p.SetRingDim(int(params["ring_dimension"]))
        flooding = _apply_native_noise_flooding(of, p, params)
        cc = of.GenCryptoContext(p)
        cc.Enable(of.PKESchemeFeature.PKE)
        cc.Enable(of.PKESchemeFeature.LEVELEDSHE)
        return cc, cc.KeyGen(), flooding

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

    def plaintext_modulus(self, ctx: AdapterContext) -> int:
        """Return the exact plaintext modulus for integer OpenFHE schemes."""
        if ctx.handles["scheme"] not in ("BFV", "BGV"):
            raise NotImplementedError(
                "OpenFHE polynomial-domain replay is only wired for BFV/BGV."
            )
        return int(ctx.handles["cc"].GetPlaintextModulus())

    def ciphertext_moduli(self, ctx: AdapterContext, ciphertext: Any) -> tuple[int, ...]:
        """Return the DCRT tower moduli for ciphertext component c0.

        The Python binding exposes ``Ciphertext.GetElements`` but not enough
        mutable DCRTPoly methods for attack construction. JSON serialization
        preserves the tower representation, so the replay path uses it as the
        narrow compatibility layer.
        """
        payload = self._serialize_ciphertext(ctx, ciphertext)
        return self._component_moduli(payload, component=0)

    def ciphertext_modulus(self, ctx: AdapterContext, ciphertext: Any) -> int:
        return math.prod(self.ciphertext_moduli(ctx, ciphertext))

    def plaintext_delta(self, ctx: AdapterContext, ciphertext: Any) -> int:
        """Return floor(Q / t), the BFV/BGV plaintext scaling factor."""
        return self.ciphertext_modulus(ctx, ciphertext) // self.plaintext_modulus(ctx)

    def perturb_ciphertext_constant(
        self,
        ctx: AdapterContext,
        ciphertext: Any,
        offset: int,
        *,
        component: int = 0,
    ) -> Any:
        """Add a constant polynomial to a ciphertext component.

        OpenFHE serializes BFV/BGV ciphertext DCRT polynomials in evaluation
        form. Adding the same residue to every slot in each RNS tower is the
        evaluation-domain representation of adding a constant polynomial. The
        Cheon replay uses this to move an encryption of zero across the
        decryption rounding boundary.
        """
        payload = self._serialize_ciphertext(ctx, ciphertext)
        towers = self._component_towers(payload, component=component)
        for tower in towers:
            data = tower["v"]["ptr_wrapper"]["data"]
            coeffs = data["v"]
            modulus = self._exact_int(data["m"]["v"], "DCRT tower modulus")
            residue = int(offset) % modulus
            for idx, coeff in enumerate(coeffs):
                coeffs[idx] = (self._exact_int(coeff, "DCRT coefficient") + residue) % modulus
        return self._deserialize_ciphertext(ctx, payload)

    def polynomial_replay_metadata(
        self, ctx: AdapterContext, ciphertext: Any
    ) -> dict[str, Any]:
        moduli = self.ciphertext_moduli(ctx, ciphertext)
        modulus = math.prod(moduli)
        return {
            "serialization_backend": "openfhe-json",
            "polynomial_domain": "DCRT evaluation form",
            "perturbation": "constant polynomial added to ciphertext component c0",
            "plaintext_modulus": self.plaintext_modulus(ctx),
            "ciphertext_modulus_bits": modulus.bit_length(),
            "dcrt_tower_count": len(moduli),
            "dcrt_moduli_bits": [m.bit_length() for m in moduli],
            "native_noise_flooding": bool(ctx.handles.get("native_noise_flooding", False)),
        }

    def _serialize_ciphertext(
        self, ctx: AdapterContext, ciphertext: Any
    ) -> dict[str, Any]:
        of = ctx.handles["openfhe"]
        return json.loads(of.Serialize(ciphertext, of.JSON))

    def _deserialize_ciphertext(
        self, ctx: AdapterContext, payload: dict[str, Any]
    ) -> Any:
        of = ctx.handles["openfhe"]
        return of.DeserializeCiphertextString(json.dumps(payload), of.JSON)

    @staticmethod
    def _component_towers(
        payload: dict[str, Any], *, component: int
    ) -> list[dict[str, Any]]:
        components = payload["value0"]["ptr_wrapper"]["data"]["v"]
        return components[component]["v"]

    @classmethod
    def _component_moduli(
        cls, payload: dict[str, Any], *, component: int
    ) -> tuple[int, ...]:
        return tuple(
            cls._exact_int(tower["v"]["ptr_wrapper"]["data"]["m"]["v"], "DCRT tower modulus")
            for tower in cls._component_towers(payload, component=component)
        )

    @staticmethod
    def _exact_int(raw: Any, label: str) -> int:
        """Coerce an OpenFHE-JSON integer field without losing precision.

        Cereal-style integers >2^53 emitted as JSON numbers (not strings) lose
        precision when ``json.loads`` parses them as ``float``. Strings always
        round-trip safely. This guard fails fast with a clear message rather
        than silently truncating a DCRT modulus during ciphertext mutation.
        """
        if isinstance(raw, str):
            return int(raw)
        if isinstance(raw, int) and not isinstance(raw, bool):
            return raw
        if isinstance(raw, float):
            if not raw.is_integer() or abs(raw) >= 2**53:
                raise RuntimeError(
                    f"OpenFHE serialization emitted {label} as a JSON float "
                    f"({raw!r}); this loses precision above 2**53. Pin "
                    "openfhe-python to a build that emits big integers as JSON "
                    "strings, or rebuild with a string-encoding cereal archive."
                )
            return int(raw)
        raise RuntimeError(
            f"Unexpected type {type(raw).__name__} for {label} in OpenFHE JSON payload."
        )

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
