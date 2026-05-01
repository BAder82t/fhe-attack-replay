# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Adapter for tuneinsight/lattigo (Go).

Lattigo is pure Go; this adapter shells out to a small Go helper binary
(``fhe-replay-lattigo-helper``, source under ``vendor/lattigo-helper/``)
that exposes the primitives the harness needs over a JSON protocol on
stdin/stdout. The Python side spawns the helper, exchanges
line-delimited JSON, and parses responses.

As of helper protocol v0.2 the helper drives a real Lattigo BGV/BFV
context: setup builds keys, encrypt/decrypt round-trip integers
through the unified ``schemes/bgv`` package, and perturb_constant
mutates ciphertext component c0 in evaluation form (the Cheon replay
primitive). Mitigated configurations (params with a recognized
``noise_flooding`` label) are routed back through the static
RiskCheck — the helper does not yet implement software flooding, so a
live Replay against a mitigated config would falsely report VULNERABLE.
"""

from __future__ import annotations

import atexit
import json
import shutil
import subprocess
import weakref
from typing import Any

from fhe_attack_replay.adapters.base import (
    AdapterCapability,
    AdapterContext,
    LibraryAdapter,
)

# Helper protocol version this adapter speaks. Bump when the wire
# protocol changes. Reuse from cheon-2024-127's mitigation list to keep
# a single source of truth for "what counts as flooding".
_PROTOCOL_VERSION = "0.3.0"

# Default sigma for software flooding when params declares a recognized
# `noise_flooding` mitigation but no explicit `noise_flooding_sigma`.
# Expressed as a fraction of delta = floor(Q/t); 1/4 matches the toy-lwe
# analog and reliably randomizes Cheon's bisection-recovered boundary
# above the SAFE-verdict variance threshold (default 0.05 * delta).
_DEFAULT_FLOODING_SIGMA_FRAC_DELTA = 0.25

# Mirrors fhe_attack_replay.attacks.cheon_2024_127._RECOGNIZED_MITIGATIONS.
# Re-imported lazily inside helpers below to avoid an import cycle at
# module-load time.


class _HelperProcess:
    """Long-lived subprocess wrapper around a JSON-stdio helper binary.

    Reused by both the lattigo (Go) and tfhe-rs (Rust) adapters; the
    wire protocol is identical, so the Python side doesn't care which
    implementation it spawned.
    """

    def __init__(self, binary: str, *, label: str = "helper") -> None:
        self._label = label
        self._proc = subprocess.Popen(
            [binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # line-buffered
        )
        weakref.finalize(self, _shutdown_proc, self._proc)
        atexit.register(_shutdown_proc, self._proc)

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._proc.stdin is None or self._proc.stdout is None:
            raise RuntimeError(f"{self._label} subprocess has no pipes")
        line = json.dumps(payload, separators=(",", ":")) + "\n"
        try:
            self._proc.stdin.write(line)
            self._proc.stdin.flush()
        except BrokenPipeError as exc:
            raise RuntimeError(f"{self._label} subprocess died: {exc}") from exc
        response_line = self._proc.stdout.readline()
        if not response_line:
            stderr = self._proc.stderr.read() if self._proc.stderr else ""
            raise RuntimeError(
                f"{self._label} subprocess returned no response"
                + (f" (stderr: {stderr.strip()!r})" if stderr.strip() else "")
            )
        try:
            response = json.loads(response_line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"{self._label} returned malformed JSON: {response_line!r} ({exc})"
            ) from exc
        if "error" in response:
            raise RuntimeError(f"{self._label} error: {response['error']}")
        return response


def _shutdown_proc(proc: subprocess.Popen) -> None:
    """Best-effort shutdown — send the shutdown opcode then close pipes."""
    if proc.poll() is not None:
        return
    try:
        if proc.stdin is not None and not proc.stdin.closed:
            proc.stdin.write('{"op":"shutdown"}\n')
            proc.stdin.flush()
            proc.stdin.close()
    except (OSError, BrokenPipeError):
        pass
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()


def _params_recognize_flooding(params: dict[str, Any]) -> bool:
    """True iff ``params['noise_flooding']`` resolves to a known mitigation.

    Imported lazily from cheon_2024_127 to avoid an import cycle at
    module-load time. The check is intentionally adapter-side rather
    than helper-side: the helper does not yet implement software
    flooding, so a live Replay against a mitigated config would
    falsely report VULNERABLE. Raising NotImplementedError from the
    perturb primitive sends Cheon back to the static RiskCheck, which
    *does* recognize these labels and produces a real SAFE verdict.
    """
    from fhe_attack_replay.attacks.cheon_2024_127 import (
        _RECOGNIZED_MITIGATIONS,
        _normalize,
    )

    label = _normalize(params.get("noise_flooding"))
    return label in _RECOGNIZED_MITIGATIONS


class LattigoAdapter(LibraryAdapter):
    """Adapter for tuneinsight/lattigo via the Go helper binary."""

    name = "lattigo"
    capability = AdapterCapability(
        schemes=("BFV", "BGV"),
        requires_native=True,
        live_oracle=True,
        notes=(
            "Requires fhe-replay-lattigo-helper on PATH (build from "
            "vendor/lattigo-helper or download a pre-built release "
            "binary). BFV/BGV live-oracle Replay; CKKS not yet wired. "
            "Mitigated configs (recognized noise_flooding label) drive "
            "live software-flooding decrypt via helper protocol v0.3."
        ),
    )

    HELPER_BINARY = "fhe-replay-lattigo-helper"

    def is_available(self) -> bool:
        return shutil.which(self.HELPER_BINARY) is not None

    def setup(self, scheme: str, params: dict[str, Any]) -> AdapterContext:
        binary = shutil.which(self.HELPER_BINARY)
        if binary is None:
            raise RuntimeError(
                f"{self.HELPER_BINARY} is not on PATH. "
                "Build it from vendor/lattigo-helper/ "
                "(cd vendor/lattigo-helper && go build -o "
                f"$HOME/.local/bin/{self.HELPER_BINARY} .) or download a "
                "release binary from the GitHub Releases page."
            )
        proc = _HelperProcess(binary, label="lattigo helper")
        # Hello round-trip — verifies the binary speaks our protocol
        # version. Mismatches surface as RuntimeError.
        hello = proc.request({"op": "hello"})
        if hello.get("version") != _PROTOCOL_VERSION:
            raise RuntimeError(
                f"lattigo helper version {hello.get('version')!r} does not "
                f"match adapter protocol {_PROTOCOL_VERSION!r}; rebuild "
                "the helper or upgrade fhe-attack-replay."
            )
        if scheme.upper() not in hello.get("scheme_support", []):
            raise NotImplementedError(
                f"lattigo helper does not advertise scheme {scheme!r} "
                f"(supports: {hello.get('scheme_support', [])})."
            )
        # Map common cross-adapter aliases to the helper's wire keys.
        # `ring_dimension` (OpenFHE) and `coeff_modulus_bits` (OpenFHE)
        # are accepted alongside the helper's native `poly_degree` /
        # `log_q` so a single `params.json` can drive multiple adapters.
        helper_params: dict[str, Any] = dict(params)
        if "poly_degree" not in helper_params and "ring_dimension" in params:
            helper_params["poly_degree"] = params["ring_dimension"]
        if "log_q" not in helper_params and "coeff_modulus_bits" in params:
            helper_params["log_q"] = params["coeff_modulus_bits"]
        # Two-phase setup: ask the helper for delta first (with flooding
        # disabled), then re-call setup with `noise_flooding_sigma`
        # derived from delta when the user declared a recognized
        # mitigation label but no explicit sigma. The helper itself
        # doesn't know about Cheon thresholds; the policy lives here.
        if (
            _params_recognize_flooding(params)
            and helper_params.get("noise_flooding_sigma") in (None, 0)
        ):
            probe = proc.request(
                {"op": "setup", "scheme": scheme.upper(), "params": helper_params}
            )
            delta = int(probe["delta"])
            sigma = max(1, int(delta * _DEFAULT_FLOODING_SIGMA_FRAC_DELTA))
            helper_params["noise_flooding_sigma"] = str(sigma)
        # JSON cannot represent ints > 2^53 cleanly; force string
        # encoding for any large explicit sigma.
        sigma_value = helper_params.get("noise_flooding_sigma")
        if isinstance(sigma_value, int) and abs(sigma_value) > (1 << 53) - 1:
            helper_params["noise_flooding_sigma"] = str(sigma_value)
        setup = proc.request(
            {"op": "setup", "scheme": scheme.upper(), "params": helper_params}
        )
        flooding_active = bool(setup.get("noise_flooding_active", False))
        flooding_sigma_str = setup.get("noise_flooding_sigma")
        return AdapterContext(
            library=self.name,
            scheme=scheme.upper(),
            params=params,
            handles={
                "helper": proc,
                "scheme": scheme.upper(),
                "context_id": setup["context_id"],
                "poly_degree": int(setup["poly_degree"]),
                "plaintext_modulus": int(setup["plaintext_modulus"]),
                "delta": int(setup["delta"]),
                "ciphertext_modulus": int(setup["ciphertext_modulus"]),
                "ciphertext_modulus_bits": int(setup["ciphertext_modulus_bits"]),
                "dcrt_tower_count": int(setup["dcrt_tower_count"]),
                "dcrt_moduli_bits": list(setup["dcrt_moduli_bits"]),
                "noise_flooding_active": flooding_active,
                "noise_flooding_sigma": (
                    int(flooding_sigma_str) if flooding_sigma_str else 0
                ),
            },
        )

    def encrypt(self, ctx: AdapterContext, plaintext: Any) -> Any:
        proc: _HelperProcess = ctx.handles["helper"]
        if isinstance(plaintext, list):
            values = [int(v) for v in plaintext]
        elif isinstance(plaintext, (int, bool)):
            values = [int(plaintext)]
        elif plaintext is None:
            values = [0]
        else:
            values = [int(v) for v in plaintext]
        response = proc.request(
            {
                "op": "encrypt",
                "context_id": ctx.handles["context_id"],
                "values": values,
            }
        )
        return response["ciphertext_id"]

    def decrypt(self, ctx: AdapterContext, ciphertext: Any) -> Any:
        proc: _HelperProcess = ctx.handles["helper"]
        response = proc.request(
            {
                "op": "decrypt",
                "context_id": ctx.handles["context_id"],
                "ciphertext_id": ciphertext,
            }
        )
        return list(response.get("values", []))

    def perturb_ciphertext_constant(
        self,
        ctx: AdapterContext,
        ciphertext: Any,
        offset: int,
        *,
        component: int = 0,
    ) -> Any:
        proc: _HelperProcess = ctx.handles["helper"]
        # The helper accepts offset as either a JSON number (small ints
        # round-trip cleanly) or a decimal string (production-bit-size
        # delta = floor(Q/t) overflows int64). Send anything outside
        # int64's safe-magnitude window as a string.
        wire_offset: int | str = int(offset)
        if abs(wire_offset) > (1 << 53) - 1:
            wire_offset = str(int(offset))
        response = proc.request(
            {
                "op": "perturb_constant",
                "context_id": ctx.handles["context_id"],
                "ciphertext_id": ciphertext,
                "offset": wire_offset,
                "component": int(component),
            }
        )
        return response["ciphertext_id"]

    def plaintext_delta(self, ctx: AdapterContext, ciphertext: Any) -> int:
        # The helper computes delta = floor(Q/t) once at setup and
        # echoes it from plaintext_delta; the cached value matches.
        return int(ctx.handles["delta"])

    def seed_replay_rng(self, ctx: AdapterContext, seed: int) -> None:
        """Re-seed the helper's flooding RNG for per-trial independence.

        Called by Cheon's `_seed_trial` between bisection trials so each
        trial's flooding sequence is independent. Without this, the
        across-trial variance signal that distinguishes a flooded oracle
        collapses (every trial sees the same flood sequence) and the
        SAFE-via-Replay path would falsely report VULNERABLE.
        """
        if not ctx.handles.get("noise_flooding_active"):
            return
        proc: _HelperProcess = ctx.handles["helper"]
        # Helper accepts int64 seed. Wrap the master seed mod 2^63 to
        # stay in range; the helper's PRNG is seeded fresh per call so
        # collisions with prior seeds are not a concern.
        wire_seed = int(seed) & ((1 << 63) - 1)
        proc.request(
            {
                "op": "set_seed",
                "context_id": ctx.handles["context_id"],
                "seed": wire_seed,
            }
        )

    def polynomial_replay_metadata(
        self, ctx: AdapterContext, ciphertext: Any
    ) -> dict[str, Any]:
        return {
            "serialization_backend": "lattigo-bgv",
            "polynomial_domain": "RNS evaluation form (NTT)",
            "perturbation": "constant added per-tower to ciphertext component c0",
            "plaintext_modulus": int(ctx.handles["plaintext_modulus"]),
            "ciphertext_modulus_bits": int(ctx.handles["ciphertext_modulus_bits"]),
            "dcrt_tower_count": int(ctx.handles["dcrt_tower_count"]),
            "dcrt_moduli_bits": list(ctx.handles["dcrt_moduli_bits"]),
            "software_flooding_active": bool(ctx.handles.get("noise_flooding_active", False)),
            "software_flooding_sigma": int(ctx.handles.get("noise_flooding_sigma", 0)),
        }

    def evaluator_fingerprint(self, ctx: AdapterContext) -> dict[str, Any]:
        return {
            "implementation": "tuneinsight/lattigo",
            "ntt_variant": "harvey-butterfly",
            "constant_time_decrypt": False,
        }
