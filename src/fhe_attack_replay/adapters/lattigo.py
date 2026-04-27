# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Adapter for tuneinsight/lattigo (Go).

Lattigo is pure Go; this adapter shells out to a small Go helper binary
(``fhe-replay-lattigo-helper``, source under ``vendor/lattigo-helper/``)
that exposes the primitives the harness needs over a JSON protocol on
stdin/stdout. The Python side spawns the helper, exchanges
line-delimited JSON, and parses responses.

**Status**: the Go helper is currently a scaffold (only ``hello`` and
``shutdown`` are implemented). The adapter therefore:

- ``is_available()`` returns True iff the helper is on PATH.
- ``setup()`` spawns the helper, does a ``hello`` round-trip to verify
  it speaks our protocol version, and returns a context that owns the
  subprocess handle.
- ``encrypt()`` / ``decrypt()`` / ``perturb_ciphertext_constant()`` /
  ``plaintext_delta()`` issue the corresponding JSON requests; the
  helper responds with an explicit
  ``{"error":"… not yet implemented …"}`` which we surface as
  ``RuntimeError``. The harness then records the result as ``ERROR``
  per the documented "no false-positive verdicts" contract.

Once the helper's ops are wired (lattigo BFV/BGV bindings against
``github.com/tuneinsight/lattigo/v6``) this adapter starts producing
real verdicts without any further Python changes — the wire protocol
is the contract.
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

_PROTOCOL_VERSION = "0.1.0"


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


class LattigoAdapter(LibraryAdapter):
    """Adapter for tuneinsight/lattigo via the Go helper binary."""

    name = "lattigo"
    capability = AdapterCapability(
        schemes=("BFV", "BGV", "CKKS"),
        requires_native=True,
        live_oracle=False,  # flips to True once the helper's ops land
        notes=(
            "Requires fhe-replay-lattigo-helper on PATH (build from "
            "vendor/lattigo-helper). Helper currently a scaffold — "
            "encrypt/decrypt/perturb ops surface as ERROR until lattigo "
            "wiring lands."
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
                "release binary."
            )
        proc = _HelperProcess(binary, label="lattigo helper")
        # hello round-trip — verifies the binary speaks our protocol
        # version. Mismatches are surfaced as RuntimeError.
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

    def perturb_ciphertext_constant(
        self,
        ctx: AdapterContext,
        ciphertext: Any,
        offset: int,
        *,
        component: int = 0,
    ) -> Any:
        proc: _HelperProcess = ctx.handles["helper"]
        response = proc.request(
            {
                "op": "perturb_constant",
                "context_id": ctx.handles.get("context_id", ""),
                "ciphertext_id": ciphertext,
                "offset": int(offset),
                "component": int(component),
            }
        )
        return response.get("ciphertext_id")

    def plaintext_delta(self, ctx: AdapterContext, ciphertext: Any) -> int:
        proc: _HelperProcess = ctx.handles["helper"]
        response = proc.request(
            {
                "op": "plaintext_delta",
                "context_id": ctx.handles.get("context_id", ""),
                "ciphertext_id": ciphertext,
            }
        )
        return int(response.get("delta", 0))

    def evaluator_fingerprint(self, ctx: AdapterContext) -> dict[str, Any]:
        return {
            "implementation": "tuneinsight/lattigo",
            "ntt_variant": "harvey-butterfly",
            "constant_time_decrypt": False,
        }
