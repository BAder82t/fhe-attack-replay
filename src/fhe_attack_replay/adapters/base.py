# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AdapterCapability:
    """Static metadata describing what schemes/modes an adapter supports.

    `live_oracle` is True when the adapter can drive end-to-end encrypt/
    perturb/decrypt against a real (or in-tree) cryptosystem. Attacks that
    run a live Replay (e.g. cheon-2024-127) gate on this flag; adapters that
    are still scaffolds (Lattigo, tfhe-rs) leave it False so attacks fall
    back to the RiskCheck path automatically.
    """

    schemes: tuple[str, ...]
    requires_native: bool = True
    live_oracle: bool = False
    notes: str = ""


@dataclass
class AdapterContext:
    """Live state shared between an adapter and an attack module.

    Adapters set up keys, encoders, and a ciphertext factory; attacks consume
    these without needing to know the underlying library.
    """

    library: str
    scheme: str
    params: dict[str, Any]
    handles: dict[str, Any] = field(default_factory=dict)


class LibraryAdapter(ABC):
    """Abstract adapter that bridges a single FHE library into the replay harness.

    Concrete adapters (OpenFHE/SEAL/Lattigo/tfhe-rs) translate the harness's
    library-agnostic primitives — keygen, encrypt, decrypt, mul, evaluator
    fingerprint — into native calls. Attack modules consume the resulting
    AdapterContext and never import the underlying library directly.
    """

    name: str = ""
    capability: AdapterCapability = AdapterCapability(schemes=())

    @abstractmethod
    def is_available(self) -> bool:
        """Return True when the underlying library is importable and usable."""

    @abstractmethod
    def setup(self, scheme: str, params: dict[str, Any]) -> AdapterContext:
        """Build keys/encoders for (scheme, params); return an AdapterContext."""

    @abstractmethod
    def encrypt(self, ctx: AdapterContext, plaintext: Any) -> Any: ...

    @abstractmethod
    def decrypt(self, ctx: AdapterContext, ciphertext: Any) -> Any: ...

    @abstractmethod
    def evaluator_fingerprint(self, ctx: AdapterContext) -> dict[str, Any]:
        """Return a dict describing the active evaluator path.

        Used by attacks (e.g. eprint 2025/867) that target specific
        NTT/butterfly variants. Keys vary per library but should at minimum
        carry: implementation, ntt_variant, constant_time_decrypt.
        """

    def supports(self, scheme: str) -> bool:
        return scheme in self.capability.schemes
