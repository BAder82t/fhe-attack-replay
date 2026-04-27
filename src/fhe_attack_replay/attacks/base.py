# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from fhe_attack_replay.adapters.base import AdapterContext, LibraryAdapter


class AttackStatus(StrEnum):
    """Outcome of an attack replay against a (library, params) target.

    VULNERABLE: the attack succeeded — the target reproduces the published break.
    SAFE:       the attack ran end-to-end and the target resisted it.
    SKIPPED:    the attack does not apply (wrong scheme, capability mismatch).
    NOT_IMPLEMENTED: the replay logic for this attack is still a scaffold.
    ERROR:      the replay raised an unexpected exception.
    """

    VULNERABLE = "vulnerable"
    SAFE = "safe"
    SKIPPED = "skipped"
    NOT_IMPLEMENTED = "not_implemented"
    ERROR = "error"


class AttackIntent(StrEnum):
    """How a module decides VULNERABLE/SAFE.

    REPLAY:        runs the exploit logic end-to-end against live ciphertexts.
    RISK_CHECK:    detects known-vulnerable parameter/config patterns statically.
    ARTIFACT_CHECK: validates traces, logs, or evidence files supplied by the user.

    A SAFE result from a REPLAY is stronger than a SAFE from a RISK_CHECK,
    which is stronger than a SAFE from an ARTIFACT_CHECK on user-supplied
    evidence. See docs/status-semantics.md.
    """

    REPLAY = "replay"
    RISK_CHECK = "risk_check"
    ARTIFACT_CHECK = "artifact_check"


@dataclass
class Citation:
    title: str
    authors: str
    venue: str
    year: int
    url: str
    eprint: str | None = None


@dataclass
class AttackResult:
    attack: str
    library: str
    scheme: str
    status: AttackStatus
    duration_seconds: float
    intent: AttackIntent = AttackIntent.REPLAY
    evidence: dict[str, Any] = field(default_factory=dict)
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["intent"] = self.intent.value
        return d


class Attack(ABC):
    """A single replayable attack against an FHE library.

    Subclasses encode one published attack. The `run` method receives a fully
    set-up AdapterContext and returns an AttackResult. The harness is
    responsible for timing, error wrapping, and reporting — subclasses focus
    on the attack itself.
    """

    id: str = ""
    title: str = ""
    applies_to_schemes: tuple[str, ...] = ()
    citation: Citation | None = None
    intent: AttackIntent = AttackIntent.REPLAY

    def applies(self, adapter: LibraryAdapter, scheme: str) -> bool:
        if not self.applies_to_schemes:
            return True
        return scheme in self.applies_to_schemes

    @abstractmethod
    def run(self, adapter: LibraryAdapter, ctx: AdapterContext) -> AttackResult:
        """Replay the attack against the live (adapter, ctx). Return a result."""
