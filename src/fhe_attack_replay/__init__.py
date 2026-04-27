# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""fhe-attack-replay: unified attack-replay regression harness for FHE libraries."""

from fhe_attack_replay.adapters.base import LibraryAdapter
from fhe_attack_replay.attacks.base import Attack, AttackIntent, AttackResult, AttackStatus
from fhe_attack_replay.registry import (
    list_adapters,
    list_attacks,
    register_adapter,
    register_attack,
    resolve_adapter,
    resolve_attack,
)
from fhe_attack_replay.runner import Coverage, RunReport, run

__version__ = "0.1.1"

__all__ = [
    "Attack",
    "AttackIntent",
    "AttackResult",
    "AttackStatus",
    "Coverage",
    "LibraryAdapter",
    "RunReport",
    "list_adapters",
    "list_attacks",
    "register_adapter",
    "register_attack",
    "resolve_adapter",
    "resolve_attack",
    "run",
]
