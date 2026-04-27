# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Shared pytest fixtures.

The registry-snapshot fixture below restores the global adapter/attack
maps between tests. Without it, tests that ``register_adapter`` or
``register_attack`` ad-hoc subclasses would leak those entries into
``run(..., attacks=None)`` runs in later tests and break length-based
assertions on the default attack set.
"""

from __future__ import annotations

import pytest

from fhe_attack_replay.adapters.base import AdapterContext, LibraryAdapter
from fhe_attack_replay.attacks.base import (
    Attack,
    AttackIntent,
    AttackResult,
    AttackStatus,
)
from fhe_attack_replay.registry import _ADAPTERS, _ATTACKS


@pytest.fixture(autouse=True)
def _registry_isolation():
    adapters_before = dict(_ADAPTERS)
    attacks_before = dict(_ATTACKS)
    try:
        yield
    finally:
        _ADAPTERS.clear()
        _ADAPTERS.update(adapters_before)
        _ATTACKS.clear()
        _ATTACKS.update(attacks_before)


class _PendingScaffoldAttack(Attack):
    """Test-only attack that always returns NOT_IMPLEMENTED.

    The CHANGELOG rolled every shipped module out of NOT_IMPLEMENTED
    after the in-tree analyzers landed (eprint-2025-867 timing,
    glitchfhe-usenix25 differential, reveal-2023-1128 correlation).
    Runner / CLI tests that need to exercise the NOT_IMPLEMENTED exit
    path therefore register this synthetic attack instead of leaning on
    a scaffolded production module that no longer exists.
    """

    id = "test-pending-scaffold"
    title = "Pending Scaffold (test-only NOT_IMPLEMENTED attack)"
    applies_to_schemes = ("BFV", "CKKS", "BGV", "LWE", "TFHE")
    intent = AttackIntent.RISK_CHECK

    def run(self, adapter: LibraryAdapter, ctx: AdapterContext) -> AttackResult:
        return AttackResult(
            attack=self.id,
            library=adapter.name,
            scheme=ctx.scheme,
            status=AttackStatus.NOT_IMPLEMENTED,
            duration_seconds=0.0,
            evidence={"reason": "test-only scaffold"},
            message="Test scaffold; the in-tree analyzer is intentionally absent.",
        )


@pytest.fixture()
def pending_attack_id():
    """Register the synthetic NOT_IMPLEMENTED attack and return its id.

    Restoration of the global ``_ATTACKS`` map is handled by the
    autouse ``_registry_isolation`` fixture above.
    """
    _ATTACKS[_PendingScaffoldAttack.id] = _PendingScaffoldAttack
    return _PendingScaffoldAttack.id
