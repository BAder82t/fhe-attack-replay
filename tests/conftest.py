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
