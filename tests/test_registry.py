# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

import pytest

from fhe_attack_replay.adapters.base import LibraryAdapter
from fhe_attack_replay.attacks.base import Attack
from fhe_attack_replay.registry import (
    list_adapters,
    list_attacks,
    resolve_adapter,
    resolve_attack,
)


def test_default_adapters_registered():
    assert set(list_adapters()) >= {"openfhe", "seal", "lattigo", "tfhe-rs"}


def test_default_attacks_registered():
    expected = {
        "cheon-2024-127",
        "reveal-2023-1128",
        "eprint-2025-867",
        "guo-qian-usenix24",
        "glitchfhe-usenix25",
    }
    assert set(list_attacks()) >= expected


def test_resolve_adapter_returns_instance():
    adapter = resolve_adapter("openfhe")
    assert isinstance(adapter, LibraryAdapter)
    assert adapter.name == "openfhe"


def test_resolve_attack_returns_instance():
    attack = resolve_attack("cheon-2024-127")
    assert isinstance(attack, Attack)
    assert attack.id == "cheon-2024-127"
    assert attack.citation is not None
    assert attack.citation.eprint == "2024/127"


def test_resolve_unknown_raises():
    with pytest.raises(KeyError):
        resolve_adapter("does-not-exist")
    with pytest.raises(KeyError):
        resolve_attack("does-not-exist")
