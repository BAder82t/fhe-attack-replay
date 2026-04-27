# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from fhe_attack_replay.adapters import (
    LattigoAdapter,
    LibraryAdapter,
    OpenFHEAdapter,
    SEALAdapter,
    TfheRsAdapter,
    ToyLWEAdapter,
)
from fhe_attack_replay.attacks import (
    Attack,
    Cheon2024_127,
    Eprint2025_867,
    GlitchFHE_USENIX25,
    GuoQian_USENIX24,
    RevEAL_2023_1128,
)

_ADAPTERS: dict[str, type[LibraryAdapter]] = {
    OpenFHEAdapter.name: OpenFHEAdapter,
    SEALAdapter.name: SEALAdapter,
    LattigoAdapter.name: LattigoAdapter,
    TfheRsAdapter.name: TfheRsAdapter,
    ToyLWEAdapter.name: ToyLWEAdapter,
}

_ATTACKS: dict[str, type[Attack]] = {
    Cheon2024_127.id: Cheon2024_127,
    RevEAL_2023_1128.id: RevEAL_2023_1128,
    Eprint2025_867.id: Eprint2025_867,
    GuoQian_USENIX24.id: GuoQian_USENIX24,
    GlitchFHE_USENIX25.id: GlitchFHE_USENIX25,
}


def register_adapter(adapter_cls: type[LibraryAdapter]) -> None:
    if not adapter_cls.name:
        raise ValueError("LibraryAdapter subclasses must define a non-empty `name`.")
    _ADAPTERS[adapter_cls.name] = adapter_cls


def register_attack(attack_cls: type[Attack]) -> None:
    if not attack_cls.id:
        raise ValueError("Attack subclasses must define a non-empty `id`.")
    _ATTACKS[attack_cls.id] = attack_cls


def list_adapters() -> list[str]:
    return sorted(_ADAPTERS)


def list_attacks() -> list[str]:
    return sorted(_ATTACKS)


def resolve_adapter(name: str) -> LibraryAdapter:
    try:
        cls = _ADAPTERS[name]
    except KeyError as exc:
        raise KeyError(
            f"Unknown library {name!r}. Known: {', '.join(list_adapters())}."
        ) from exc
    return cls()


def resolve_attack(attack_id: str) -> Attack:
    try:
        cls = _ATTACKS[attack_id]
    except KeyError as exc:
        raise KeyError(
            f"Unknown attack {attack_id!r}. Known: {', '.join(list_attacks())}."
        ) from exc
    return cls()
