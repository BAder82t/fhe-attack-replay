# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Schema regression tests for the OpenFHE-JSON ciphertext layout.

The OpenFHE adapter mutates ciphertexts via the cereal-archive JSON
representation because openfhe-python does not expose mutable DCRTPoly
APIs. The tests below freeze the JSON path resolution so a future
openfhe-python release that reshapes the archive surfaces as a loud test
failure instead of silent corruption.

These tests do not require ``openfhe-python`` to be importable — they
operate on a captured payload in ``tests/fixtures/``.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from fhe_attack_replay.adapters.openfhe import OpenFHEAdapter

FIXTURE = Path(__file__).parent / "fixtures" / "openfhe_bfv_ciphertext.json"


@pytest.fixture()
def payload() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_component_towers_resolves_for_component_zero(payload):
    towers = OpenFHEAdapter._component_towers(payload, component=0)
    assert isinstance(towers, list)
    assert len(towers) == 2  # two DCRT towers in component c0


def test_component_towers_resolves_for_component_one(payload):
    towers = OpenFHEAdapter._component_towers(payload, component=1)
    assert len(towers) == 1


def test_component_moduli_returns_int_tuple(payload):
    moduli = OpenFHEAdapter._component_moduli(payload, component=0)
    assert moduli == (1099511627791, 2199023255579)
    for m in moduli:
        assert isinstance(m, int)


def test_perturb_ciphertext_constant_round_trip(payload):
    """End-to-end mutation against the captured payload.

    Patches ``_serialize_ciphertext`` / ``_deserialize_ciphertext`` to
    operate on the in-memory dict so we can exercise the perturbation logic
    without an OpenFHE build. The mutated ciphertext should reflect
    `(coeff + offset) mod modulus` for every coefficient in component c0.
    """
    adapter = OpenFHEAdapter()
    handle = {"openfhe": None}

    class _StubCtx:
        handles = handle
        scheme = "BFV"
        params: dict = {}
        library = "openfhe"

    def _serialize(_ctx, ciphertext):
        return copy.deepcopy(ciphertext)

    def _deserialize(_ctx, p):
        return p

    adapter._serialize_ciphertext = _serialize  # type: ignore[assignment]
    adapter._deserialize_ciphertext = _deserialize  # type: ignore[assignment]

    perturbed = adapter.perturb_ciphertext_constant(_StubCtx(), payload, 7, component=0)
    towers = OpenFHEAdapter._component_towers(perturbed, component=0)
    # tower 0: modulus 1099511627791, original [11,22,33,44] => +7
    coeffs0 = towers[0]["v"]["ptr_wrapper"]["data"]["v"]
    assert coeffs0 == [18, 29, 40, 51]
    # tower 1: modulus 2199023255579, original [101,202,303,404] => +7
    coeffs1 = towers[1]["v"]["ptr_wrapper"]["data"]["v"]
    assert coeffs1 == [108, 209, 310, 411]
    # component c1 must be untouched
    untouched = OpenFHEAdapter._component_towers(perturbed, component=1)[0][
        "v"
    ]["ptr_wrapper"]["data"]["v"]
    assert untouched == [55, 66, 77, 88]


def test_perturb_with_negative_offset_wraps_modulo(payload):
    adapter = OpenFHEAdapter()
    handle = {"openfhe": None}

    class _StubCtx:
        handles = handle
        scheme = "BFV"
        params: dict = {}
        library = "openfhe"

    adapter._serialize_ciphertext = lambda _ctx, ct: copy.deepcopy(ct)  # type: ignore[assignment]
    adapter._deserialize_ciphertext = lambda _ctx, p: p  # type: ignore[assignment]

    perturbed = adapter.perturb_ciphertext_constant(_StubCtx(), payload, -1, component=0)
    coeffs0 = OpenFHEAdapter._component_towers(perturbed, component=0)[0][
        "v"
    ]["ptr_wrapper"]["data"]["v"]
    # 11 - 1 = 10, 22 - 1 = 21, etc.
    assert coeffs0 == [10, 21, 32, 43]


def test_unknown_archive_path_raises_keyerror(payload):
    """If openfhe-python ships a reshaped archive (e.g. drops ``ptr_wrapper``),
    the path resolver should fail loudly with ``KeyError`` rather than
    silently returning empty towers."""
    broken = copy.deepcopy(payload)
    del broken["value0"]["ptr_wrapper"]
    with pytest.raises(KeyError):
        OpenFHEAdapter._component_towers(broken, component=0)
