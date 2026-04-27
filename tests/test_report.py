# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

from fhe_attack_replay import run
from fhe_attack_replay.report import to_json, to_svg_badge, write_json, write_svg_badge


def _example_report():
    return run(library="openfhe", params={"scheme": "BFV"}, attacks=None)


def test_to_json_round_trips_with_coverage_block():
    report = _example_report()
    payload = json.loads(to_json(report))
    assert payload["library"] == "openfhe"
    assert "overall_status" in payload
    assert isinstance(payload["results"], list)
    assert isinstance(payload["coverage"], dict)
    assert payload["coverage"]["requested"] == len(payload["results"])
    assert "ratio" in payload["coverage"]


def test_write_json_creates_parent_dir(tmp_path: Path):
    report = _example_report()
    out = tmp_path / "nested" / "report.json"
    write_json(report, out)
    assert out.exists()
    payload = json.loads(out.read_text())
    assert payload["library"] == "openfhe"
    assert "coverage" in payload


def test_to_svg_badge_emits_svg_with_implemented_label():
    report = _example_report()
    svg = to_svg_badge(report)
    assert svg.startswith("<svg")
    assert "fhe-attack-replay" in svg
    # All scaffolds today: badge should expose coverage, not just "scaffold".
    assert "implemented" in svg or "vulnerable" in svg or "safe" in svg
    assert svg.endswith("</svg>")


def test_write_svg_badge_creates_file(tmp_path: Path):
    out = tmp_path / "badge.svg"
    write_svg_badge(_example_report(), out)
    assert out.exists()
    assert out.read_text().startswith("<svg")
