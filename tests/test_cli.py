# Copyright 2026 Vaultbytes (Bader Issaei)
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

import pytest

from fhe_attack_replay.cli import main


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_cli_list_all(capsys):
    rc = main(["list", "all"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "libraries:" in out
    assert "attacks:" in out
    assert "openfhe" in out
    assert "cheon-2024-127" in out


def test_cli_run_writes_report_and_badge(tmp_path: Path):
    params = tmp_path / "params.json"
    params.write_text(json.dumps({"scheme": "BFV"}))
    out = tmp_path / "report.json"
    badge = tmp_path / "badge.svg"
    rc = main(
        [
            "run",
            "--lib",
            "openfhe",
            "--params",
            str(params),
            "--output-json",
            str(out),
            "--badge",
            str(badge),
            "--quiet",
        ]
    )
    assert rc == 0
    payload = json.loads(out.read_text())
    assert payload["library"] == "openfhe"
    assert badge.read_text().startswith("<svg")


def test_cli_missing_lib_returns_usage_error(tmp_path: Path):
    params = tmp_path / "params.json"
    params.write_text(json.dumps({"scheme": "BFV"}))
    rc = main(["run", "--params", str(params)])
    assert rc == 64
