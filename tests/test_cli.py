# Copyright 2026 Vaultbytes (Bader Issaei)
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

import pytest

from fhe_attack_replay.cli import (
    EXIT_ALL_SKIPPED,
    EXIT_NOT_IMPLEMENTED,
    EXIT_OK,
    EXIT_USAGE,
    main,
)


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_cli_list_all(capsys):
    rc = main(["list", "all"])
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert "libraries:" in out
    assert "attacks:" in out
    assert "openfhe" in out
    assert "cheon-2024-127" in out


def test_cli_run_writes_report_and_badge_with_not_implemented_exit(tmp_path: Path):
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
    # Default: NOT_IMPLEMENTED is a hard fail.
    assert rc == EXIT_NOT_IMPLEMENTED
    payload = json.loads(out.read_text())
    assert payload["library"] == "openfhe"
    assert "coverage" in payload
    assert payload["coverage"]["requested"] >= 1
    assert badge.read_text().startswith("<svg")


def test_cli_run_allow_not_implemented_returns_ok(tmp_path: Path):
    params = tmp_path / "params.json"
    params.write_text(json.dumps({"scheme": "BFV"}))
    out = tmp_path / "report.json"
    rc = main(
        [
            "run",
            "--lib",
            "openfhe",
            "--params",
            str(params),
            "--attacks",
            "cheon-2024-127",
            "--output-json",
            str(out),
            "--allow-not-implemented",
            "--quiet",
        ]
    )
    assert rc == EXIT_OK


def test_cli_run_only_skipped_returns_5(tmp_path: Path):
    # GuoQian is CKKS-only; running it with BFV makes the run all-skipped.
    params = tmp_path / "params.json"
    params.write_text(json.dumps({"scheme": "BFV"}))
    out = tmp_path / "report.json"
    rc = main(
        [
            "run",
            "--lib",
            "openfhe",
            "--params",
            str(params),
            "--attacks",
            "guo-qian-usenix24",
            "--output-json",
            str(out),
            "--quiet",
        ]
    )
    assert rc == EXIT_ALL_SKIPPED


def test_cli_run_only_skipped_allow_skipped_returns_ok(tmp_path: Path):
    params = tmp_path / "params.json"
    params.write_text(json.dumps({"scheme": "BFV"}))
    out = tmp_path / "report.json"
    rc = main(
        [
            "run",
            "--lib",
            "openfhe",
            "--params",
            str(params),
            "--attacks",
            "guo-qian-usenix24",
            "--output-json",
            str(out),
            "--allow-skipped",
            "--quiet",
        ]
    )
    assert rc == EXIT_OK


def test_cli_missing_lib_returns_usage_error(tmp_path: Path):
    params = tmp_path / "params.json"
    params.write_text(json.dumps({"scheme": "BFV"}))
    rc = main(["run", "--params", str(params)])
    assert rc == EXIT_USAGE
