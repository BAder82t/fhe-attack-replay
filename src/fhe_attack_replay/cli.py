# Copyright 2026 Vaultbytes (Bader Issaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from fhe_attack_replay import __version__
from fhe_attack_replay.attacks.base import AttackStatus
from fhe_attack_replay.registry import list_adapters, list_attacks
from fhe_attack_replay.report import to_json, write_json, write_svg_badge
from fhe_attack_replay.runner import run

_EXIT_OK = 0
_EXIT_VULNERABLE = 2
_EXIT_ERROR = 3
_EXIT_USAGE = 64


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fhe-replay",
        description=(
            "Unified attack-replay regression harness for FHE libraries. "
            "Replays published attacks against a (library, params) target and "
            "emits a JSON report plus an optional SVG status badge."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", required=False)

    run_p = sub.add_parser("run", help="Run attack replays (default subcommand).")
    _add_run_args(run_p)

    list_p = sub.add_parser("list", help="List known libraries and attacks.")
    list_p.add_argument(
        "what",
        choices=["libraries", "attacks", "all"],
        nargs="?",
        default="all",
    )

    _add_run_args(parser)
    return parser


def _add_run_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--lib",
        choices=list_adapters(),
        help="Target FHE library.",
    )
    p.add_argument(
        "--params",
        type=Path,
        help="Path to params JSON (scheme, ring degree, modulus, etc.).",
    )
    p.add_argument(
        "--scheme",
        help="Override scheme (default: read from params['scheme']).",
    )
    p.add_argument(
        "--attacks",
        default="all",
        help="Comma-separated attack ids, or 'all'. See `fhe-replay list attacks`.",
    )
    p.add_argument(
        "--output-json",
        type=Path,
        help="Write report JSON to this path (default: stdout).",
    )
    p.add_argument(
        "--badge",
        type=Path,
        help="Write SVG status badge to this path.",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress stdout JSON when --output-json is given.",
    )


def _load_params(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    if not path.exists():
        raise FileNotFoundError(f"params file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_attacks(spec: str) -> list[str] | None:
    if spec.strip().lower() == "all":
        return None
    ids = [s.strip() for s in spec.split(",") if s.strip()]
    if not ids:
        return None
    return ids


def _exit_code_for(status: AttackStatus) -> int:
    if status is AttackStatus.VULNERABLE:
        return _EXIT_VULNERABLE
    if status is AttackStatus.ERROR:
        return _EXIT_ERROR
    return _EXIT_OK


def _cmd_list(what: str) -> int:
    if what in ("libraries", "all"):
        print("libraries:")
        for name in list_adapters():
            print(f"  - {name}")
    if what in ("attacks", "all"):
        print("attacks:")
        for attack_id in list_attacks():
            print(f"  - {attack_id}")
    return _EXIT_OK


def _cmd_run(args: argparse.Namespace) -> int:
    if not args.lib:
        print("error: --lib is required for `run`.", file=sys.stderr)
        return _EXIT_USAGE
    params = _load_params(args.params)
    attacks = _resolve_attacks(args.attacks)
    report = run(library=args.lib, params=params, attacks=attacks, scheme=args.scheme)

    if args.output_json:
        write_json(report, args.output_json)
        if not args.quiet:
            print(to_json(report))
    else:
        print(to_json(report))

    if args.badge:
        write_svg_badge(report, args.badge)

    return _exit_code_for(report.overall_status)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "list":
        return _cmd_list(args.what)
    return _cmd_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
