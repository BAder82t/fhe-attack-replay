# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from fhe_attack_replay import __version__
from fhe_attack_replay.registry import list_adapters, list_attacks, resolve_adapter
from fhe_attack_replay.report import to_json, write_json, write_svg_badge
from fhe_attack_replay.runner import RunReport, run

EXIT_OK = 0
EXIT_VULNERABLE = 2
EXIT_ERROR = 3
EXIT_NOT_IMPLEMENTED = 4
EXIT_ALL_SKIPPED = 5
EXIT_USAGE = 64


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fhe-replay",
        description=(
            "Framework for replaying published FHE attacks against a "
            "(library, params) target. Emits a JSON report and an SVG status "
            "badge. NOT_IMPLEMENTED never silently passes by default — green "
            "CI requires real results."
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

    sub.add_parser(
        "doctor",
        help="Show adapter availability and native dependency notes.",
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
    p.add_argument(
        "--allow-not-implemented",
        action="store_true",
        help="Treat NOT_IMPLEMENTED results as success (exit 0). Off by default.",
    )
    p.add_argument(
        "--allow-skipped",
        action="store_true",
        help="Treat all-SKIPPED runs as success (exit 0). Off by default.",
    )
    p.add_argument(
        "--min-coverage",
        type=float,
        default=None,
        help=(
            "Require coverage.ratio to be at least this value (0.0-1.0). "
            "Checked after status exits such as VULNERABLE/ERROR."
        ),
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


def _exit_code_for(
    report: RunReport,
    *,
    allow_not_implemented: bool,
    allow_skipped: bool,
) -> int:
    cov = report.coverage
    if cov.vulnerable > 0:
        return EXIT_VULNERABLE
    if cov.errors > 0:
        return EXIT_ERROR
    if cov.not_implemented > 0 and not allow_not_implemented:
        return EXIT_NOT_IMPLEMENTED
    if cov.ran == 0 and cov.skipped > 0 and not allow_skipped:
        return EXIT_ALL_SKIPPED
    return EXIT_OK


def _cmd_list(what: str) -> int:
    if what in ("libraries", "all"):
        print("libraries:")
        for name in list_adapters():
            print(f"  - {name}")
    if what in ("attacks", "all"):
        print("attacks:")
        for attack_id in list_attacks():
            print(f"  - {attack_id}")
    return EXIT_OK


def _cmd_doctor() -> int:
    print("adapter status:")
    for name in list_adapters():
        adapter = resolve_adapter(name)
        try:
            available = adapter.is_available()
            error = ""
        except Exception as exc:  # pragma: no cover - defensive for native imports
            available = False
            error = f" ({type(exc).__name__}: {exc})"
        status = "available" if available else "missing"
        native = "native dependency" if adapter.capability.requires_native else "in-tree"
        schemes = ", ".join(adapter.capability.schemes) or "none"
        print(f"  - {name}: {status} [{native}; schemes: {schemes}]{error}")
        if adapter.capability.notes:
            print(f"    note: {adapter.capability.notes}")
    print()
    print("Use `fhe-replay run --lib toy-lwe ...` for a dependency-free live replay.")
    print("Native adapters can still run RiskCheck paths when their bindings are missing.")
    return EXIT_OK


def _cmd_run(args: argparse.Namespace) -> int:
    if not args.lib:
        print("error: --lib is required for `run`.", file=sys.stderr)
        return EXIT_USAGE
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

    rc = _exit_code_for(
        report,
        allow_not_implemented=args.allow_not_implemented,
        allow_skipped=args.allow_skipped,
    )
    if (
        rc == EXIT_OK
        and args.min_coverage is not None
        and report.coverage.ratio < args.min_coverage
    ):
        print(
            f"warning: implemented coverage {report.coverage.ratio:.4f} is below "
            f"--min-coverage {args.min_coverage:.4f}.",
            file=sys.stderr,
        )
        return EXIT_NOT_IMPLEMENTED
    if rc == EXIT_NOT_IMPLEMENTED:
        print(
            f"warning: {report.coverage.not_implemented}/{report.coverage.requested} "
            "selected attack(s) are NOT_IMPLEMENTED. Pass --allow-not-implemented "
            "to treat as success.",
            file=sys.stderr,
        )
    elif rc == EXIT_ALL_SKIPPED:
        print(
            "warning: every selected attack was SKIPPED; no attack actually ran. "
            "Pass --allow-skipped to treat as success.",
            file=sys.stderr,
        )
    return rc


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "list":
        return _cmd_list(args.what)
    if args.command == "doctor":
        return _cmd_doctor()
    return _cmd_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
