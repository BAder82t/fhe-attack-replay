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

    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run attack replays.")
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
    p.add_argument(
        "--evidence",
        action="append",
        default=[],
        metavar="KEY=PATH",
        help=(
            "Pass an evidence file to ArtifactCheck attacks (repeatable). "
            "Example: --evidence trace=runs/seal-ntt.npy --evidence model=conf.json. "
            "Files must exist; their paths are surfaced under "
            "params['evidence_paths'][key]."
        ),
    )


def _load_params(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    if not path.exists():
        raise FileNotFoundError(f"params file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _parse_evidence(specs: list[str]) -> dict[str, Path]:
    """Parse `--evidence KEY=PATH` flags into a name→path dict.

    Validates that every path exists; missing files are a usage error
    rather than a runtime ERROR so a typo in CI surfaces immediately.
    """
    out: dict[str, Path] = {}
    for spec in specs:
        if "=" not in spec:
            raise ValueError(
                f"--evidence expects KEY=PATH, got {spec!r}. Example: "
                "--evidence trace=runs/seal-ntt.npy"
            )
        key, _, raw_path = spec.partition("=")
        key = key.strip()
        if not key:
            raise ValueError(
                f"--evidence key is empty in {spec!r}. Example: "
                "--evidence trace=runs/seal-ntt.npy"
            )
        if key in out:
            raise ValueError(
                f"--evidence key {key!r} declared more than once."
            )
        path = Path(raw_path.strip()).expanduser()
        if not path.exists():
            raise FileNotFoundError(
                f"--evidence path for {key!r} not found: {path}"
            )
        out[key] = path
    return out


def _resolve_attacks(spec: str) -> list[str] | None:
    """Parse the --attacks argument into a list of ids or None.

    None means "run every registered attack". An empty/whitespace-only spec
    is a usage error rather than a silent "all" — that mistake in CI
    scripting would defeat the purpose of an explicit attack list.
    """
    stripped = spec.strip()
    if stripped.lower() == "all":
        return None
    ids = [s.strip() for s in stripped.split(",") if s.strip()]
    if not ids:
        raise ValueError(
            "--attacks is empty. Pass 'all' to run every registered attack, "
            "or a comma-separated list of ids (see `fhe-replay list attacks`)."
        )
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
    try:
        params = _load_params(args.params)
        attacks = _resolve_attacks(args.attacks)
        evidence_paths = _parse_evidence(getattr(args, "evidence", []) or [])
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if evidence_paths:
        # Surface as POSIX-style strings so JSON serialization round-trips
        # cleanly. Attacks can reopen via Path(...) when they need the file.
        existing = dict(params.get("evidence_paths") or {})
        existing.update({k: str(v) for k, v in evidence_paths.items()})
        params["evidence_paths"] = existing
    try:
        report = run(library=args.lib, params=params, attacks=attacks, scheme=args.scheme)
    except KeyError as exc:
        # Unknown adapter or attack id — registry raises KeyError.
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:  # pragma: no cover - defensive top-level guard
        print(f"error: replay setup failed: {exc!r}", file=sys.stderr)
        return EXIT_ERROR

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


if __name__ == "__main__":  # pragma: no cover - script entry point
    raise SystemExit(main())
