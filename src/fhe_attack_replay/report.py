# Copyright 2026 Vaultbytes (Bader Issaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from fhe_attack_replay.attacks.base import AttackStatus
from fhe_attack_replay.runner import RunReport

_BADGE_COLORS = {
    AttackStatus.SAFE: "#3fb950",
    AttackStatus.VULNERABLE: "#d73a49",
    AttackStatus.ERROR: "#f0883e",
    AttackStatus.SKIPPED: "#8b949e",
    AttackStatus.NOT_IMPLEMENTED: "#dbab09",
}


def to_json(report: RunReport, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, sort_keys=True)


def write_json(report: RunReport, path: str | Path, indent: int = 2) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(to_json(report, indent=indent), encoding="utf-8")
    return p


def _summary_label(report: RunReport) -> tuple[str, str]:
    counts = Counter(r.status for r in report.results)
    overall = report.overall_status
    label = f"{counts[AttackStatus.SAFE]}/{len(report.results)} safe"
    if counts[AttackStatus.VULNERABLE]:
        label = f"{counts[AttackStatus.VULNERABLE]} vulnerable"
    elif counts[AttackStatus.ERROR]:
        label = f"{counts[AttackStatus.ERROR]} error"
    elif counts[AttackStatus.NOT_IMPLEMENTED] == len(report.results):
        label = "scaffold"
    return label, _BADGE_COLORS.get(overall, _BADGE_COLORS[AttackStatus.NOT_IMPLEMENTED])


def to_svg_badge(report: RunReport) -> str:
    """Render a minimal shields.io-style flat SVG badge.

    Self-contained — no network calls, no template engine. Width is computed
    from a fixed-width font approximation; good enough for README embeds.
    """
    label = "fhe-attack-replay"
    value, color = _summary_label(report)
    label_w = 8 + 6 * len(label)
    value_w = 10 + 6 * len(value)
    total_w = label_w + value_w
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20" '
        f'role="img" aria-label="{label}: {value}">'
        f'<linearGradient id="s" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<rect width="{total_w}" height="20" rx="3" fill="#555"/>'
        f'<rect x="{label_w}" width="{value_w}" height="20" rx="3" fill="{color}"/>'
        f'<rect width="{total_w}" height="20" rx="3" fill="url(#s)"/>'
        f'<g fill="#fff" text-anchor="middle" '
        f'font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">'
        f'<text x="{label_w / 2:.1f}" y="14">{label}</text>'
        f'<text x="{label_w + value_w / 2:.1f}" y="14">{value}</text>'
        f"</g></svg>"
    )


def write_svg_badge(report: RunReport, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(to_svg_badge(report), encoding="utf-8")
    return p
