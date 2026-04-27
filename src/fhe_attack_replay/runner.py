# Copyright 2026 Vaultbytes (Bader Issaei)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import time
import traceback
from dataclasses import asdict, dataclass, field
from typing import Any

from fhe_attack_replay.adapters.base import AdapterContext, LibraryAdapter
from fhe_attack_replay.attacks.base import Attack, AttackResult, AttackStatus
from fhe_attack_replay.registry import list_attacks, resolve_adapter, resolve_attack


@dataclass
class RunReport:
    library: str
    scheme: str
    params: dict[str, Any]
    results: list[AttackResult] = field(default_factory=list)

    @property
    def overall_status(self) -> AttackStatus:
        for r in self.results:
            if r.status is AttackStatus.VULNERABLE:
                return AttackStatus.VULNERABLE
        for r in self.results:
            if r.status is AttackStatus.ERROR:
                return AttackStatus.ERROR
        if self.results and all(
            r.status in (AttackStatus.SAFE, AttackStatus.SKIPPED) for r in self.results
        ):
            return AttackStatus.SAFE
        return AttackStatus.NOT_IMPLEMENTED

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["results"] = [r.to_dict() for r in self.results]
        d["overall_status"] = self.overall_status.value
        return d


def _run_one(adapter: LibraryAdapter, ctx: AdapterContext, attack: Attack) -> AttackResult:
    if not attack.applies(adapter, ctx.scheme):
        return AttackResult(
            attack=attack.id,
            library=adapter.name,
            scheme=ctx.scheme,
            status=AttackStatus.SKIPPED,
            duration_seconds=0.0,
            evidence={"reason": f"Attack does not apply to scheme {ctx.scheme!r}."},
        )
    start = time.perf_counter()
    try:
        result = attack.run(adapter, ctx)
    except NotImplementedError as exc:
        return AttackResult(
            attack=attack.id,
            library=adapter.name,
            scheme=ctx.scheme,
            status=AttackStatus.NOT_IMPLEMENTED,
            duration_seconds=time.perf_counter() - start,
            evidence={"exception": repr(exc)},
            message=str(exc),
        )
    except Exception as exc:
        return AttackResult(
            attack=attack.id,
            library=adapter.name,
            scheme=ctx.scheme,
            status=AttackStatus.ERROR,
            duration_seconds=time.perf_counter() - start,
            evidence={"traceback": traceback.format_exc()},
            message=repr(exc),
        )
    if result.duration_seconds == 0.0:
        result.duration_seconds = time.perf_counter() - start
    return result


def _setup_or_synthetic(
    adapter: LibraryAdapter, scheme: str, params: dict[str, Any]
) -> AdapterContext:
    """Set up the adapter or fall back to a synthetic context.

    A synthetic context lets attacks that only need the evaluator fingerprint
    or a parameter snapshot run end-to-end even when no native library is
    installed. Attacks that need real ciphertext/key plumbing will report
    ERROR or NOT_IMPLEMENTED — by design.
    """
    if adapter.is_available():
        return adapter.setup(scheme, params)
    return AdapterContext(library=adapter.name, scheme=scheme, params=params, handles={})


def run(
    library: str,
    params: dict[str, Any],
    attacks: list[str] | None = None,
    scheme: str | None = None,
) -> RunReport:
    """Replay the requested attacks against (library, params).

    `attacks=None` runs every registered attack. `scheme` defaults to
    params["scheme"] if present, else the first scheme the adapter advertises.
    """
    adapter = resolve_adapter(library)
    resolved_scheme = scheme or params.get("scheme")
    if resolved_scheme is None:
        if not adapter.capability.schemes:
            raise ValueError(
                f"Adapter {adapter.name!r} advertises no schemes; pass scheme= explicitly."
            )
        resolved_scheme = adapter.capability.schemes[0]
    ctx = _setup_or_synthetic(adapter, resolved_scheme, params)

    attack_ids = attacks if attacks is not None else list_attacks()
    report = RunReport(library=adapter.name, scheme=resolved_scheme, params=params)
    for attack_id in attack_ids:
        attack = resolve_attack(attack_id)
        report.results.append(_run_one(adapter, ctx, attack))
    return report
