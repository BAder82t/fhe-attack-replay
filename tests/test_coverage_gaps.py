# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Targeted tests filling the residual coverage gaps after the review-pass.

Exists separately from `test_review_fixes.py` so the review-fix tests stay
focused on behaviour the review called out, while these tests pin
otherwise-untested error paths and adapter branches.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from fhe_attack_replay import run
from fhe_attack_replay.adapters import (
    LattigoAdapter,
    TfheRsAdapter,
)
from fhe_attack_replay.adapters.base import (
    AdapterCapability,
    AdapterContext,
    LibraryAdapter,
)
from fhe_attack_replay.adapters.openfhe import OpenFHEAdapter
from fhe_attack_replay.adapters.seal import SEALAdapter
from fhe_attack_replay.adapters.toy_lwe import ToyLWEAdapter
from fhe_attack_replay.attacks.base import (
    Attack,
    AttackIntent,
    AttackResult,
    AttackStatus,
)
from fhe_attack_replay.attacks.cheon_2024_127 import Cheon2024_127
from fhe_attack_replay.cli import (
    EXIT_ERROR,
    EXIT_NOT_IMPLEMENTED,
    EXIT_OK,
    EXIT_USAGE,
    EXIT_VULNERABLE,
    main,
)
from fhe_attack_replay.lab.toy_lwe import ToyLWE
from fhe_attack_replay.registry import register_adapter, register_attack
from fhe_attack_replay.report import _summary_label, to_svg_badge
from fhe_attack_replay.runner import Coverage, RunReport

# --- toy_lwe lab edge cases ------------------------------------------------


def test_toylwe_rejects_q_not_multiple_of_t():
    with pytest.raises(ValueError, match="multiple of t"):
        ToyLWE(n=8, q=10, t=3)


def test_toylwe_decrypt_creates_default_rng_when_flooded_and_none_passed():
    toy = ToyLWE(n=8, q=1024, t=16, sigma=1.0, noise_flooding_sigma=4.0)
    seed_rng = np.random.default_rng(0)
    keys = toy.keygen(seed_rng)
    ct = toy.encrypt(keys, 0, seed_rng)
    # rng=None forces the decrypt path to instantiate its own default_rng.
    decrypted = toy.decrypt(keys, ct, rng=None)
    assert isinstance(decrypted, int)


# --- toy-lwe adapter encrypt/decrypt/fingerprint -------------------------


def test_toylwe_adapter_encrypt_decrypt_round_trip():
    adapter = ToyLWEAdapter()
    ctx = adapter.setup("LWE", {"n": 8, "q": 1024, "t": 16, "seed": 3})
    ct = adapter.encrypt(ctx, 5)
    pt = adapter.decrypt(ctx, ct)
    assert pt == 5


def test_toylwe_adapter_evaluator_fingerprint_reflects_flooding():
    adapter = ToyLWEAdapter()
    ctx = adapter.setup("LWE", {"noise_flooding_sigma": 7.5, "seed": 11})
    fp = adapter.evaluator_fingerprint(ctx)
    assert fp["implementation"].startswith("fhe-attack-replay toy-lwe")
    assert fp["constant_time_decrypt"] is False
    assert fp["noise_flooding_sigma"] == pytest.approx(7.5)


def test_toylwe_adapter_evaluator_fingerprint_handles_synthetic_context():
    adapter = ToyLWEAdapter()
    synthetic = AdapterContext(library="toy-lwe", scheme="LWE", params={}, handles={})
    fp = adapter.evaluator_fingerprint(synthetic)
    assert fp["noise_flooding_sigma"] == 0.0


# --- Lattigo / tfhe-rs scaffold paths --------------------------------------


def test_lattigo_setup_runtime_error_when_helper_missing(monkeypatch):
    adapter = LattigoAdapter()
    monkeypatch.setattr(
        "fhe_attack_replay.adapters.lattigo.shutil.which", lambda _name: None
    )
    assert adapter.is_available() is False
    with pytest.raises(RuntimeError, match="not on PATH"):
        adapter.setup("BFV", {})


def test_lattigo_setup_not_implemented_when_helper_present(monkeypatch):
    adapter = LattigoAdapter()
    monkeypatch.setattr(
        "fhe_attack_replay.adapters.lattigo.shutil.which", lambda _name: "/fake/bin"
    )
    assert adapter.is_available() is True
    with pytest.raises(NotImplementedError, match="scaffold"):
        adapter.setup("BFV", {})


def test_lattigo_encrypt_decrypt_and_fingerprint_are_scaffolds():
    adapter = LattigoAdapter()
    with pytest.raises(NotImplementedError):
        adapter.encrypt(_synthetic_ctx("lattigo"), 0)
    with pytest.raises(NotImplementedError):
        adapter.decrypt(_synthetic_ctx("lattigo"), object())
    fp = adapter.evaluator_fingerprint(_synthetic_ctx("lattigo"))
    assert fp["implementation"] == "tuneinsight/lattigo"


def test_tfhe_rs_setup_runtime_error_when_helper_missing(monkeypatch):
    adapter = TfheRsAdapter()
    monkeypatch.setattr(
        "fhe_attack_replay.adapters.tfhe_rs.shutil.which", lambda _name: None
    )
    assert adapter.is_available() is False
    with pytest.raises(RuntimeError, match="not on PATH"):
        adapter.setup("TFHE", {})


def test_tfhe_rs_setup_not_implemented_when_helper_present(monkeypatch):
    adapter = TfheRsAdapter()
    monkeypatch.setattr(
        "fhe_attack_replay.adapters.tfhe_rs.shutil.which", lambda _name: "/fake/bin"
    )
    assert adapter.is_available() is True
    with pytest.raises(NotImplementedError, match="scaffold"):
        adapter.setup("TFHE", {})


def test_tfhe_rs_encrypt_decrypt_and_fingerprint_are_scaffolds():
    adapter = TfheRsAdapter()
    with pytest.raises(NotImplementedError):
        adapter.encrypt(_synthetic_ctx("tfhe-rs"), 0)
    with pytest.raises(NotImplementedError):
        adapter.decrypt(_synthetic_ctx("tfhe-rs"), object())
    fp = adapter.evaluator_fingerprint(_synthetic_ctx("tfhe-rs"))
    assert fp["implementation"] == "zama-ai/tfhe-rs"
    assert fp["constant_time_decrypt"] is True


def _synthetic_ctx(library: str) -> AdapterContext:
    return AdapterContext(library=library, scheme="BFV", params={}, handles={})


# --- SEAL adapter import-failure + galois-keys + read-degree fallback ----


def test_seal_setup_raises_runtime_error_when_tenseal_missing(monkeypatch):
    monkeypatch.setattr(
        "fhe_attack_replay.adapters.seal.importlib.import_module",
        _raises(ImportError("tenseal not installed")),
    )
    adapter = SEALAdapter()
    assert adapter.is_available() is False
    with pytest.raises(RuntimeError, match="not importable"):
        adapter.setup("BFV", {})


def test_seal_try_import_swallows_oserror(monkeypatch):
    from fhe_attack_replay.adapters import seal

    monkeypatch.setattr(
        seal.importlib, "import_module", _raises(OSError("dlopen failure"))
    )
    assert seal._try_import_tenseal() is None


def test_seal_setup_bfv_with_galois_keys():
    pytest.importorskip("tenseal")
    adapter = SEALAdapter()
    ctx = adapter.setup(
        "BFV",
        {
            "poly_modulus_degree": 8192,
            "plaintext_modulus": 1032193,
            "generate_galois_keys": True,
        },
    )
    assert ctx.scheme == "BFV"


def test_seal_setup_ckks_with_galois_keys():
    pytest.importorskip("tenseal")
    adapter = SEALAdapter()
    ctx = adapter.setup(
        "CKKS",
        {
            "poly_modulus_degree": 8192,
            "coeff_mod_bit_sizes": [60, 40, 40, 60],
            "scale_bits": 40,
            "generate_galois_keys": True,
        },
    )
    assert ctx.scheme == "CKKS"


def test_seal_read_poly_modulus_degree_swallows_attribute_error():
    class _Stub:
        def seal_context(self):
            raise AttributeError("no method")

    assert SEALAdapter._read_poly_modulus_degree(_Stub()) is None


def test_seal_read_poly_modulus_degree_swallows_runtime_error():
    class _Stub:
        def seal_context(self):
            raise RuntimeError("backend down")

    assert SEALAdapter._read_poly_modulus_degree(_Stub()) is None


# --- OpenFHE adapter native branches --------------------------------------


_HAS_OPENFHE = importlib.util.find_spec("openfhe") is not None
requires_openfhe = pytest.mark.skipif(
    not _HAS_OPENFHE, reason="openfhe-python not importable in this environment"
)


def test_openfhe_setup_raises_runtime_error_when_module_missing(monkeypatch):
    monkeypatch.setattr(
        "fhe_attack_replay.adapters.openfhe.importlib.import_module",
        _raises(ImportError("openfhe missing")),
    )
    adapter = OpenFHEAdapter()
    assert adapter.is_available() is False
    with pytest.raises(RuntimeError, match="not importable"):
        adapter.setup("BFV", {})


def test_openfhe_try_import_swallows_oserror(monkeypatch):
    from fhe_attack_replay.adapters import openfhe

    monkeypatch.setattr(
        openfhe.importlib, "import_module", _raises(OSError("dlopen"))
    )
    assert openfhe._try_import_openfhe() is None


@requires_openfhe
def test_openfhe_setup_unknown_scheme_raises_value_error():
    adapter = OpenFHEAdapter()
    with pytest.raises(ValueError, match="does not support scheme"):
        adapter.setup("DCKKS", {})


@requires_openfhe
def test_openfhe_setup_bfv_with_ring_dimension():
    adapter = OpenFHEAdapter()
    ctx = adapter.setup(
        "BFV",
        {
            "plaintext_modulus": 65537,
            "multiplicative_depth": 1,
            "ring_dimension": 8192,
        },
    )
    assert ctx.scheme == "BFV"


@requires_openfhe
def test_openfhe_setup_bgv_round_trip():
    adapter = OpenFHEAdapter()
    ctx = adapter.setup(
        "BGV",
        {
            "plaintext_modulus": 65537,
            "multiplicative_depth": 1,
            "ring_dimension": 8192,
        },
    )
    ct = adapter.encrypt(ctx, [1, 2, 3])
    pt = adapter.decrypt(ctx, ct)
    assert list(pt[:3]) == [1, 2, 3]


@requires_openfhe
def test_openfhe_setup_ckks_round_trip_and_unsupported_plaintext_modulus():
    adapter = OpenFHEAdapter()
    ctx = adapter.setup(
        "CKKS",
        {
            "multiplicative_depth": 1,
            "scale_bits": 50,
            "batch_size": 8,
            # Ring dimension 16384 is the smallest CKKS size that satisfies
            # OpenFHE's HE-standard guard at 128-bit security.
            "ring_dimension": 16384,
        },
    )
    ct = adapter.encrypt(ctx, [1.5, 2.25])
    pt = adapter.decrypt(ctx, ct)
    assert abs(pt[0] - 1.5) < 1e-2
    assert abs(pt[1] - 2.25) < 1e-2
    # CKKS has no exact plaintext modulus — the polynomial-domain replay
    # path is BFV/BGV-only.
    with pytest.raises(NotImplementedError, match="BFV/BGV"):
        adapter.plaintext_modulus(ctx)


# --- Cheon attack dispatch dead-ends --------------------------------------


def test_cheon_bisect_boundary_raises_for_unknown_adapter():
    """If a future adapter advertises live_oracle but isn't routed by the
    bisect dispatcher, the helper raises NotImplementedError so the public
    `run` fall-back kicks in."""

    class _StubCtx:
        scheme = "BFV"
        params: dict[str, Any] = {}
        library = "stub"
        handles: dict[str, Any] = {}

    class _StubAdapter:
        name = "stub-adapter-not-dispatched"

    attack = Cheon2024_127()
    with pytest.raises(NotImplementedError, match="Live-bisect"):
        attack._bisect_boundary(
            _StubAdapter(), _StubCtx(), object(), rounds=4, delta=128
        )


def test_cheon_run_replay_falls_back_when_inner_raises_not_implemented():
    """A live-oracle adapter that exposes the polynomial-domain protocol
    (so `_has_live_dispatch` returns True) but whose primitives raise
    NotImplementedError mid-run must fall back to RiskCheck rather than
    ERROR. Triggers the `except NotImplementedError: pass` branch in
    `Cheon2024_127.run`."""

    class _BrokenLiveAdapter(LibraryAdapter):
        name = "future-fhe"  # not in the private-dispatch set
        capability = AdapterCapability(
            schemes=("BFV",),
            live_oracle=True,
            requires_native=False,
        )

        def is_available(self):
            return True

        def setup(self, scheme, params):
            return AdapterContext(library=self.name, scheme=scheme, params=params)

        def encrypt(self, ctx, plaintext):
            # Mid-replay the adapter discovers it cannot actually run live
            # primitives (e.g. native extension missing) — raise the
            # documented signal so the harness falls back gracefully.
            raise NotImplementedError("no live primitives")

        def decrypt(self, ctx, ciphertext):
            raise NotImplementedError

        def evaluator_fingerprint(self, ctx):
            return {}

        # These two methods drive `_has_live_dispatch` to return True; the
        # NotImplementedError from `encrypt` is what trips the fallback.
        def perturb_ciphertext_constant(self, ctx, ct, offset, *, component=0):
            raise NotImplementedError

        def plaintext_delta(self, ctx, ct):
            raise NotImplementedError

    attack = Cheon2024_127()
    ctx = AdapterContext(
        library="future-fhe",
        scheme="BFV",
        params={
            "scheme": "BFV",
            "adversary_model": "ind-cpa-d",
            "noise_flooding": "none",
        },
    )
    result = attack.run(_BrokenLiveAdapter(), ctx)
    # Replay raised NotImplementedError, fell back to RiskCheck.
    assert result.evidence["mode"] == "risk_check"
    assert result.status is AttackStatus.VULNERABLE


def test_cheon_delta_for_falls_back_to_unit_when_no_handle():
    """With no `toy` handle and a non-openfhe adapter name, `_delta_for`
    returns `1` so the variance threshold floors at 1.0."""

    class _FakeAdapter:
        name = "future-fhe"

    ctx = AdapterContext(library="future-fhe", scheme="BFV", params={})
    delta = Cheon2024_127()._delta_for(_FakeAdapter(), ctx, object())
    assert delta == 1


def test_cheon_delta_for_raises_when_openfhe_missing_method():
    """An openfhe-named adapter without `plaintext_delta` raises
    NotImplementedError. The replay loop catches that and falls back."""

    class _IncompleteOpenFHE:
        name = "openfhe"

    ctx = AdapterContext(library="openfhe", scheme="BFV", params={})
    with pytest.raises(NotImplementedError, match="plaintext_delta"):
        Cheon2024_127()._delta_for(_IncompleteOpenFHE(), ctx, object())


def test_cheon_bisect_openfhe_raises_without_perturb_method():
    class _Stub:
        name = "openfhe"

    attack = Cheon2024_127()
    with pytest.raises(NotImplementedError, match="ciphertext perturbation"):
        attack._bisect_boundary_openfhe(
            _Stub(), AdapterContext(library="openfhe", scheme="BFV", params={}),
            object(), rounds=4, delta=64,
        )


def test_cheon_bisect_openfhe_raises_when_baseline_empty():
    class _Stub:
        name = "openfhe"

        def perturb_ciphertext_constant(self, ctx, ct, offset, *, component=0):
            return ct

        def decrypt(self, ctx, ct):
            return []

    attack = Cheon2024_127()
    with pytest.raises(NotImplementedError, match="packed decrypt"):
        attack._bisect_boundary_openfhe(
            _Stub(), AdapterContext(library="openfhe", scheme="BFV", params={}),
            object(), rounds=4, delta=64,
        )


def test_cheon_bisect_openfhe_raises_runtime_error_when_no_flip():
    """Stub that never flips → bisection RuntimeError after 8 doublings."""

    class _Stub:
        name = "openfhe"

        def perturb_ciphertext_constant(self, ctx, ct, offset, *, component=0):
            return ct

        def decrypt(self, ctx, ct):
            return [0, 0, 0, 0]  # baseline never changes

    attack = Cheon2024_127()
    with pytest.raises(RuntimeError, match="did not cross"):
        attack._bisect_boundary_openfhe(
            _Stub(), AdapterContext(library="openfhe", scheme="BFV", params={}),
            object(), rounds=4, delta=2,
        )


# --- runner / report edge cases --------------------------------------------


def test_coverage_ratio_zero_when_no_attacks_requested():
    cov = Coverage(requested=0)
    assert cov.ratio == 0.0


def test_overall_status_error_when_results_have_error_only():
    report = RunReport(
        library="x",
        scheme="LWE",
        params={},
        results=[
            AttackResult(
                attack="cheon-2024-127",
                library="x",
                scheme="LWE",
                status=AttackStatus.ERROR,
                duration_seconds=0.0,
            )
        ],
    )
    assert report.overall_status is AttackStatus.ERROR


def test_runner_resolves_default_scheme_from_capability():
    """Calling run() with no scheme and no params['scheme'] picks the
    first capability scheme. toy-lwe advertises ('LWE',), so that's the
    pick."""
    report = run(library="toy-lwe", params={}, attacks=["cheon-2024-127"])
    assert report.scheme == "LWE"


def test_runner_raises_when_adapter_advertises_no_schemes():
    class _NoSchemeAdapter(LibraryAdapter):
        name = "no-scheme"
        capability = AdapterCapability(schemes=())

        def is_available(self):
            return False

        def setup(self, scheme, params):
            return AdapterContext(library=self.name, scheme=scheme, params=params)

        def encrypt(self, ctx, plaintext):
            raise NotImplementedError

        def decrypt(self, ctx, ciphertext):
            raise NotImplementedError

        def evaluator_fingerprint(self, ctx):
            return {}

    register_adapter(_NoSchemeAdapter)
    with pytest.raises(ValueError, match="advertises no schemes"):
        run(library="no-scheme", params={}, attacks=["cheon-2024-127"])


def test_runner_records_not_implemented_when_attack_raises_it():
    """A scaffold attack that raises NotImplementedError mid-run produces a
    NOT_IMPLEMENTED result with the exception preserved in evidence."""

    class _ScaffoldAttack(Attack):
        id = "scaffold-attack-2026"
        title = "Scaffold attack that raises"
        applies_to_schemes: tuple[str, ...] = ()
        intent = AttackIntent.REPLAY

        def run(self, adapter, ctx):
            raise NotImplementedError("not yet wired")

    register_attack(_ScaffoldAttack)
    report = run(
        library="toy-lwe", params={"scheme": "LWE"}, attacks=["scaffold-attack-2026"]
    )
    r = report.results[0]
    assert r.status is AttackStatus.NOT_IMPLEMENTED
    assert "not yet wired" in r.message
    assert "NotImplementedError" in r.evidence["exception"]


def test_attack_applies_returns_true_when_no_scheme_filter():
    class _UnfilteredAttack(Attack):
        id = "unfiltered-attack-2026"
        title = "Unfiltered"
        applies_to_schemes: tuple[str, ...] = ()  # empty → applies everywhere

        def run(self, adapter, ctx):
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.SAFE,
                duration_seconds=0.0,
            )

    attack = _UnfilteredAttack()
    assert attack.applies(adapter=ToyLWEAdapter(), scheme="LWE") is True
    assert attack.applies(adapter=ToyLWEAdapter(), scheme="MADE-UP") is True


def test_summary_label_no_attacks_ran_when_only_skipped():
    report = RunReport(
        library="x",
        scheme="BFV",
        params={},
        results=[
            AttackResult(
                attack="any",
                library="x",
                scheme="BFV",
                status=AttackStatus.SKIPPED,
                duration_seconds=0.0,
            )
        ],
        coverage=Coverage(requested=1, skipped=1),
    )
    label, _color = _summary_label(report)
    assert label == "no attacks ran"


def test_summary_label_error_count():
    report = RunReport(
        library="x",
        scheme="BFV",
        params={},
        results=[
            AttackResult(
                attack="any",
                library="x",
                scheme="BFV",
                status=AttackStatus.ERROR,
                duration_seconds=0.0,
            )
        ],
        coverage=Coverage(requested=1, errors=1, ran=1),
    )
    label, _color = _summary_label(report)
    assert label == "1 error"


def test_summary_label_implemented_count_when_not_implemented_present():
    report = RunReport(
        library="x",
        scheme="BFV",
        params={},
        results=[
            AttackResult(
                attack="a",
                library="x",
                scheme="BFV",
                status=AttackStatus.SAFE,
                duration_seconds=0.0,
            ),
            AttackResult(
                attack="b",
                library="x",
                scheme="BFV",
                status=AttackStatus.NOT_IMPLEMENTED,
                duration_seconds=0.0,
            ),
        ],
        coverage=Coverage(requested=2, ran=1, safe=1, not_implemented=1),
    )
    label, _color = _summary_label(report)
    assert "1/2 implemented" in label


def test_to_svg_badge_renders_for_minimal_report():
    report = RunReport(library="x", scheme="LWE", params={}, results=[])
    svg = to_svg_badge(report)
    assert svg.startswith("<svg")
    assert svg.endswith("</svg>")


# --- registry guards --------------------------------------------------------


def test_register_adapter_rejects_empty_name():
    class _Anon(LibraryAdapter):
        name = ""
        capability = AdapterCapability(schemes=("BFV",))

        def is_available(self):
            return False

        def setup(self, scheme, params):
            return AdapterContext(library=self.name, scheme=scheme, params=params)

        def encrypt(self, ctx, plaintext):
            return None

        def decrypt(self, ctx, ciphertext):
            return None

        def evaluator_fingerprint(self, ctx):
            return {}

    with pytest.raises(ValueError, match="non-empty"):
        register_adapter(_Anon)


def test_register_attack_rejects_empty_id():
    class _Anon(Attack):
        id = ""
        title = "anon"

        def run(self, adapter, ctx):
            return AttackResult(
                attack=self.id,
                library=adapter.name,
                scheme=ctx.scheme,
                status=AttackStatus.SAFE,
                duration_seconds=0.0,
            )

    with pytest.raises(ValueError, match="non-empty"):
        register_attack(_Anon)


# --- CLI exit-code branches ------------------------------------------------


def test_cli_load_params_returns_empty_dict_when_path_none(tmp_path: Path):
    # Reach `_load_params(None)` via the CLI by omitting --params. toy-lwe
    # works on defaults so the run still produces a real verdict.
    rc = main(
        [
            "run",
            "--lib",
            "toy-lwe",
            "--attacks",
            "cheon-2024-127",
            "--quiet",
        ]
    )
    # Default toy-lwe config (no params file) has noise_flooding_sigma=0,
    # so it converges to VULNERABLE.
    assert rc == EXIT_VULNERABLE


def test_cli_run_unknown_lib_returns_usage_error(tmp_path: Path):
    # argparse's `--lib` choices reject this before _cmd_run runs, exiting
    # with code 2 via SystemExit. We assert that exit path here.
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "run",
                "--lib",
                "definitely-not-a-real-adapter",
                "--quiet",
            ]
        )
    assert exc.value.code == 2


def test_cli_run_emits_json_to_stdout_when_no_output_json(capsys, tmp_path: Path):
    params = tmp_path / "p.json"
    params.write_text(json.dumps({"scheme": "LWE", "noise_flooding_sigma": 65536.0}))
    rc = main(
        [
            "run",
            "--lib",
            "toy-lwe",
            "--params",
            str(params),
            "--attacks",
            "cheon-2024-127",
        ]
    )
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["library"] == "toy-lwe"
    assert rc == EXIT_OK


def test_cli_run_returns_exit_error_on_attack_error(tmp_path: Path):
    # safe_variance_frac_delta=0 makes the cheon module raise ValueError
    # → harness reports ERROR → CLI exits 3.
    params = tmp_path / "p.json"
    params.write_text(
        json.dumps({"scheme": "LWE", "safe_variance_frac_delta": 0})
    )
    rc = main(
        [
            "run",
            "--lib",
            "toy-lwe",
            "--params",
            str(params),
            "--attacks",
            "cheon-2024-127",
            "--quiet",
        ]
    )
    assert rc == EXIT_ERROR


def test_cli_run_returns_exit_vulnerable(tmp_path: Path):
    params = tmp_path / "p.json"
    params.write_text(json.dumps({"scheme": "LWE", "noise_flooding_sigma": 0.0, "seed": 1}))
    rc = main(
        [
            "run",
            "--lib",
            "toy-lwe",
            "--params",
            str(params),
            "--attacks",
            "cheon-2024-127",
            "--quiet",
        ]
    )
    assert rc == EXIT_VULNERABLE


def test_cli_run_exit_not_implemented_triggers_warning(capsys, tmp_path: Path):
    # glitchfhe-usenix25 with a supplied fault log returns NOT_IMPLEMENTED
    # because the differential analyzer is not yet bundled.
    params = tmp_path / "p.json"
    params.write_text(json.dumps({"scheme": "BFV"}))
    fault_log = tmp_path / "fault.log"
    fault_log.write_text("synthetic capture")
    out = tmp_path / "report.json"
    rc = main(
        [
            "run",
            "--lib",
            "openfhe",
            "--params",
            str(params),
            "--attacks",
            "glitchfhe-usenix25",
            "--evidence",
            f"fault_log={fault_log}",
            "--output-json",
            str(out),
            "--quiet",
        ]
    )
    captured = capsys.readouterr()
    assert rc == EXIT_NOT_IMPLEMENTED
    assert "NOT_IMPLEMENTED" in captured.err


def test_cli_run_unknown_attack_id_returns_usage_error(tmp_path: Path):
    params = tmp_path / "p.json"
    params.write_text(json.dumps({"scheme": "LWE"}))
    rc = main(
        [
            "run",
            "--lib",
            "toy-lwe",
            "--params",
            str(params),
            "--attacks",
            "definitely-not-an-attack-2099",
            "--quiet",
        ]
    )
    assert rc == EXIT_USAGE


def test_cli_run_writes_json_and_also_prints_when_quiet_omitted(
    capsys, tmp_path: Path
):
    params = tmp_path / "p.json"
    params.write_text(json.dumps({"scheme": "LWE", "noise_flooding_sigma": 65536.0}))
    out = tmp_path / "report.json"
    rc = main(
        [
            "run",
            "--lib",
            "toy-lwe",
            "--params",
            str(params),
            "--attacks",
            "cheon-2024-127",
            "--output-json",
            str(out),
        ]
    )
    captured = capsys.readouterr().out
    payload = json.loads(captured)
    on_disk = json.loads(out.read_text())
    assert payload["library"] == on_disk["library"] == "toy-lwe"
    assert rc == EXIT_OK


def test_summary_label_safe_count_when_only_safe_results():
    report = RunReport(
        library="x",
        scheme="BFV",
        params={},
        results=[
            AttackResult(
                attack="a",
                library="x",
                scheme="BFV",
                status=AttackStatus.SAFE,
                duration_seconds=0.0,
            ),
        ],
        coverage=Coverage(requested=1, ran=1, safe=1),
    )
    label, _color = _summary_label(report)
    assert label == "1/1 safe"


def test_cli_run_all_skipped_warning_message(capsys, tmp_path: Path):
    params = tmp_path / "p.json"
    params.write_text(json.dumps({"scheme": "BFV"}))
    rc = main(
        [
            "run",
            "--lib",
            "openfhe",
            "--params",
            str(params),
            "--attacks",
            "guo-qian-usenix24",
            "--quiet",
        ]
    )
    err = capsys.readouterr().err
    assert "every selected attack was SKIPPED" in err
    assert rc == 5


# --- helpers ---------------------------------------------------------------


def _raises(exc: BaseException):
    def _f(*_a, **_kw):
        raise exc

    return _f
