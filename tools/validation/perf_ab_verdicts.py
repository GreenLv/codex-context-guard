#!/usr/bin/env python3
"""Bootstrap verdicts for formal interleaved A/B runs (RV-05, sixth round).

Rules (per-cell, per-metric, per-statistic — the original RR06 v2 gate):
every gated (metric, statistic) pair is judged on its own one-sided 99%
bootstrap confidence bound (10,000 resamples) of the candidate/baseline
ratio, and ANY pair whose lower bound exceeds 1.0 declares a slowdown for
that cell. Both the median and the nearest-rank p95 are gating statistics;
a cell whose tail regressed while its median did not is
DECLARED-SLOWER(p95), never silently folded into "noise". memory_stop
carries a second gated metric (tracemalloc peak_bytes) alongside elapsed.

Verdicts are computed only from the raw run — no hand-transcribed values.
`--check-tail-oracle` runs the built-in synthetic negative control (a
tail-only regression whose median LoCI is exactly 1 and whose p95 LoCI is
2) and fails unless it is declared.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import sys
from pathlib import Path

RESAMPLES = 10_000
SEED = 20261026


def nearest_rank(sorted_values: list[float], percentile: int) -> float:
    index = max(0, -(-len(sorted_values) * percentile // 100) - 1)
    return sorted_values[min(index, len(sorted_values) - 1)]


def median(sorted_values: list[float]) -> float:
    n = len(sorted_values)
    mid = n // 2
    if n % 2:
        return sorted_values[mid]
    return (sorted_values[mid - 1] + sorted_values[mid]) / 2


def ratio_lo99(baseline: list[float], candidate: list[float],
               statistic, rng: random.Random) -> float:
    stats_b: list[float] = []
    stats_a: list[float] = []
    n_b, n_a = len(baseline), len(candidate)
    for _ in range(RESAMPLES):
        sample_b = (baseline[rng.randrange(n_b)] for _ in range(n_b))
        sample_a = (candidate[rng.randrange(n_a)] for _ in range(n_a))
        stats_b.append(statistic(sorted(sample_b)))
        stats_a.append(statistic(sorted(sample_a)))
    ratios = sorted(a / b for b, a in zip(stats_b, stats_a) if b > 0)
    return ratios[max(0, int(0.01 * len(ratios)) - 1)]


def ratio_hi99(baseline, candidate, statistic, rng):
    ratios = []
    for _ in range(RESAMPLES):
        b = statistic(sorted(baseline[rng.randrange(len(baseline))] for _ in baseline))
        a = statistic(sorted(candidate[rng.randrange(len(candidate))] for _ in candidate))
        if b > 0:
            ratios.append(a / b)
    ratios.sort()
    return ratios[min(len(ratios) - 1, math.ceil(0.99 * len(ratios)) - 1)]


def delta_lo99(baseline, candidate, statistic, rng):
    deltas = []
    for _ in range(RESAMPLES):
        b = statistic(sorted(baseline[rng.randrange(len(baseline))] for _ in baseline))
        a = statistic(sorted(candidate[rng.randrange(len(candidate))] for _ in candidate))
        deltas.append(a - b)
    deltas.sort()
    return deltas[max(0, int(0.01 * len(deltas)) - 1)]


def delta_hi99(baseline, candidate, statistic, rng):
    deltas = []
    for _ in range(RESAMPLES):
        b = statistic(sorted(baseline[rng.randrange(len(baseline))] for _ in baseline))
        a = statistic(sorted(candidate[rng.randrange(len(candidate))] for _ in candidate))
        deltas.append(a - b)
    deltas.sort()
    return deltas[min(len(deltas) - 1, math.ceil(0.99 * len(deltas)) - 1)]


def inspect_windows_wrappers(raw: dict, scope: dict) -> dict[str, str]:
    """Recompute wrappers from independently re-identified runtime trees."""
    root = Path(__file__).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from tools.validation.acceptance_identity import runtime_tree_digest

    identities = raw.get("identities")
    if not isinstance(identities, dict):
        raise ValueError("runtime tree identities missing")
    wrappers = {}
    for side in ("baseline", "candidate"):
        location = identities.get(f"{side}_tree")
        if not isinstance(location, str) or not location:
            raise ValueError(f"{side} runtime tree location missing")
        tree = Path(location).resolve(strict=True)
        if not tree.is_dir():
            raise ValueError(f"{side} runtime tree is not a directory")
        expected = scope.get(f"{side}_runtime_digest")
        if runtime_tree_digest(tree) != expected:
            raise ValueError(f"{side} runtime tree identity differs")
        try:
            hooks = json.loads((tree / "hooks" / "hooks.json").read_text(encoding="utf-8"))
            wrapper = hooks["hooks"]["SessionEnd"][0]["hooks"][0]["commandWindows"]
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError(f"{side} SessionEnd Windows wrapper missing") from exc
        if not isinstance(wrapper, str) or not wrapper:
            raise ValueError(f"{side} SessionEnd Windows wrapper invalid")
        if runtime_tree_digest(tree) != expected:
            raise ValueError(f"{side} runtime tree changed during wrapper inspection")
        wrappers[side] = hashlib.sha256(wrapper.encode("utf-8")).hexdigest()
    return wrappers


def validate_scoped(raw, scope, windows_shell_identity=None, windows_wrapper_hashes=None):
    """Reject partial/censored batches and identity or declaration drift."""
    if (not isinstance(scope, dict)
            or set(scope) != {'schema', 'cells', 'attempts', 'baseline_runtime_digest',
                              'candidate_runtime_digest', 'budgets'}
            or raw.get('mode') != 'scoped-formal' or raw.get('scope_manifest') != scope
            or scope.get('schema') != 'perf-scoped/v1'
            or raw.get('execution_state') != 'completed'
            or raw.get('accepted') is not True or raw.get('coverage_complete') is not True
            or raw.get('blocking_failures') != 0):
        raise ValueError('scoped producer result is incomplete or differs from declaration')
    cells, n = scope.get('cells'), scope.get('attempts')
    if (not isinstance(cells, list) or not cells or len(set(cells)) != len(cells)
            or type(n) is not int or n < 20 or raw.get('planned_cells') != cells
            or raw.get('predeclared_attempts_per_cell') != n
            or set(raw.get('cells', {})) != set(cells)):
        raise ValueError('scoped coverage differs')
    identities = raw.get('identities', {})
    for side in ('baseline', 'candidate'):
        expected = scope.get(f'{side}_runtime_digest')
        if (not isinstance(expected, str) or len(expected) != 64
                or any(c not in '0123456789abcdef' for c in expected)
                or identities.get(f'{side}_runtime_digest') != expected):
            raise ValueError('scoped identity differs')
    shell = identities.get('windows_shell')
    if (sys.platform == 'win32' and cells == ['session_end']
            and shell is None and windows_shell_identity is None):
        raise ValueError('Windows session_end requires explicit shell verification')
    if shell is not None or windows_shell_identity is not None or windows_wrapper_hashes is not None:
        if (not isinstance(shell, dict) or set(shell) != {'before', 'after', 'wrapper_sha256'}
                or windows_shell_identity is None or windows_wrapper_hashes is None
                or cells != ['session_end']
                or shell.get('before') != windows_shell_identity
                or shell.get('after') != windows_shell_identity):
            raise ValueError('explicit Windows shell identity differs or is missing')
        wrappers = shell.get('wrapper_sha256')
        if (not isinstance(wrappers, dict) or set(wrappers) != {'baseline', 'candidate'}
                or wrappers != windows_wrapper_hashes
                or any(not isinstance(value, str) or len(value) != 64
                       or any(c not in '0123456789abcdef' for c in value)
                       for value in wrappers.values())):
            raise ValueError('Windows wrapper identity differs or is missing')
    budgets = scope.get('budgets')
    if not isinstance(budgets, dict) or set(budgets) != ({'elapsed', 'peak_bytes'} if 'memory_stop' in cells else {'elapsed'}):
        raise ValueError('missing metric budgets')
    for budget in budgets.values():
        if (not isinstance(budget, dict) or set(budget) != {'relative', 'absolute'}
                or any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in budget.values())):
            raise ValueError('invalid metric budget')
    for cell in cells:
        sides = raw['cells'][cell]['sides']
        if set(sides) != {'baseline', 'candidate'}:
            raise ValueError('scoped sides differ')
        for side, payload in sides.items():
            rows = payload['raw_rows']
            if len(rows) != n:
                raise ValueError('scoped sample count differs')
            for index, row in enumerate(rows):
                if shell is not None and row.get('wrapper_sha256') != wrappers[side]:
                    raise ValueError('Windows sample wrapper differs')
                metrics = ['stop_wall' if cell == 'stop_s1' else 'elapsed'] + (['peak_bytes'] if cell == 'memory_stop' else [])
                if (row.get('index') != index or row.get('side') != side
                        or row.get('outcome_class') != 'completed' or row.get('assertion') != 'ok'
                        or row.get('home_cleanup', {}).get('status') != 'removed'
                        or row.get('stop_batch', False)
                        or any(type(row.get(k)) not in (int, float) or not math.isfinite(row[k]) or row[k] <= 0 for k in metrics)):
                    raise ValueError('scoped sample failed or incomplete')


def cell_metrics(cell: str, rows_baseline: list[dict], rows_candidate: list[dict], *, scoped=False):
    """The gated (metric, values) pairs for one cell."""
    elapsed = 'stop_wall' if scoped and cell == 'stop_s1' else 'elapsed'
    metrics = {
        "elapsed": ([r[elapsed] for r in rows_baseline],
                    [r[elapsed] for r in rows_candidate]),
    }
    if cell == "memory_stop":
        metrics["peak_bytes"] = ([r["peak_bytes"] for r in rows_baseline],
                                 [r["peak_bytes"] for r in rows_candidate])
    return metrics


def verdicts_from_raw(raw: dict, seed: int = SEED, scope: dict | None = None,
                      windows_shell_identity: dict | None = None,
                      windows_wrapper_hashes: dict | None = None) -> dict:
    if raw.get('mode') == 'scoped-formal' and scope is None:
        raise ValueError('scoped-formal results require their scope manifest')
    if scope is not None:
        validate_scoped(raw, scope, windows_shell_identity, windows_wrapper_hashes)
    elif raw.get("identities", {}).get("windows_shell") is not None or windows_shell_identity is not None or windows_wrapper_hashes is not None:
        raise ValueError("explicit Windows shell requires a scoped formal result")
    rng = random.Random(seed)
    verdicts = {}
    declared = []
    inconclusive = []
    for cell, payload in raw["cells"].items():
        sides = payload["sides"]
        rows_b = [r for r in sides["baseline"]["raw_rows"]
                  if r.get("outcome_class") == "completed"
                  and r.get("assertion") in (None, "ok")]
        rows_a = [r for r in sides["candidate"]["raw_rows"]
                  if r.get("outcome_class") == "completed"
                  and r.get("assertion") in (None, "ok")]
        result = {
            "n_baseline": len(rows_b), "n_candidate": len(rows_a),
            "failures_baseline": len(sides["baseline"]["raw_rows"]) - len(rows_b),
            "failures_candidate": len(sides["candidate"]["raw_rows"]) - len(rows_a),
        }
        slower_pairs = []
        uncertain_pairs = []
        for metric, (values_b, values_a) in cell_metrics(cell, rows_b, rows_a, scoped=scope is not None).items():
            for statistic_name, statistic in (("median", median),
                                              ("p95", lambda s: nearest_rank(s, 95))):
                point = statistic(sorted(values_a)) / statistic(sorted(values_b))
                lo99 = ratio_lo99(values_b, values_a, statistic, rng)
                delta = delta_lo99(values_b, values_a, statistic, rng) if scope else None
                key = f"{statistic_name}_{metric}"
                result[f"{key}_baseline"] = statistic(sorted(values_b))
                result[f"{key}_candidate"] = statistic(sorted(values_a))
                result[f"{key}_ratio_point"] = round(point, 4)
                result[f"{key}_lo99"] = round(lo99, 4)
                if scope:
                    result[f'{key}_delta_lo99'] = delta
                    budget = scope['budgets'][metric]
                    upper_ratio = ratio_hi99(values_b, values_a, statistic, rng)
                    upper_delta = delta_hi99(values_b, values_a, statistic, rng)
                    result[f'{key}_hi99'] = upper_ratio
                    result[f'{key}_delta_hi99'] = upper_delta
                    slower = lo99 > 1.0 + budget['relative'] and delta > budget['absolute']
                    if not slower and upper_ratio > 1.0 + budget['relative'] and upper_delta > budget['absolute']:
                        uncertain_pairs.append({'cell': cell, 'metric': metric, 'statistic': statistic_name})
                else:
                    slower = lo99 > 1.0
                if slower:
                    slower_pairs.append({"cell": cell, "metric": metric,
                                         "statistic": statistic_name,
                                         "ratio_point": round(point, 4),
                                         "ratio_lo99": round(lo99, 4)})
        if slower_pairs:
            result["verdict"] = (
                "DECLARED-SLOWER(median)" if any(p["statistic"] == "median"
                                                 for p in slower_pairs)
                else "DECLARED-SLOWER(p95)")
            result["declared_pairs"] = slower_pairs
        elif uncertain_pairs:
            result['verdict'] = 'INCONCLUSIVE'
            result['inconclusive_pairs'] = uncertain_pairs
        else:
            result["verdict"] = ("WITHIN-DECLARED-BUDGET" if scope
                                 else "not-distinguishable-from-noise")
        verdicts[cell] = result
        declared.extend(slower_pairs)
        inconclusive.extend(uncertain_pairs)
    result = {
        "verdicts": verdicts,
        "declared_regressions": declared,
        "method": {
            "resamples": RESAMPLES,
            "seed": seed,
            "gate": "per cell, per metric, per statistic: one-sided 99% "
                    "bootstrap CI of the candidate/baseline ratio; ANY gated "
                    "pair (median or p95; elapsed or peak_bytes) with "
                    "LoCI > 1.0 declares a slowdown and is never waived",
        },
        "identities": raw.get("identities"),
    }
    if scope:
        result['scope_manifest'] = scope
        result['inconclusive_pairs'] = inconclusive
        result['accepted'] = not declared and not inconclusive
        result['method']['gate'] = ('regression if both lower bounds exceed budgets; pass only if at least one '
                                    'upper bound is within budget; otherwise inconclusive')
    return result


def synthetic_tail_only() -> dict:
    """The persistent negative control: a tail-only regression. Baseline is
    40 identical samples; the candidate has 30 identical and 10 doubled
    samples — the median cannot move (LoCI = 1) while the nearest-rank p95
    exactly doubles (LoCI = 2). The gate must declare it."""
    rows_b = [{"elapsed": 1.0, "outcome_class": "completed", "assertion": "ok"}
              for _ in range(40)]
    rows_a = ([{"elapsed": 1.0, "outcome_class": "completed", "assertion": "ok"}
               for _ in range(30)]
              + [{"elapsed": 2.0, "outcome_class": "completed", "assertion": "ok"}
                 for _ in range(10)])
    return {"cells": {"synthetic-tail-only-regression": {"sides": {
        "baseline": {"raw_rows": rows_b},
        "candidate": {"raw_rows": rows_a}}}},
        "identities": {"synthetic": True}}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw", nargs="?", type=Path,
                        help="formal A/B raw JSON; omit with --check-tail-oracle")
    parser.add_argument("--out", type=Path)
    parser.add_argument('--scope-manifest', type=Path)
    parser.add_argument('--windows-shell', type=Path,
                        help='recheck the explicit Windows shell used for sampling')
    parser.add_argument("--check-tail-oracle", action="store_true",
                        help="run the synthetic tail-only negative control")
    args = parser.parse_args(argv)
    if args.check_tail_oracle:
        if args.windows_shell is not None:
            parser.error('--windows-shell is not used by the tail oracle')
        report = verdicts_from_raw(synthetic_tail_only())
        cell = report["verdicts"]["synthetic-tail-only-regression"]
        ok = (cell["verdict"] == "DECLARED-SLOWER(p95)"
              and cell["median_elapsed_lo99"] <= 1.0
              and cell["p95_elapsed_lo99"] > 1.0
              and report["declared_regressions"])
        print(json.dumps({"tail_oracle_declared": ok,
                          "verdict": cell["verdict"],
                          "median_lo99": cell["median_elapsed_lo99"],
                          "p95_lo99": cell["p95_elapsed_lo99"]}, indent=1))
        return 0 if ok else 1
    if args.raw is None:
        parser.error("raw is required unless --check-tail-oracle is given")
    raw = json.loads(args.raw.read_text(encoding="utf-8"))
    scope = json.loads(args.scope_manifest.read_text(encoding='utf-8')) if args.scope_manifest else None
    if raw.get('mode') == 'scoped-formal' and scope is None:
        parser.error('scoped-formal results require their scope manifest')
    shell_identity = None
    wrapper_hashes = None
    if args.windows_shell is not None:
        # Resolve through the producer's exact inspector so preflight and
        # independent consumer enforce identical executable/version facts.
        root = Path(__file__).resolve().parents[2]
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from tools.validation.perf_ab import inspect_windows_shell
        try:
            shell_identity = inspect_windows_shell(args.windows_shell)
            if scope is None:
                raise ValueError("explicit Windows shell requires a scoped formal result")
            wrapper_hashes = inspect_windows_wrappers(raw, scope)
        except (OSError, ValueError) as exc:
            parser.error(f'Windows shell verification failed: {exc}')
    report = verdicts_from_raw(raw, scope=scope, windows_shell_identity=shell_identity,
                               windows_wrapper_hashes=wrapper_hashes)
    target = args.out or args.raw.with_name(
        args.raw.name.replace(".json", "-verdicts.json"))
    target.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    for cell, result in report["verdicts"].items():
        print(f"{cell:24s} {result['verdict']:30s} "
              f"med {result['median_elapsed_ratio_point']:.4f} "
              f"lo99 {result['median_elapsed_lo99']:.4f} "
              f"p95 lo99 {result['p95_elapsed_lo99']:.4f}")
    print("declared pairs:", len(report["declared_regressions"]))
    return 1 if scope and not report['accepted'] else 0


if __name__ == "__main__":
    raise SystemExit(main())
