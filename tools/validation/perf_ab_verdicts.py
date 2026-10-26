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
import json
import random
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


def cell_metrics(cell: str, rows_baseline: list[dict], rows_candidate: list[dict]):
    """The gated (metric, values) pairs for one cell."""
    metrics = {
        "elapsed": ([r["elapsed"] for r in rows_baseline],
                    [r["elapsed"] for r in rows_candidate]),
    }
    if cell == "memory_stop":
        metrics["peak_bytes"] = ([r["peak_bytes"] for r in rows_baseline],
                                 [r["peak_bytes"] for r in rows_candidate])
    return metrics


def verdicts_from_raw(raw: dict, seed: int = SEED) -> dict:
    rng = random.Random(seed)
    verdicts = {}
    declared = []
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
        for metric, (values_b, values_a) in cell_metrics(cell, rows_b, rows_a).items():
            for statistic_name, statistic in (("median", median),
                                              ("p95", lambda s: nearest_rank(s, 95))):
                point = statistic(sorted(values_a)) / statistic(sorted(values_b))
                lo99 = ratio_lo99(values_b, values_a, statistic, rng)
                key = f"{statistic_name}_{metric}"
                result[f"{key}_baseline"] = statistic(sorted(values_b))
                result[f"{key}_candidate"] = statistic(sorted(values_a))
                result[f"{key}_ratio_point"] = round(point, 4)
                result[f"{key}_lo99"] = round(lo99, 4)
                if lo99 > 1.0:
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
        else:
            result["verdict"] = "not-distinguishable-from-noise"
        verdicts[cell] = result
        declared.extend(slower_pairs)
    return {
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
    parser.add_argument("--check-tail-oracle", action="store_true",
                        help="run the synthetic tail-only negative control")
    args = parser.parse_args(argv)
    if args.check_tail_oracle:
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
    report = verdicts_from_raw(json.loads(args.raw.read_text()))
    target = args.out or args.raw.with_name(
        args.raw.name.replace(".json", "-verdicts.json"))
    target.write_text(json.dumps(report, indent=1) + "\n")
    for cell, result in report["verdicts"].items():
        print(f"{cell:24s} {result['verdict']:30s} "
              f"med {result['median_elapsed_ratio_point']:.4f} "
              f"lo99 {result['median_elapsed_lo99']:.4f} "
              f"p95 lo99 {result['p95_elapsed_lo99']:.4f}")
    print("declared pairs:", len(report["declared_regressions"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
