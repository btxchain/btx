"""Predeclared paired binary evaluation, with family-wise error budgeting.

A conservative Hoeffding bound applies to paired differences in [-1,1]. It
counts distinct test cases, never evaluator signatures, as statistical samples.
There is no claim that this metric proves absence of backdoors or contamination.
"""
from decimal import Decimal, localcontext, ROUND_CEILING
from .codec import integer
from .errors import require

SCALE = 1_000_000


def paired_bound(counts: dict, alpha_ppm: int, max_trials: int):
    require(set(counts) == {"00", "01", "10", "11"}, "PAIR_COUNTS")
    for n in counts.values(): integer(n, 0, 100_000_000)
    n = sum(counts.values()); require(n > 0, "EMPTY_EVALUATION")
    integer(alpha_ppm, 1, 500_000); integer(max_trials, 1, 1_000_000)
    # 01 means parent fails, candidate succeeds. Bonferroni across all trials.
    delta_ppm = ((counts["01"] - counts["10"]) * SCALE) // n
    with localcontext() as ctx:
        ctx.prec = 60
        eps = ((Decimal(2) * (Decimal(max_trials * SCALE) / alpha_ppm).ln() / n).sqrt() * SCALE)
        radius = int(eps.to_integral_value(rounding=ROUND_CEILING))
    return {"n": n, "delta_ppm": delta_ppm, "lower_ppm": max(-SCALE, delta_ppm-radius),
            "upper_ppm": min(SCALE, delta_ppm+radius), "alpha_ppm": alpha_ppm,
            "max_trials": max_trials, "method": "PAIRED_HOEFFDING_BONFERRONI_V1"}


def qualify_report(report: dict, policy: dict):
    require(report["suite_id"] == policy["suite_id"], "EVALUATION_SUITE")
    require(report["holdout_commitment"] == policy["holdout_commitment"], "HOLDOUT")
    bound = paired_bound(report["counts"], policy["alpha_ppm"], policy["max_trials"])
    require(bound["n"] >= policy["min_examples"], "EVALUATION_SMALL")
    require(bound["delta_ppm"] >= policy["min_gain_ppm"] and bound["lower_ppm"] > 0, "NO_SIGNIFICANT_GAIN")
    require(set(report["regressions_ppm"]) == set(policy["max_regression_ppm"]), "REGRESSION_COVERAGE")
    for metric, value in report["regressions_ppm"].items():
        integer(value, -SCALE, SCALE)
        require(value <= policy["max_regression_ppm"][metric], "REGRESSION", metric)
    require(report["reproducible"] is True, "REPRODUCIBILITY")
    return bound


def pareto_frontier(candidates: list[dict]):
    """Maximize integer quality/novelty, minimize integer cost, preserve niches."""
    out = []
    for c in candidates:
        dominated = False
        for d in candidates:
            if c["niche"] != d["niche"] or c["id"] == d["id"]: continue
            cv, dv = (c["quality"],c["novelty"],-c["cost"]),(d["quality"],d["novelty"],-d["cost"])
            if all(x >= y for x,y in zip(dv,cv)) and any(x>y for x,y in zip(dv,cv)):
                dominated=True;break
        if not dominated: out.append(c)
    return sorted(out,key=lambda c:(c["niche"],-c["quality"],c["id"]))


def research_allocation(candidates: list[dict], slots: int, exploration_percent: int = 20):
    integer(slots, 0, 100000); integer(exploration_percent, 0, 100)
    if not candidates or slots == 0: return {}
    frontier = pareto_frontier(candidates)
    explore = min(slots,max(1,slots*exploration_percent//100)) if exploration_percent else 0
    novelty = sorted(candidates,key=lambda c:(-c["novelty"],c["id"]))
    result = {c["id"]:0 for c in candidates}
    for i in range(explore):result[novelty[i%len(novelty)]["id"]]+=1
    for i in range(slots-explore):result[frontier[i%len(frontier)]["id"]]+=1
    return result
