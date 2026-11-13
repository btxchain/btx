"""Experimental statistics; no single neuron score is a proof of monosemanticity."""
from __future__ import annotations
import math
import numpy as np
from .codec import require, keys, identity, digest_text


def paired_evaluation(rows, *, suite_hash, profile_id, trial_budget=1, alpha_ppm=50000, resamples=2000, seed=0):
    """Cluster bootstrap at predeclared task level, keeping repeated seeds together.

    The same case/seed cannot be counted twice. Evaluator signatures are not extra
    observations. Intervals are exploratory unless the suite and trial budget were
    genuinely committed before selection; this function cannot establish that.
    """
    digest_text(suite_hash); digest_text(profile_id)
    require(type(rows) is list and 2 <= len(rows) <= 10000, 'SAMPLES', 'Need 2..10000 paired observations')
    require(type(trial_budget) is int and 1 <= trial_budget <= 10000, 'TRIALS', 'Invalid trial budget')
    require(type(alpha_ppm) is int and 1 <= alpha_ppm <= 200000, 'ALPHA', 'Invalid alpha')
    require(type(resamples) is int and 100 <= resamples <= 10000, 'RESAMPLES', 'Invalid resampling budget')
    seen, groups = set(), {}
    for r in rows:
        keys(r, {'task_id','seed','baseline_success','candidate_success'})
        require(type(r['task_id']) is str and 0 < len(r['task_id']) <= 128 and type(r['seed']) is int, 'CASE', 'Invalid case identity')
        k = (r['task_id'],r['seed'])
        require(k not in seen, 'DUPLICATE_SAMPLE', 'Duplicate case/seed would inflate sample count')
        seen.add(k)
        require(type(r['baseline_success']) is bool and type(r['candidate_success']) is bool, 'OUTCOME', 'Binary outcomes required')
        groups.setdefault(r['task_id'], []).append(int(r['candidate_success'])-int(r['baseline_success']))
    require(len(groups) >= 2, 'CLUSTERS', 'At least two independent task clusters are required')
    # Equal task weighting avoids giving more weight to tasks with more repeated seeds.
    means = np.array([np.mean(groups[k]) for k in sorted(groups)], dtype=np.float64)
    rng = np.random.default_rng(seed)
    values = np.empty(resamples)
    for start in range(0, resamples, 100):
        n = min(100, resamples-start)
        values[start:start+n] = means[rng.integers(0,len(means),(n,len(means)))].mean(1)
    alpha = alpha_ppm/1e6/trial_budget
    lo,hi = np.quantile(values,[alpha/2,1-alpha/2])
    plus = sum(r['candidate_success'] and not r['baseline_success'] for r in rows)
    minus = sum(r['baseline_success'] and not r['candidate_success'] for r in rows)
    return {'schema':'btx.neuronlab.evaluation/1', 'suite_hash':suite_hash, 'profile_id':profile_id,
        'sample_commitment':identity('BTX/NeuronLab/PairedSamples/1', sorted(rows,key=lambda x:(x['task_id'],x['seed']))),
        'pairs':len(rows), 'task_clusters':len(groups), 'improved_pairs':plus, 'regressed_pairs':minus,
        'mean_delta_ppm':round(float(means.mean())*1e6), 'interval_ppm':[round(float(lo)*1e6),round(float(hi)*1e6)],
        'trial_budget':trial_budget, 'alpha_ppm':alpha_ppm, 'resamples':resamples, 'bootstrap_seed':seed,
        'method':'equal-task-weighted cluster percentile bootstrap; Bonferroni trial budget',
        'status':'EXPLORATORY_UNLESS_PREREGISTRATION_INDEPENDENTLY_ESTABLISHED',
        'release_authority':False}


def bh_adjust(pvalues):
    a = np.asarray(pvalues,dtype=np.float64)
    require(a.ndim == 1 and 0 < a.size <= 10000 and np.isfinite(a).all() and ((a>=0)&(a<=1)).all(), 'PVALUES', 'Invalid p-values')
    order = np.argsort(a,kind='stable'); adjusted = np.minimum.accumulate((a[order]*len(a)/np.arange(1,len(a)+1))[::-1])[::-1]
    result = np.empty_like(a); result[order] = np.minimum(adjusted,1)
    return result.tolist()


def deduplicate_attestations(reports):
    """Do not count repeated reports on the same sample set as new samples."""
    groups = {}
    for r in reports:
        k = (r['suite_hash'],r['profile_id'],r['sample_commitment'])
        groups.setdefault(k,[]).append(r)
    return [{'suite_hash':k[0], 'profile_id':k[1], 'sample_commitment':k[2],
             'attestations':len(v), 'statistical_sample_sets':1,
             'administrative_independence':'MUST_BE_ESTABLISHED_EXTERNALLY'} for k,v in groups.items()]


def representation_metrics(activations, labels, *, concept_count=4):
    """Observable proxies with explicit non-equivalence to superposition."""
    a = np.asarray(activations,dtype=np.float64); y = np.asarray(labels,dtype=np.int64)
    require(a.ndim==2 and 4<=a.shape[0]<=8192 and a.shape[1]<=8192 and y.shape==(a.shape[0],), 'METRICS', 'Invalid capture matrix')
    require(np.isfinite(a).all() and ((y>=0)&(y<concept_count)).all(), 'METRICS', 'Invalid capture labels')
    k=max(2,math.ceil(a.shape[0]*0.1))
    units=[]
    for i in range(a.shape[1]):
        top=np.argsort(np.abs(a[:,i]),kind='stable')[-k:]
        counts=np.bincount(y[top],minlength=concept_count).astype(float)
        p=counts/counts.sum(); nonzero=p[p>0]
        entropy=-float((nonzero*np.log(nonzero)).sum())/math.log(concept_count)
        units.append({'unit':i,'top_decile_label_purity_ppm':round(float(p.max())*1e6),
                      'label_entropy_ppm':round(entropy*1e6)})
    centered=a-a.mean(0)
    # Cap exact SVD workload. No unlimited all-pairs neuron matrix.
    matrix=centered[:2048,:512]
    s=np.linalg.svd(matrix,compute_uv=False)
    e=s*s
    participation=float(e.sum()**2/(e@e)) if float(e@e)>0 else 0
    return {'units':units[:512], 'units_omitted':max(0,len(units)-512),
            'participation_ratio_millionths':round(participation*1e6),
            'svd_rows':matrix.shape[0], 'svd_columns':matrix.shape[1],
            'interpretation':'TASK_LABEL_SELECTIVITY_AND_REPRESENTATION_RANK_PROXIES; NOT A SUPERPOSITION ESTIMATOR'}
