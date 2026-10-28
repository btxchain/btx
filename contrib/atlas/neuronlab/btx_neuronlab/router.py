"""Bounded, data-only context routing. Choice is not permission.

Only numeric features declared by the operator are accepted. A route can choose
among exact approved profiles or choose baseline, never create new authority.
"""
from __future__ import annotations
import math
from .codec import require, keys, text, digest_text, integer, identity


def validate_router(p):
    keys(p, {'schema','features','routes','fallback','minimum_margin_ppm','max_switches','policy_epoch'})
    require(p['schema']=='btx.neuronlab.router/1','ROUTER','Unknown router schema')
    require(type(p['features']) is list and 1<=len(p['features'])<=64 and len(set(p['features']))==len(p['features']), 'FEATURES','Invalid feature list')
    for x in p['features']: text(x,64)
    require(type(p['routes']) is list and 1<=len(p['routes'])<=16, 'ROUTES','Invalid route count')
    seen=set()
    for r in p['routes']:
        keys(r,{'profile_id','weights_ppm','bias_ppm'})
        digest_text(r['profile_id'])
        require(r['profile_id'] not in seen,'ROUTES','Duplicate route')
        seen.add(r['profile_id'])
        require(type(r['weights_ppm']) is list and len(r['weights_ppm'])==len(p['features']),'WEIGHTS','Router width mismatch')
        for w in r['weights_ppm']:integer(w,-100000000,100000000)
        integer(r['bias_ppm'],-100000000,100000000)
    require(p['fallback']=='baseline','FALLBACK','Only an unmodified baseline fallback is supported')
    integer(p['minimum_margin_ppm'],0,100000000)
    integer(p['max_switches'],0,128);integer(p['policy_epoch'],1,2**31-1)
    return p


def choose(p, features_ppm, approved_profiles, *, previous=None, switches=0):
    validate_router(p)
    integer(switches,0,128,'switch count')
    if previous is not None: digest_text(previous)
    keys(features_ppm,set(p['features']))
    values=[integer(features_ppm[k],-1000000,1000000,'normalized feature') for k in p['features']]
    scores=[]
    for r in p['routes']:
        if r['profile_id'] not in approved_profiles: continue
        score=r['bias_ppm']+sum(w*v//1000000 for w,v in zip(r['weights_ppm'],values))
        scores.append((score,r['profile_id']))
    scores.sort(key=lambda x:(-x[0],x[1]))
    choice=None;reason='NO_APPROVED_ROUTE'
    if scores:
        margin=scores[0][0]-(scores[1][0] if len(scores)>1 else 0)
        if margin>=p['minimum_margin_ppm']:
            choice=scores[0][1];reason='BOUNDED_LINEAR_SELECTION'
        else: reason='LOW_MARGIN_BASELINE'
    if choice!=previous and switches>=p['max_switches']:
        choice=None;reason='SWITCH_BUDGET_BASELINE'
    return {'profile_id':choice,'reason':reason,'policy_id':identity('BTX/NeuronLab/Router/1',p),
            'feature_commitment':identity('BTX/NeuronLab/RouteFeatures/1',features_ppm),
            'request_boundary_only':True,'grants_added':False,'scores':[{'profile_id':i,'score_ppm':s}for s,i in scores]}
