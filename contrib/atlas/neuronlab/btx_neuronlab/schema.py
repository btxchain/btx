"""Intervention profile v1. Every target is an exact coordinate, not a semantic label."""
from __future__ import annotations
from .codec import require, keys, text, integer, digest_text, bounded, identity

SCHEMA = 'btx.neuronlab.profile/1'
OPS = {'neuron_add', 'neuron_scale', 'neuron_clamp', 'head_scale',
       'residual_add', 'residual_project_out', 'sae_feature_add'}
FACTS = {'pretraining_dropout', 'finetuning_dropout', 'optimizer', 'weight_decay',
         'training_tokens', 'training_data', 'normalization', 'activation', 'post_training'}
LOCI = {'mlp_post_activation', 'attention_pre_output', 'residual_post'}
MAX_OPERATIONS = 64

def fact(value):
    keys(value, {'status', 'value', 'source'})
    require(value['status'] in {'unknown', 'reported', 'measured_in_this_study'}, 'FACT', 'Invalid evidence status')
    require(value['value'] is None if value['status'] == 'unknown' else value['value'] is not None,
            'FACT', 'Unknown history must stay null; reported facts need a value')
    require(type(value['source']) is str and len(value['source']) <= 512, 'FACT', 'Invalid fact source')
    require(value['status'] == 'unknown' or bool(value['source']), 'FACT', 'A nonunknown fact needs provenance')
    bounded(value)
    return value

def unknown_recipe():
    return {'schema': 'btx.neuronlab.training-recipe/1', 'facts': {
        name: {'status': 'unknown', 'value': None, 'source': ''} for name in sorted(FACTS)}}

def validate_recipe(recipe):
    keys(recipe, {'schema', 'facts'})
    require(recipe['schema'] == 'btx.neuronlab.training-recipe/1', 'RECIPE', 'Unknown training-recipe version')
    keys(recipe['facts'], FACTS)
    for value in recipe['facts'].values(): fact(value)
    return recipe

def validate_binding(b):
    keys(b, {'weights_hash', 'config_hash', 'tokenizer_hash', 'architecture', 'adapter',
             'layers', 'hidden_size', 'intermediate_size', 'heads', 'activation',
             'representation', 'btx_model_id', 'execution_fingerprint'})
    for name in ('weights_hash', 'config_hash', 'tokenizer_hash', 'execution_fingerprint'):
        digest_text(b[name], name)
    for name in ('architecture', 'adapter', 'activation', 'representation'):
        text(b[name], 128, name)
    integer(b['layers'], 1, 512, 'layer count')
    integer(b['hidden_size'], 1, 32768, 'hidden size')
    integer(b['intermediate_size'], 1, 131072, 'intermediate size')
    integer(b['heads'], 1, 1024, 'attention heads')
    require(b['hidden_size'] % b['heads'] == 0, 'HEADS', 'Hidden size must divide into heads for supported adapters')
    require(b['btx_model_id'] is None or (type(b['btx_model_id']) is str and len(b['btx_model_id']) <= 512), 'MODEL_ID', 'Invalid native ID')
    return b

def validate_operation(o, binding):
    keys(o, {'id', 'kind', 'layer', 'indices', 'coefficient_ppm', 'normalization', 'phase',
             'token_start', 'token_end', 'tensor', 'calibration', 'bounds_ppm', 'sae'})
    text(o['id'], 64)
    require(o['kind'] in OPS, 'OPERATOR', 'Unsupported operator')
    integer(o['layer'], 0, binding['layers'] - 1, 'layer')
    require(type(o['indices']) is list and len(o['indices']) <= 256 and all(type(i) is int for i in o['indices']) and len(set(o['indices'])) == len(o['indices']),
            'INDEX', 'Invalid or duplicate indices')
    limit = binding['heads'] if o['kind'] == 'head_scale' else binding['intermediate_size']
    for i in o['indices']: integer(i, 0, limit - 1, 'unit index')
    scalar = o['kind'] in {'neuron_add', 'neuron_scale', 'neuron_clamp', 'head_scale'}
    require(bool(o['indices']) if scalar else not o['indices'], 'INDEX', 'Wrong index form for operator')
    integer(o['coefficient_ppm'], -8_000_000, 8_000_000, 'coefficient millionths')
    require(o['normalization'] in {'absolute', 'token_l2', 'residual_median_downcol'}, 'NORMALIZATION', 'Unknown dose normalization')
    if o['kind'] == 'residual_add':
        require(o['normalization'] in {'absolute', 'token_l2'}, 'NORMALIZATION', 'Invalid residual normalization')
    elif o['kind'] == 'neuron_add':
        require(o['normalization'] in {'absolute', 'residual_median_downcol'}, 'NORMALIZATION', 'Invalid neuron normalization')
    else:
        require(o['normalization'] == 'absolute', 'NORMALIZATION', 'This operator uses absolute units')
    require(o['phase'] in {'both', 'prefill', 'decode'}, 'PHASE', 'Unknown phase')
    integer(o['token_start'], 0, 1_048_576)
    integer(o['token_end'], -1, 1_048_576)
    require(o['token_end'] == -1 or o['token_end'] > o['token_start'], 'SCHEDULE', 'Empty token interval')
    if o['kind'] in {'residual_add', 'residual_project_out'}:
        text(o['tensor'], 96)
    else:
        require(o['tensor'] is None, 'TENSOR', 'Unexpected direction tensor')
    if o['normalization'] == 'residual_median_downcol':
        keys(o['calibration'], {'corpus_hash', 'capture_hash', 'residual_median_millionths', 'down_column_norms_millionths'})
        c = o['calibration']
        digest_text(c['corpus_hash']); digest_text(c['capture_hash'])
        integer(c['residual_median_millionths'], 1, 10**14)
        require(type(c['down_column_norms_millionths']) is list and len(c['down_column_norms_millionths']) == len(o['indices']), 'CALIBRATION', 'Column norms missing')
        for n in c['down_column_norms_millionths']: integer(n, 1, 10**14)
    else:
        require(o['calibration'] is None, 'CALIBRATION', 'Unexpected calibration')
    if o['kind'] == 'neuron_clamp':
        require(type(o['bounds_ppm']) is list and len(o['bounds_ppm']) == 2, 'CLAMP', 'Two clamp bounds required')
        lo, hi = o['bounds_ppm']
        integer(lo, -100_000_000, 100_000_000); integer(hi, -100_000_000, 100_000_000)
        require(lo <= hi, 'CLAMP', 'Inverted clamp interval')
    else:
        require(o['bounds_ppm'] is None, 'CLAMP', 'Unexpected clamp bounds')
    if o['kind'] == 'sae_feature_add':
        keys(o['sae'], {'artifact_hash', 'encoder', 'decoder', 'bias', 'feature'})
        digest_text(o['sae']['artifact_hash'])
        for k in ('encoder', 'decoder', 'bias'): text(o['sae'][k], 96)
        integer(o['sae']['feature'], 0, 65535)
    else:
        require(o['sae'] is None, 'SAE', 'Unexpected SAE adapter')
    return o

def validate_profile(p):
    bounded(p)
    keys(p, {'schema', 'title', 'description', 'binding', 'training_recipe', 'operations',
             'parent_profiles', 'privacy', 'license', 'claims', 'created_ms', 'composition', 'tensors'})
    require(p['schema'] == SCHEMA, 'VERSION', 'Unsupported profile version')
    text(p['title'], 160); text(p['description'], 2048)
    validate_binding(p['binding']); validate_recipe(p['training_recipe'])
    require(p['composition'] == 'ordered/pre-site-norm/v1', 'COMPOSITION', 'Unknown composition semantics')
    require(type(p['operations']) is list and 1 <= len(p['operations']) <= MAX_OPERATIONS, 'OPERATIONS', 'Profile needs 1..64 operations')
    seen = set()
    for o in p['operations']:
        validate_operation(o, p['binding'])
        require(o['id'] not in seen, 'DUPLICATE_OPERATION', 'Operation IDs must be unique')
        seen.add(o['id'])
    require(type(p['parent_profiles']) is list and len(p['parent_profiles']) <= 8, 'PARENTS', 'Too many parents')
    for v in p['parent_profiles']: digest_text(v)
    require(p['privacy'] in {'private', 'realm', 'public'}, 'PRIVACY', 'Unknown privacy class')
    text(p['license'], 256)
    require(type(p['claims']) is list and len(p['claims']) <= 16, 'CLAIMS', 'Too many hypotheses')
    for c in p['claims']:
        keys(c, {'label', 'status', 'evidence_refs'})
        text(c['label'], 256)
        require(c['status'] in {'hypothesis', 'observed_on_declared_suite'}, 'CLAIM', 'Universal semantic claims are not a profile field')
        require(type(c['evidence_refs']) is list and len(c['evidence_refs']) <= 32, 'CLAIM', 'Invalid evidence list')
        for r in c['evidence_refs']: digest_text(r)
        require(c['status'] == 'hypothesis' or bool(c['evidence_refs']), 'CLAIM', 'Observed claim needs evidence')
    integer(p['created_ms'], 0, 2**63-1)
    require(type(p['tensors']) is dict and len(p['tensors']) <= 128, 'TENSORS', 'Too many tensor objects')
    for name, d in p['tensors'].items():
        text(name, 96)
        require(all(x.isascii() and (x.isalnum() or x in '._-') for x in name), 'TENSOR_NAME', 'Unsafe tensor name')
        keys(d, {'dtype', 'shape', 'sha384'})
        require(d['dtype'] == 'F32', 'DTYPE', 'Portable controls use finite little-endian float32')
        require(type(d['shape']) is list and 1 <= len(d['shape']) <= 2, 'SHAPE', 'Only vectors/matrices accepted')
        size = 1
        for n in d['shape']: size *= integer(n, 1, 131072)
        require(size <= 2_097_152, 'SIZE', 'Tensor exceeds 8 MiB element budget')
        digest_text(d['sha384'])
    for o in p['operations']:
        if o['tensor']:
            require(o['tensor'] in p['tensors'], 'TENSOR', 'Missing referenced direction')
            require(p['tensors'][o['tensor']]['shape'] == [p['binding']['hidden_size']], 'TENSOR', 'Direction width mismatch')
        if o['sae']:
            s = o['sae']; h = p['binding']['hidden_size']
            require(all(s[k] in p['tensors'] for k in ('encoder', 'decoder', 'bias')), 'SAE', 'Missing SAE tensors')
            es, ds, bs = (p['tensors'][s[k]]['shape'] for k in ('encoder', 'decoder', 'bias'))
            require(len(es) == 2 and es[1] == h and ds == [h, es[0]] and bs == [es[0]] and s['feature'] < es[0], 'SAE', 'SAE shape mismatch')
            binding = {k: p['tensors'][s[k]] for k in ('encoder', 'decoder', 'bias')}
            require(identity('BTX/NeuronLab/SAE/1', binding) == s['artifact_hash'], 'SAE', 'SAE identity mismatch')
    return p

def operation(kind='neuron_scale', layer=0, indices=None, coefficient_ppm=0, **kwargs):
    result = dict(id='op-1', kind=kind, layer=layer, indices=[0] if indices is None else indices,
                  coefficient_ppm=coefficient_ppm, normalization='absolute', phase='both', token_start=0,
                  token_end=-1, tensor=None, calibration=None, bounds_ppm=None, sae=None)
    result.update(kwargs)
    return result

def compatibility(profile, actual_binding):
    validate_binding(actual_binding)
    expected = profile['binding']
    # Native model ID is an origin/reference, not a substitute for byte identity.
    diffs = [k for k in expected if k != 'btx_model_id' and expected[k] != actual_binding[k]]
    return {'compatible': not diffs, 'mismatches': diffs,
            'migration': 'EXPLICIT_RECALIBRATION_AND_REEVALUATION_REQUIRED' if diffs else 'EXACT_BINDING'}
