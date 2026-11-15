"""Controlled activation patching, mediated paths and pair interactions.

An intervention estimates an effect under the supplied counterfactual. Neither
this module nor a colourful heatmap establishes a complete causal explanation.
"""
from __future__ import annotations
import hashlib
import torch
from .codec import require, integer, keys, identity, LabError
from .engine import encode_prompt
from .runtime_io import (point, forward, metric, metric_spec, vocabulary, ppm,
                         restoration, device_of, MAX_CAPTURE_BYTES)


def aligned_tokens(clean, corrupt, alignment=None):
    if alignment is None:
        require(len(clean) == len(corrupt), 'ALIGNMENT_REQUIRED', 'Different token lengths require an explicit clean/corrupt index map')
        return dict(enumerate(range(len(corrupt))))
    require(type(alignment) is list and 0 < len(alignment) <= 2048, 'ALIGNMENT', 'Bounded explicit token pairs required')
    pairs = {}
    for row in alignment:
        require(type(row) is list and len(row) == 2, 'ALIGNMENT', 'Pairs are [clean_index, corrupted_index]')
        a = integer(row[0], 0, len(clean)-1); b = integer(row[1], 0, len(corrupt)-1)
        require(a not in pairs and b not in pairs.values(), 'ALIGNMENT', 'Token mapping must be one-to-one')
        pairs[a] = b
    return pairs


def _indices(cell, width, head_count=None):
    if cell.get("heads"):
        require(head_count is not None and width%head_count==0,"HEAD_LAYOUT","Actual attention width does not match declared query heads")
        stride=width//head_count
        return [h*stride+i for h in cell["heads"] for i in range(stride)]
    indices = cell.get('units', [])
    require(not indices or max(indices) < width, 'COORDINATES', 'Unit exceeds actual activation width')
    return indices or list(range(width))


def replacement(source, cell, mapping, *, kind='patch', mean=None, head_count=None):
    """Copy only chosen coordinates. Source and destination token positions differ."""
    require(source.ndim == 3 and source.shape[0] == 1, 'PATCH', 'Single-request source required')
    units = _indices(cell, source.shape[-1],head_count); tokens = cell['tokens']
    require(all(t in mapping and t < source.shape[1] for t in tokens), 'ALIGNMENT', 'Selected source token has no alignment')
    src_t = torch.tensor(tokens); dst_t = [mapping[t] for t in tokens]
    selected = source[0, src_t][:, units].clone()
    if kind == 'zero': selected.zero_()
    if kind == 'mean':
        require(mean is not None and mean.ndim == 1 and mean.shape[0] == source.shape[-1], 'MEAN_CONTROL', 'A declared external reference mean is required')
        selected[:] = mean[units]
    def apply(value):
        require(value.shape[-1] == source.shape[-1] and max(dst_t) < value.shape[1], 'PATCH_SHAPE', 'Patch and target shape mismatch')
        out = value.clone()
        t = torch.tensor(dst_t, device=value.device)[:, None]
        u = torch.tensor(units, device=value.device)[None, :]
        out[0, t, u] = selected.to(device=value.device, dtype=value.dtype)
        return out
    return apply


def combine_edits(edits, key, apply):
    if key in edits:
        old = edits[key]
        edits[key] = lambda x, old=old, apply=apply: apply(old(x))
    else: edits[key] = apply


def noise_edit(model, adapter, clean_ids, corruption):
    if corruption is None: return {}, None
    keys(corruption, {'kind','positions','std_ppm','seed'})
    require(corruption['kind'] == 'embedding_gaussian', 'CORRUPTION', 'Unknown corruption method')
    integer(corruption['std_ppm'], 1, 2_000_000); integer(corruption['seed'], 0, 2**31-1)
    positions = corruption['positions']
    require(type(positions) is list and 0 < len(positions) <= 128 and len(set(positions)) == len(positions), 'CORRUPTION', 'Bounded unique positions required')
    for pos in positions: integer(pos, 0, len(clean_ids)-1)
    module, _ = adapter.hook_target(0, 'embedding')
    width = int(module.weight.shape[-1])
    generator = torch.Generator(device='cpu').manual_seed(corruption['seed'])
    noise = torch.randn((len(positions), width), generator=generator, dtype=torch.float32)*(corruption['std_ppm']/1e6)
    digest = hashlib.sha384(noise.numpy().astype('<f4').tobytes()).hexdigest()
    def apply(x):
        out = x.clone(); out[:, positions] += noise.to(x.device, x.dtype); return out
    return {(0, 'embedding'): apply}, {'noise_f32_sha384': digest, **corruption}


class Experiment:
    """One exact pair, metric, and fixed corruption shared by all counterfactuals."""
    def __init__(self, model, tokenizer, adapter, binding, request, fence=None):
        keys(request, {'clean_prompt','corrupted_prompt','metric'}, {'alignment','corruption','direction'})
        self.model, self.adapter, self.binding, self.fence = model, adapter, binding, fence
        vocab = vocabulary(model)
        self.clean = encode_prompt(request['clean_prompt'], tokenizer, vocab)
        self.corrupt = encode_prompt(request['corrupted_prompt'], tokenizer, vocab)
        self.mapping = aligned_tokens(self.clean, self.corrupt, request.get('alignment'))
        self.metric = metric_spec(request['metric'], vocab, min(len(self.clean),len(self.corrupt)))
        self.direction = request.get('direction', 'denoise')
        require(self.direction in {'denoise','noise','zero'}, 'DIRECTION', 'Unknown patching direction')
        corruption = request.get('corruption')
        require(corruption is None or self.clean == self.corrupt, 'CORRUPTION', 'Embedding noise uses identical token inputs; do not combine with text corruption')
        self.noise, noise_meta = noise_edit(model, adapter, self.clean, corruption)
        self.clean_logits, _ = forward(model, adapter, self.clean, fence=fence)
        self.corrupt_logits, _ = forward(model, adapter, self.corrupt, edits=self.noise, fence=fence)
        self.clean_score = metric(self.clean_logits, self.metric)
        self.corrupt_score = metric(self.corrupt_logits, self.metric)
        self.source_ids, self.base_ids = (self.clean,self.corrupt) if self.direction=='denoise' else (self.corrupt,self.clean)
        self.source_edits = {} if self.direction=='denoise' else self.noise
        self.base_edits = self.noise if self.direction=='denoise' else {}
        self.source_score, self.base_score = (self.clean_score,self.corrupt_score) if self.direction=='denoise' else (self.corrupt_score,self.clean_score)
        self.map = self.mapping if self.direction=='denoise' else {v:k for k,v in self.mapping.items()}
        self.meta = {'schema':'btx.neuronlab.causal-design/1', 'binding':binding,
            'inputs': {'clean_ids':self.clean, 'corrupted_ids':self.corrupt,
                       'alignment':[[k,v] for k,v in self.mapping.items()]},
            'metric': self.metric, 'direction':self.direction, 'corruption':noise_meta,
            'clean_metric_millionths':ppm(self.clean_score), 'corrupted_metric_millionths':ppm(self.corrupt_score),
            'claim_scope':'CONTROLLED_INTERVENTION_ON_DECLARED_INPUTS_NOT_COMPLETE_CIRCUIT'}
        self.design_id = identity('BTX/NeuronLab/CausalDesign/1', self.meta)

    def validate(self, cells, limit=256):
        require(type(cells) is list and 1 <= len(cells) <= limit, 'CELL_BUDGET', 'Too many or empty causal cells')
        out = [point(c, self.binding) for c in cells]
        ids = [identity('BTX/NeuronLab/CausalCell/1',c) for c in out]
        require(len(set(ids))==len(ids), 'DUPLICATE_CELL', 'Duplicate experiment cells')
        return out

    def _capture(self, cells, source=True):
        sites = {(c['layer'],c['site']) for c in cells}
        ids = self.source_ids if source else self.base_ids
        _, captured = forward(self.model,self.adapter,ids,capture=sites,
                              edits=self.source_edits if source else self.base_edits,fence=self.fence)
        return captured

    def score(self, cells, source_cache):
        edits = dict(self.base_edits)
        for cell in cells:
            key = cell['layer'], cell['site']
            combine_edits(edits,key,replacement(source_cache[key],cell,self.map,kind='zero' if self.direction=='zero' else 'patch',head_count=self.binding['heads']))
        z,_ = forward(self.model,self.adapter,self.base_ids,edits=edits,fence=self.fence)
        return metric(z,self.metric)

    def scan(self, cells, progress=None):
        cells = self.validate(cells)
        # One site cache at a time: O(sequence * one site width), not all layers.
        results=[]; cache={}; previous=None
        for i,cell in enumerate(cells):
            key=cell['layer'],cell['site']
            if key!=previous:
                cache=self._capture([cell]); previous=key
            score=self.score([cell],cache)
            row={'cell':cell,'cell_id':identity('BTX/NeuronLab/CausalCell/1',cell),
                 **restoration(score,self.base_score,self.source_score)}
            if self.direction=='zero':row.update(restoration_millionths=None,normalization='NOT_APPLICABLE_TO_ZERO_ABLATION')
            results.append(row)
            if progress: progress({'type':'causal-cell','completed':i+1,'total':len(cells),'cell_id':row['cell_id'],'effect_millionths':row['effect_millionths']})
        return {'schema':'btx.neuronlab.causal-trace/1','design_id':self.design_id,'design':self.meta,
                'cells':results,'coverage':{'requested_cells':len(cells),'executed_cells':len(results),'universe_complete':False},
                'reference_direction':self.direction, 'safety_claim':False,
                'warning':'Effects depend on counterfactual, metric, token alignment and joint interactions. Negative/overshooting restoration is retained.'}

    def interaction(self, a, b):
        a,b=self.validate([a,b],2);cache=self._capture([a,b])
        # Overlapping coordinates are ambiguous because a patch would be applied twice.
        if (a['layer'],a['site'])==(b['layer'],b['site']):
            units_a=set(_indices(a,cache[a['layer'],a['site']].shape[-1],self.binding['heads']));units_b=set(_indices(b,cache[b['layer'],b['site']].shape[-1],self.binding['heads']))
            require(not(set(a['tokens'])&set(b['tokens']) and units_a&units_b),'OVERLAPPING_PATCH','Interaction factors must not overlap')
        sa,sb,sab=self.score([a],cache),self.score([b],cache),self.score([a,b],cache)
        return {'schema':'btx.neuronlab.joint-interaction/1','design_id':self.design_id,
                'a':a,'b':b,'base_millionths':ppm(self.base_score),'a_millionths':ppm(sa),'b_millionths':ppm(sb),
                'joint_millionths':ppm(sab),'interaction_millionths':ppm(sab-sa-sb+self.base_score),
                'interpretation':'FACTORIAL_NONADDITIVITY_ON_THIS_INPUT_PAIR_NOT_GLOBAL_INDEPENDENCE'}

    def path(self, sender, receiver, frozen=None):
        sender,receiver=self.validate([sender,receiver],2)
        frozen=self.validate(frozen,32) if frozen else []
        # Cross-block strict order avoids pretending hooks with architecture-dependent
        # intra-block ordering define the same causal path on every architecture.
        require(sender['layer']<receiver['layer'],'PATH_ORDER','Mediated path requires receiver in a strictly later decoder block')
        require(all(sender['layer']<f['layer']<receiver['layer'] for f in frozen),'PATH_ORDER','Frozen controls must be strictly intermediate')
        require(self.direction=='denoise','PATH_DIRECTION','Mediated paths use declared clean-to-corrupt restoration')
        src=self._capture([sender]);base=self._capture([receiver,*frozen],source=False)
        edits=dict(self.base_edits);key=sender['layer'],sender['site']
        combine_edits(edits,key,replacement(src[key],sender,self.map,head_count=self.binding['heads']))
        # Frozen controls use destination indices; the schema says so explicitly.
        destmap=dict(enumerate(range(len(self.base_ids))))
        for f in frozen:
            key=f['layer'],f['site'];combine_edits(edits,key,replacement(base[key],f,destmap,head_count=self.binding['heads']))
        rkey=receiver['layer'],receiver['site']
        _,mediated=forward(self.model,self.adapter,self.base_ids,capture=[rkey],edits=edits,fence=self.fence)
        # Replay only the receiver's resulting activation into a fresh original
        # corrupted pass. This measures mediation at a receiver, not all graph paths.
        edits=dict(self.base_edits)
        combine_edits(edits,rkey,replacement(mediated[rkey],receiver,destmap,head_count=self.binding['heads']))
        z,_=forward(self.model,self.adapter,self.base_ids,edits=edits,fence=self.fence)
        s=metric(z,self.metric)
        return {'schema':'btx.neuronlab.path-trace/1','design_id':self.design_id,'sender':sender,'receiver':receiver,
                'frozen':frozen,'receiver_tokens':'DESTINATION_TOKEN_INDICES','freeze_tokens':'DESTINATION_TOKEN_INDICES',
                **restoration(s,self.base_score,self.source_score),
                'estimand':'RECEIVER_MEDIATED_SENDER_EFFECT_WITH_EXPLICIT_FROZEN_CONTROLS',
                'exclusive_graph_path_proven':False}


def trace_grid(binding, layers, tokens, site='residual_post', units=None):
    require(type(layers) is list and type(tokens) is list and 0<len(layers)*len(tokens)<=4096,'GRID_BUDGET','Grid limit is 4096 cells; execute in chunks')
    return [point({'layer':l,'site':site,'tokens':[t],'units':units or []},binding) for l in layers for t in tokens]
