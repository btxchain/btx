"""Bounded scientific tensor I/O. No payload-selected Python/module names."""
from __future__ import annotations
import hashlib
import math
from dataclasses import dataclass
import torch
from .codec import require, integer, keys, identity, canonical
from .operators import model_lock

SITES = ('embedding', 'residual_pre', 'attention_pre_output', 'attention_post',
         'mlp_post_activation', 'mlp_post_output', 'residual_post')
MAX_CAPTURE_BYTES = 64 * 1024 * 1024


def token_ids(value, vocab, limit=2048):
    require(type(value) is list and 1 <= len(value) <= limit, 'TOKEN_BUDGET', 'Nonempty bounded token sequence required')
    return [integer(i, 0, vocab-1, 'token') for i in value]


def vocabulary(model):
    if hasattr(model, 'config_dict'): return model.config_dict['vocab_size']
    return int(model.get_output_embeddings().weight.shape[0])


def context_limit(model):
    if hasattr(model, 'config_dict'): return 512
    c = getattr(model.config, 'text_config', model.config)
    return min(8192, int(getattr(c, 'max_position_embeddings', getattr(c, 'n_positions', 2048))))


def device_of(model): return next(model.parameters()).device


def weights_digest(model):
    """Expensive audit path, not an idle GUI poll. Never transfers all weights at once."""
    h = hashlib.sha384()
    for name, p in sorted(model.state_dict().items()):
        h.update(name.encode()); h.update(str(p.dtype).encode()); h.update(canonical(list(p.shape)))
        flat = p.detach().reshape(-1)
        for start in range(0, flat.numel(), 262144):
            h.update(flat[start:start+262144].contiguous().cpu().view(torch.uint8).numpy().tobytes())
    return h.hexdigest()


def site_key(layer, site): return f'{layer}:{site}'


def point(value, binding):
    keys(value, {'layer', 'site', 'tokens'}, {'units','heads'})
    integer(value['layer'], 0, binding['layers']-1, 'layer')
    require(value['site'] in SITES, 'SITE', 'Unknown scientific hook point')
    require(value['site'] != 'embedding' or value['layer'] == 0, 'SITE', 'Embedding is a single model-level site')
    for k, cap in [('tokens', 2048), ('units', 4096)]:
        v = value.get(k, [])
        require(type(v) is list and len(v) <= cap and len(set(v)) == len(v), 'COORDINATES', 'Duplicate/oversized coordinate set')
        for n in v: integer(n, 0, 131071, k)
    heads=value.get('heads',[])
    require(type(heads)is list and len(heads)<=binding['heads'] and len(set(heads))==len(heads),'HEADS','Invalid head selection')
    for head in heads:integer(head,0,binding['heads']-1,'head')
    require(not heads or (value['site']=='attention_pre_output' and not value.get('units')),'HEADS','Head selection is only valid before attention output projection and cannot mix with unit selection')
    require(value['tokens'], 'COORDINATES', 'Select at least one token')
    return dict(value, units=value.get('units', []))


def unwrap(out):
    x = out[0] if isinstance(out, tuple) else out
    require(isinstance(x, torch.Tensor) and x.ndim == 3 and x.shape[0] == 1, 'HOOK_LAYOUT', 'Expected single-request [batch,token,feature] tensor')
    return x


class Hooks:
    """Owns all forward hooks for one experiment. Serial per model, finite capture cap.

    edits[(layer,site)] is a *trusted local callable*, never deserialized model code.
    Captures are POST edit at each requested point; path experiments state that order.
    """
    def __init__(self, model, adapter, capture=(), edits=None, fence=None, budget=MAX_CAPTURE_BYTES):
        self.model, self.adapter, self.fence = model, adapter, fence
        self.wanted, self.edits = set(capture), edits or {}
        self.values, self.handles, self.used = {}, [], 0
        self.lock = model_lock(model); self.budget = budget
    def _apply(self, key, x):
        unwrap(x)
        if self.fence: self.fence()
        y = self.edits[key](x) if key in self.edits else x
        require(y.shape == x.shape and y.dtype == x.dtype and y.device == x.device, 'PATCH_SHAPE', 'Edit changed activation shape, precision or device')
        require(torch.isfinite(y).all().item(), 'NONFINITE', 'Nonfinite scientific activation')
        if key in self.wanted:
            require(key not in self.values, 'HOOK_REENTRY', 'Repeated hook execution is unsupported for this trace')
            size = y.numel()*4
            require(self.used+size <= self.budget, 'CAPTURE_BUDGET', 'Requested capture exceeds memory budget; split the experiment')
            self.values[key] = y.detach().to(device='cpu', dtype=torch.float32).clone()
            self.used += size
        return y
    def __enter__(self):
        require(self.lock.acquire(blocking=False), 'MODEL_BUSY', 'Another operation owns this model')
        try:
            require(not self.model.training, 'TRAIN_MODE', 'Scientific inference requires eval mode')
            for key in sorted(self.wanted | set(self.edits)):
                module, when = self.adapter.hook_target(*key)
                if when == 'pre':
                    def pre(mod, args, kwargs, key=key):
                        if args: return (self._apply(key, args[0]), *args[1:]), kwargs
                        require('hidden_states' in kwargs, 'HOOK_LAYOUT', 'No input hidden states at reviewed hook')
                        return args, dict(kwargs, hidden_states=self._apply(key, kwargs['hidden_states']))
                    self.handles.append(module.register_forward_pre_hook(pre, with_kwargs=True))
                else:
                    def post(mod, args, out, key=key):
                        y = self._apply(key, unwrap(out))
                        return (y, *out[1:]) if isinstance(out, tuple) else y
                    self.handles.append(module.register_forward_hook(post))
            return self
        except BaseException:
            for h in self.handles: h.remove()
            self.handles.clear(); self.lock.release(); raise
    def __exit__(self, *exc):
        for h in self.handles: h.remove()
        self.handles.clear(); self.lock.release()


def forward(model, adapter, ids, *, capture=(), edits=None, fence=None, budget=MAX_CAPTURE_BYTES):
    ids = token_ids(ids, vocabulary(model), min(2048, context_limit(model)))
    if fence: fence()
    with Hooks(model, adapter, capture, edits, fence, budget) as h, torch.inference_mode():
        tokens = torch.tensor([ids], dtype=torch.long, device=device_of(model))
        result = model(input_ids=tokens, attention_mask=torch.ones_like(tokens), use_cache=False)
        logits = result.logits.detach().float().cpu()
        require(torch.isfinite(logits).all().item(), 'NONFINITE', 'Nonfinite output logits')
    if fence: fence()
    return logits, h.values


def metric_spec(spec, vocab, length):
    keys(spec, {'kind', 'target', 'foil', 'position'})
    require(spec['kind'] in {'logit_difference', 'log_probability', 'probability'}, 'METRIC', 'Unknown causal metric')
    integer(spec['target'], 0, vocab-1, 'target token')
    integer(spec['foil'], 0, vocab-1, 'foil token')
    require(spec['target'] != spec['foil'], 'METRIC', 'Target and foil must differ')
    integer(spec['position'], -length, length-1, 'prediction position')
    return spec


def metric(logits, spec):
    z = logits[0, spec['position']].double()
    if spec['kind'] == 'logit_difference': return float(z[spec['target']]-z[spec['foil']])
    l = torch.log_softmax(z, -1)[spec['target']]
    return float(l.exp() if spec['kind'] == 'probability' else l)


def ppm(value):
    # Returned measurements remain exact safe integers across the GUI JSON boundary.
    require(math.isfinite(float(value)) and abs(float(value)) < 9e9, 'NUMBER', 'Unrepresentable measured number')
    return int(round(float(value)*1_000_000))


def restoration(patched, base, source, eps=1e-8):
    delta = patched-base; denom = source-base
    return {'metric_millionths': ppm(patched), 'effect_millionths': ppm(delta),
            'restoration_millionths': ppm(delta/denom) if abs(denom) > eps else None,
            'normalization': 'UNCLIPPED' if abs(denom) > eps else 'UNDEFINED_NEAR_ZERO_BASELINE_GAP'}
