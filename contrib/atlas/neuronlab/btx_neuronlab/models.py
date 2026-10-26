"""Trusted, locally installed model adapters. Never deserialize pickle or remote code."""
from __future__ import annotations
import hashlib
import importlib.metadata
from pathlib import Path
import numpy as np
import torch
from .codec import require, canonical, loads, sha384, identity, read_file, LabError
from .schema import validate_binding, compatibility

ALLOWED = {
    'GPT2LMHeadModel': 'torch-gpt2-v1',
    'LlamaForCausalLM': 'torch-dense-v1',
    'Qwen2ForCausalLM': 'torch-dense-v1',
    'Qwen3ForCausalLM': 'torch-dense-v1',
    'Qwen3_5ForConditionalGeneration': 'torch-qwen35-v1',
    'BTXTinyLM': 'torch-tiny-v1',
    'MistralForCausalLM': 'torch-dense-v1',
    'GemmaForCausalLM': 'torch-dense-v1',
    'Gemma2ForCausalLM': 'torch-dense-v1',
    'Phi3ForCausalLM': 'torch-dense-v1',
    'Olmo2ForCausalLM': 'torch-dense-v1',
    'GPTNeoXForCausalLM': 'torch-neox-v1',
    'GPTJForCausalLM': 'torch-gptj-v1',
    'OPTForCausalLM': 'torch-opt-v1',
}


def file_digest(path):
    require(not path.is_symlink(), 'SYMLINK', 'Model symlink refused')
    h = hashlib.sha384()
    with path.open('rb') as f:
        while block := f.read(4*1024*1024): h.update(block)
    return h.hexdigest()


def execution_fingerprint(architecture):
    # Pin the reviewed numerical adapter and framework versions, not a claim of
    # bitwise equivalence across hardware or a lock of every transitive library.
    local = Path(__file__).resolve().parent
    files = ['models.py', 'operators.py', 'engine.py', 'tiny.py', 'schema.py', 'runtime_io.py', 'decoding.py', 'tracing.py']
    try: transformers_version = importlib.metadata.version('transformers')
    except importlib.metadata.PackageNotFoundError: transformers_version = 'not-installed'
    return identity('BTX/NeuronLab/ExecutionSemantics/1', {
        'torch': str(torch.__version__),
        'transformers': transformers_version if architecture != 'BTXTinyLM' else 'not-used',
        'math_policy': 'fp32-interventions/reference-single-request/v1',
        'modules': {f: sha384(read_file(local/f, 1_048_576)) for f in files}})


def model_binding(root: Path, btx_model_id=None):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), 'MODEL_PATH', 'A local model directory is required')
    config_bytes = read_file(root/'config.json', 1_048_576)
    config = loads(config_bytes, signed=False)
    require(type(config) is dict and not config.get('auto_map'), 'REMOTE_CODE', 'Custom/remote model code is refused')
    architectures = config.get('architectures', [])
    require(type(architectures) is list and len(architectures) == 1 and architectures[0] in ALLOWED, 'ARCHITECTURE', 'No admitted adapter for this exact model architecture')
    arch = architectures[0]
    c = config.get('text_config', config)
    require(not c.get('auto_map'), 'REMOTE_CODE', 'Nested custom model code refused')
    files = sorted(root.rglob('*'))
    require(len(files) <= 4096, 'FILES', 'Model directory entry limit exceeded')
    weights, tokenizer = [], []
    for f in files:
        require(not f.is_symlink(), 'SYMLINK', 'Model directory cannot contain symlinks')
        if not f.is_file(): continue
        require(f.suffix.lower() not in {'.bin', '.pt', '.pth', '.pkl', '.pickle', '.py', '.so', '.dll', '.dylib'}, 'UNSAFE_MODEL_FILE', 'Executable/pickle model payload refused')
        if f.suffix == '.safetensors':
            weights.append({'path': f.relative_to(root).as_posix(), 'bytes': f.stat().st_size, 'hash': file_digest(f)})
        elif f.name in {'tokenizer.json', 'tokenizer_config.json', 'special_tokens_map.json', 'vocab.json', 'merges.txt', 'tokenizer.model', 'added_tokens.json'}:
            tokenizer.append({'path': f.relative_to(root).as_posix(), 'bytes': f.stat().st_size, 'hash': file_digest(f)})
    require(weights and len(weights) <= 1024, 'WEIGHTS', 'SafeTensors weight files are required')
    hidden = c.get('hidden_size', c.get('n_embd'))
    layers = c.get('num_hidden_layers', c.get('n_layer'))
    heads = c.get('num_attention_heads', c.get('n_head'))
    inter = c.get('intermediate_size') or c.get('ffn_dim') or c.get('n_inner') or (4*hidden)
    activation = c.get('hidden_act', c.get('activation_function', 'unknown'))
    binding = {'weights_hash': identity('BTX/NeuronLab/WeightsTree/1', weights),
        'config_hash': sha384(config_bytes), 'tokenizer_hash': identity('BTX/NeuronLab/Tokenizer/1', tokenizer),
        'architecture': arch, 'adapter': ALLOWED[arch], 'execution_fingerprint': execution_fingerprint(arch), 'layers': layers, 'hidden_size': hidden,
        'intermediate_size': inter, 'heads': heads, 'activation': activation,
        'representation': 'safetensors/' + str(c.get('torch_dtype', c.get('dtype', 'declared-unspecified'))),
        'btx_model_id': btx_model_id}
    validate_binding(binding)
    return binding, config


class Adapter:
    def __init__(self, model, binding):
        self.model, self.binding = model, binding
        name = binding['adapter']
        if name == 'torch-tiny-v1': self.layers = model.blocks
        elif name == 'torch-gpt2-v1': self.layers = model.transformer.h
        elif name == 'torch-dense-v1': self.layers = model.model.layers
        elif name == 'torch-neox-v1': self.layers = model.gpt_neox.layers
        elif name == 'torch-gptj-v1': self.layers = model.transformer.h
        elif name == 'torch-opt-v1': self.layers = model.model.decoder.layers
        elif name == 'torch-qwen35-v1': self.layers = model.model.language_model.layers
        else: raise LabError('ADAPTER', 'Unimplemented adapter')
        require(len(self.layers) == binding['layers'], 'LAYER_COUNT', 'Runtime layer count differs from model binding')
        # Do not infer that a same-shaped module has the same semantics.
        self.name = name

    def hook_target(self, layer, site):
        require(0 <= layer < len(self.layers), 'LAYER', 'Layer out of range')
        block = self.layers[layer]
        try:
            if site == 'embedding':
                require(layer == 0, 'SITE', 'Only one embedding site exists')
                return (self.model.embedding if self.name == 'torch-tiny-v1' else self.model.get_input_embeddings()), 'post'
            if site == 'residual_pre': return block, 'pre'
            if site == 'residual_post': return block, 'post'
            if site in {'mlp_post_activation', 'mlp_post_output'}:
                if self.name == 'torch-gpt2-v1': mod = block.mlp.c_proj
                elif self.name == 'torch-gptj-v1': mod = block.mlp.fc_out
                elif self.name == 'torch-neox-v1': mod = block.mlp.dense_4h_to_h
                elif self.name == 'torch-opt-v1': mod = block.fc2
                else: mod = block.mlp.down_proj
                return mod, 'pre' if site == 'mlp_post_activation' else 'post'
            if site in {'attention_pre_output', 'attention_post'}:
                if self.name == 'torch-tiny-v1': mod = block.attention.out_proj
                elif self.name == 'torch-gpt2-v1': mod = block.attn.c_proj
                elif self.name == 'torch-gptj-v1': mod = block.attn.out_proj
                elif self.name == 'torch-neox-v1': mod = block.attention.dense
                elif self.name == 'torch-opt-v1': mod = block.self_attn.out_proj
                else:
                    if self.name == 'torch-qwen35-v1':
                        require(hasattr(block, 'self_attn'), 'HEAD_ADAPTER_UNSUPPORTED', 'Linear-attention layout needs its own qualification')
                    mod = block.self_attn.o_proj
                return mod, 'pre' if site == 'attention_pre_output' else 'post'
        except AttributeError as e:
            raise LabError('ADAPTER_LAYOUT', 'Installed engine layout differs from the reviewed adapter') from e
        raise LabError('HOOK', 'Unknown instrumentation point')

    def output_weight(self):
        return (self.model.lm_head if self.name == 'torch-tiny-v1' else self.model.get_output_embeddings()).weight

    def final_norm(self):
        if self.name == 'torch-tiny-v1': return self.model.norm
        if self.name in {'torch-gpt2-v1', 'torch-gptj-v1'}: return self.model.transformer.ln_f
        if self.name == 'torch-neox-v1': return self.model.gpt_neox.final_layer_norm
        if self.name == 'torch-opt-v1': return self.model.model.decoder.final_layer_norm
        if self.name == 'torch-qwen35-v1': return self.model.model.language_model.norm
        return self.model.model.norm

    def down_columns(self, layer, indices):
        module, _ = self.hook_target(layer, 'mlp_post_activation')
        w = module.weight.detach().float()
        if self.name == 'torch-gpt2-v1': w = w.T
        require(w.shape == (self.binding['hidden_size'], self.binding['intermediate_size']), 'WEIGHT_SHAPE', 'Down-projection shape mismatch')
        return w[:, indices]


def load_local(root: Path, binding=None, *, device='cpu'):
    root = Path(root)
    expected = binding
    binding, config = model_binding(root, expected.get('btx_model_id') if expected else None)
    if expected:
        require(compatibility({'binding': expected}, binding)['compatible'], 'INCOMPATIBLE', 'Registered model directory changed since review')
    require(device in {'cpu', 'cuda', 'mps'}, 'DEVICE', 'Unsupported device')
    require(device!='cuda' or torch.cuda.is_available(),'DEVICE','CUDA is not available in this runtime')
    require(device!='mps' or torch.backends.mps.is_available(),'DEVICE','MPS is not available in this runtime')
    if binding['architecture'] == 'BTXTinyLM':
        from .tiny import TinyLM
        from safetensors.torch import load_file
        model = TinyLM.from_config(config)
        model.load_state_dict(load_file(str(root/'model.safetensors')), strict=True)
        tokenizer = None
    else:
        try:
            import transformers
        except ImportError as e:
            raise LabError('ENGINE_ABSENT', 'Install an audited transformers build supporting this adapter; no online fallback') from e
        cls = getattr(transformers, binding['architecture'], None)
        require(cls is not None, 'ENGINE_ABSENT', 'Installed transformers does not implement this architecture')
        tokenizer = transformers.AutoTokenizer.from_pretrained(str(root), local_files_only=True, trust_remote_code=False)
        model = cls.from_pretrained(str(root), local_files_only=True, trust_remote_code=False,
                                    use_safetensors=True, torch_dtype=torch.float32)
    model = model.to(device).eval()
    # Science code does not train this instance. Attribution uses activation grads
    # explicitly and never accumulates parameter gradients.
    model.requires_grad_(False)
    return model, tokenizer, Adapter(model, binding), binding
