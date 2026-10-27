import json
import pytest
from btx_neuronlab.codec import LabError
from btx_neuronlab.models import load_local, model_binding
from btx_neuronlab.tiny import TinyLM


def _tiny_model_dir(tmp_path):
    root = tmp_path / 'model'
    try:
        TinyLM().save(root)
    except Exception:
        pytest.skip('torch cannot save the tiny model')
    return root


def test_weight_index_parent_path_is_refused(tmp_path):
    root = _tiny_model_dir(tmp_path)
    outside = tmp_path / 'outside.safetensors'
    outside.write_bytes((root / 'model.safetensors').read_bytes())
    (root / 'model.safetensors.index.json').write_text(json.dumps({
        'weight_map': {'embedding.weight': '../outside.safetensors'},
    }), encoding='utf-8')
    with pytest.raises(LabError) as caught:
        model_binding(root)
    assert caught.value.code == 'WEIGHTS'


def test_weight_index_hash_changes_when_map_names_an_extra_shard(tmp_path):
    root = _tiny_model_dir(tmp_path)
    unmodified = model_binding(root)[0]['weights_hash']
    extra = root / 'extra.safetensors'
    extra.write_bytes((root / 'model.safetensors').read_bytes())
    with_extra = model_binding(root)[0]['weights_hash']
    (root / 'model.safetensors.index.json').write_text(json.dumps({
        'weight_map': {'embedding.weight': 'extra.safetensors'},
    }), encoding='utf-8')
    remapped = model_binding(root)[0]['weights_hash']
    assert remapped != unmodified
    assert remapped != with_extra


def _require_transformers():
    try:
        import transformers
    except ImportError:
        pytest.skip('transformers is not importable')
    return transformers


def _save_tiny_gpt2(root):
    _require_transformers()
    from transformers import GPT2Config, GPT2LMHeadModel, GPT2Tokenizer
    config = GPT2Config(n_layer=1, n_head=1, n_embd=8, vocab_size=32, bos_token_id=0, eos_token_id=0)
    root.mkdir(parents=True)
    GPT2LMHeadModel(config).save_pretrained(root, safe_serialization=True)
    vocab = {'<|endoftext|>': 0, **{f'tok{i}': i for i in range(1, 32)}}
    vocab_path, merges_path = root / 'vocab.json', root / 'merges.txt'
    vocab_path.write_text(json.dumps(vocab), encoding='utf-8')
    merges_path.write_text('#version: 0.2\n', encoding='utf-8')
    try:
        tokenizer = GPT2Tokenizer(vocab_file=str(vocab_path), merges_file=str(merges_path))
    except TypeError:
        tokenizer = GPT2Tokenizer(vocab=vocab, merges=[])
    tokenizer.save_pretrained(root)
    return root


def test_omitted_tied_head_loads_from_the_input_embedding(tmp_path):
    torch = pytest.importorskip('torch')
    from safetensors.torch import save_file
    from btx_neuronlab.models import _load_declared_weights

    class Tied(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.embed = torch.nn.Embedding(4, 3)
            self.lm_head = torch.nn.Linear(3, 4, bias=False)
            self.lm_head.weight = self.embed.weight

        def get_input_embeddings(self):
            return self.embed

        def get_output_embeddings(self):
            return self.lm_head

    root = tmp_path / 'tied-head'
    root.mkdir()
    weight = torch.arange(12, dtype=torch.float32).reshape(4, 3)
    (root / 'config.json').write_text(json.dumps({'tie_word_embeddings': True}), encoding='utf-8')
    save_file({'embed.weight': weight}, root / 'model.safetensors')
    model = Tied()
    with torch.no_grad():
        model.embed.weight.zero_()
    _load_declared_weights(model, root)
    assert torch.equal(model.embed.weight.detach(), weight)
    assert torch.equal(model.lm_head.weight.detach(), weight)


def test_untied_or_extra_missing_head_stays_refused(tmp_path):
    torch = pytest.importorskip('torch')
    from safetensors.torch import save_file
    from btx_neuronlab.models import _load_declared_weights

    class Tied(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.embed = torch.nn.Embedding(4, 3)
            self.lm_head = torch.nn.Linear(3, 4, bias=False)
            self.lm_head.weight = self.embed.weight

        def get_input_embeddings(self):
            return self.embed

        def get_output_embeddings(self):
            return self.lm_head

    root = tmp_path / 'untied-head'
    root.mkdir()
    weight = torch.arange(12, dtype=torch.float32).reshape(4, 3)
    (root / 'config.json').write_text(json.dumps({'tie_word_embeddings': False}), encoding='utf-8')
    save_file({'embed.weight': weight}, root / 'model.safetensors')
    with pytest.raises(LabError) as caught:
        _load_declared_weights(Tied(), root)
    assert caught.value.code == 'WEIGHTS'


def test_tied_gpt2_save_pretrained_loads(tmp_path):
    root = _save_tiny_gpt2(tmp_path / 'tied')
    from safetensors import safe_open
    with safe_open(root / 'model.safetensors', framework='pt') as handle:
        keys = set(handle.keys())
    assert 'lm_head.weight' not in keys
    assert 'transformer.wte.weight' in keys
    model, _, _, _ = load_local(root)
    output_weight = model.get_output_embeddings().weight
    input_weight = model.get_input_embeddings().weight
    assert output_weight is input_weight or output_weight.data_ptr() == input_weight.data_ptr()


def test_untied_missing_lm_head_is_weights(tmp_path):
    root = _save_tiny_gpt2(tmp_path / 'untied')
    config_path = root / 'config.json'
    config = json.loads(config_path.read_text(encoding='utf-8'))
    config['tie_word_embeddings'] = False
    config_path.write_text(json.dumps(config), encoding='utf-8')
    with pytest.raises(LabError) as caught:
        load_local(root)
    assert caught.value.code == 'WEIGHTS'
