import json
import pytest
from btx_neuronlab.codec import LabError
from btx_neuronlab.models import model_binding
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
