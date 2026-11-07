"""Host-byte admission. Shapes stay integers; nothing here builds the score tensor."""
import json
import struct
from pathlib import Path
import pytest
from btxmesh.codec import encode
from btxmesh.errors import MeshError
from btxmesh.executor import execute
from btxmesh.governor import DEFAULT_HOST_BYTES as GOVERNOR_DEFAULT_HOST_BYTES, Governor
from btxmesh.kv import choose_execution, prefix_should_transfer
from btxmesh.runtime import (
    DEFAULT_HOST_BYTES, DecoderConfig, admit_workload, attention_bytes, host_byte_budget, logit_bytes, parameter_elements,
)
from btxmesh.storage import atomic_write


def _policy(tmp_path, **extra):
    policy = {"idle_contribution": True, "slots": 4, "vram_bytes": 2**40, "cpu_threads": 1, "max_steps_per_job": 8, "allowed_executors": ["torch.train", "dataset.verify"]}
    policy.update(extra)
    atomic_write(tmp_path / "config.json", encode({"resource_policy": policy}))


def _review_config():
    # Legal reference bounds: the parameter cap still admits this shape.
    cfg = DecoderConfig(vocab=2, width=128, heads=128, context=32768)
    assert cfg.validate() is cfg
    return cfg


def test_parameter_estimate_includes_position_and_head():
    cfg = _review_config()
    previous = cfg.layers * cfg.width * cfg.width * 12 + cfg.vocab * cfg.width
    assert parameter_elements(cfg) == previous + cfg.context * cfg.width + cfg.vocab * cfg.width


def test_oversized_attention_rejected_before_allocation():
    cfg = _review_config()
    batch, sequence = 256, 32768
    attention = attention_bytes(batch, cfg.heads, sequence)
    assert attention == batch * cfg.heads * sequence * sequence * 4
    assert attention == 1 << 47
    assert attention > DEFAULT_HOST_BYTES
    params = parameter_elements(cfg) * 4
    assert host_byte_budget(cfg, batch, sequence) >= params + params + params + attention
    assert DEFAULT_HOST_BYTES == GOVERNOR_DEFAULT_HOST_BYTES == 2 * 1024**3
    with pytest.raises(MeshError, match="HOST_BUDGET"):
        admit_workload(cfg, batch, sequence)


def test_logits_and_kept_activations_are_counted():
    # One attention matrix is 1 GiB and fits, but the logits alone are 8 GiB,
    # and a training step keeps about four copies of them.
    cfg = DecoderConfig(vocab=65536, width=64, layers=1, heads=1, context=8192)
    params = parameter_elements(cfg) * 4
    assert params + params + params + attention_bytes(4, cfg.heads, 8192) < DEFAULT_HOST_BYTES
    assert logit_bytes(4, 8192, cfg.vocab) == 8 * 1024**3
    with pytest.raises(MeshError, match="HOST_BUDGET"):
        admit_workload(cfg, 4, 8192)
    # Backward keeps one softmax per layer, so depth counts too.
    deep = DecoderConfig(vocab=8, width=8, layers=96, heads=1, context=4096)
    assert attention_bytes(4, deep.heads, 4096) < DEFAULT_HOST_BYTES
    with pytest.raises(MeshError, match="HOST_BUDGET"):
        admit_workload(deep, 4, 4096)
    # Inference keeps no gradients, so the same shape costs less than training.
    assert host_byte_budget(cfg, 1, 1024, training=False) < host_byte_budget(cfg, 1, 1024)


def test_two_reservations_cannot_exceed_the_host_budget(tmp_path):
    _policy(tmp_path)
    governor = Governor(tmp_path)
    try:
        assert governor.host_ceiling() == 2 * 1024**3
        first = governor.host_ceiling() // 2 + 1
        governor.acquire("job-a", "realm", host_bytes=first)
        with pytest.raises(MeshError, match="DEVICE_HOST"):
            governor.acquire("job-b", "realm", host_bytes=first)
        with pytest.raises(MeshError, match="PHYSICAL_QUIESCENCE_REQUIRED"):
            governor.release("job-a", quiescent=False)
        governor.cancel("job-a")
        with pytest.raises(MeshError, match="DEVICE_HOST"):
            governor.acquire("job-b", "realm", host_bytes=first)
        governor.release("job-a", quiescent=True)
        governor.acquire("job-b", "realm", host_bytes=first)
    finally:
        governor.close()


def test_worker_consults_choose_execution_local_recompute():
    costs = {"prefill_ms": 5, "remote_queue_ms": 100, "local_queue_ms": 1, "bytes_to_move": 8_000_000, "bandwidth_bps": 1_000, "rtt_ms": 100, "decode_remote_ms": 0, "decode_local_ms": 0}
    assert choose_execution(**costs)["choice"] == "RECOMPUTE_LOCAL"
    locator = {"bytes": costs["bytes_to_move"], **{k: v for k, v in costs.items() if k != "bytes_to_move"}}
    assert prefix_should_transfer(locator) is False
    transfer = {"prefill_ms": 100_000, "remote_queue_ms": 100_000, "local_queue_ms": 0, "bytes_to_move": 8, "bandwidth_bps": 10**9, "rtt_ms": 1, "decode_remote_ms": 0, "decode_local_ms": 0}
    assert choose_execution(**transfer)["choice"] == "TRANSFER_KV"
    assert prefix_should_transfer({"bytes": transfer["bytes_to_move"], **{k: v for k, v in transfer.items() if k != "bytes_to_move"}}) is True
    worker = Path(__file__).resolve().parents[1] / "btxmesh" / "worker.py"
    text = worker.read_text()
    assert "if not prefix_should_transfer(locator):continue" in text
    assert "EngineProcess" not in text and "plan_engine" not in text
    executor = (worker.parent / "executor.py").read_text()
    assert executor.index('if op=="dataset.verify"') < executor.index("Decoder.from_checkpoint")
    assert 'device="cpu"' in executor


def test_dataset_verify_does_not_load_the_checkpoint(tmp_path):
    header = {"tokens": {"dtype": "I64", "shape": [1], "data_offsets": [0, 8]}}
    raw = json.dumps(header, separators=(",", ":")).encode()
    raw += b" " * ((8 - len(raw) % 8) % 8)
    blob = struct.pack("<Q", len(raw)) + raw + (1).to_bytes(8, "little")
    work = tmp_path / "job"
    work.mkdir()
    (work / "dataset.safetensors").write_bytes(blob)
    result = execute({"executor": "dataset.verify", "payload": {}}, work / "response.json")
    assert result["report"]["bytes"] == len(blob)
    assert not (work / "model.safetensors").exists()
