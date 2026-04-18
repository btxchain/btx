#!/usr/bin/env python3
"""Independent MatRiCT+ transcript checker for deterministic and randomized corpora.

This checker intentionally does not call into BTX C++ verification code. It
recomputes the ring-signature Fiat-Shamir seed, balance-proof transcript hash,
range-proof binding / relation transcript hashes, and the top-level MatRiCT+
challenge seed from a generated corpus artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


def ser_compact_size(value: int) -> bytes:
    if value < 0:
        raise ValueError("compact size must be non-negative")
    if value < 253:
        return struct.pack("<B", value)
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def ser_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return ser_compact_size(len(encoded)) + encoded


def ser_u32(value: int) -> bytes:
    return struct.pack("<I", value)


def ser_i32(value: int) -> bytes:
    return struct.pack("<i", value)


def ser_i64(value: int) -> bytes:
    return struct.pack("<q", value)


def uint256_hex_to_ser_bytes(value: str) -> bytes:
    return bytes.fromhex(value)[::-1]


def blob_hex_to_bytes(value: str) -> bytes:
    return bytes.fromhex(value)


def ser_uint256_vector(values: list[str]) -> bytes:
    return ser_compact_size(len(values)) + b"".join(uint256_hex_to_ser_bytes(v) for v in values)


def ser_nested_uint256_vector(values: list[list[str]]) -> bytes:
    return ser_compact_size(len(values)) + b"".join(ser_uint256_vector(row) for row in values)


def ser_blob_vector(blobs: list[str]) -> bytes:
    return ser_compact_size(len(blobs)) + b"".join(blob_hex_to_bytes(blob) for blob in blobs)


def ser_nested_blob_vector(blobs: list[list[str]]) -> bytes:
    return ser_compact_size(len(blobs)) + b"".join(ser_blob_vector(row) for row in blobs)


def hash_gethex(preimage: bytes) -> str:
    return hashlib.sha256(preimage).digest()[::-1].hex()


def check_ring_signature(sample: dict, params: dict) -> list[str]:
    ring = sample["transcripts"]["ring_signature"]
    preimage = bytearray()
    preimage.extend(ser_string("BTX_MatRiCT_RingSig_FS_V3"))
    preimage.extend(ser_u32(params["poly_n"]))
    preimage.extend(ser_i32(params["poly_q"]))
    preimage.extend(ser_u32(params["module_rank"]))
    preimage.extend(ser_u32(params["ring_size"]))
    preimage.extend(uint256_hex_to_ser_bytes(ring["message_hash_hex"]))
    preimage.extend(ser_nested_uint256_vector(ring["ring_members_hex"]))
    preimage.extend(ser_blob_vector(ring["key_images_serialized_hex"]))
    preimage.extend(ser_nested_blob_vector(ring["member_public_key_offsets_serialized_hex"]))
    for input_chunks in ring["transcript_chunks_serialized_hex"]:
        for chunk in input_chunks:
            preimage.extend(blob_hex_to_bytes(chunk))
    actual = hash_gethex(bytes(preimage))
    expected = ring["expected_challenge_seed_hex"]
    return [] if actual == expected else [f"ring_signature.challenge_seed mismatch: expected {expected}, got {actual}"]


def check_balance_proof(sample: dict, params: dict) -> list[str]:
    balance = sample["transcripts"]["balance_proof"]
    fixture = sample["fixture"]
    preimage = bytearray()
    preimage.extend(ser_string("BTX_MatRiCT_BalanceProof_V2"))
    preimage.extend(ser_u32(params["poly_n"]))
    preimage.extend(ser_i32(params["poly_q"]))
    preimage.extend(ser_u32(params["module_rank"]))
    preimage.extend(blob_hex_to_bytes(balance["nonce_commitment_serialized_hex"]))
    preimage.extend(blob_hex_to_bytes(balance["statement_commitment_serialized_hex"]))
    preimage.extend(ser_blob_vector(balance["input_commitments_serialized_hex"]))
    preimage.extend(ser_blob_vector(balance["output_commitments_serialized_hex"]))
    preimage.extend(ser_i64(fixture["fee_sat"]))
    preimage.extend(uint256_hex_to_ser_bytes(fixture["tx_binding_hash_hex"]))
    actual = hash_gethex(bytes(preimage))
    expected = balance["expected_transcript_hash_hex"]
    return [] if actual == expected else [f"balance_proof.transcript_hash mismatch: expected {expected}, got {actual}"]


def check_range_proofs(sample: dict, params: dict) -> list[str]:
    failures: list[str] = []
    for idx, range_proof in enumerate(sample["transcripts"]["range_proofs"]):
        binding_preimage = bytearray()
        binding_preimage.extend(ser_string("BTX_MatRiCT_RangeProof_Binding_V1"))
        binding_preimage.extend(ser_u32(params["poly_n"]))
        binding_preimage.extend(ser_i32(params["poly_q"]))
        binding_preimage.extend(ser_u32(params["module_rank"]))
        binding_preimage.extend(blob_hex_to_bytes(range_proof["value_commitment_serialized_hex"]))
        binding_preimage.extend(ser_blob_vector(range_proof["bit_commitments_serialized_hex"]))
        for bit_proof in range_proof["bit_proofs"]:
            binding_preimage.extend(uint256_hex_to_ser_bytes(bit_proof["c0_hex"]))
            binding_preimage.extend(uint256_hex_to_ser_bytes(bit_proof["c1_hex"]))
            binding_preimage.extend(blob_hex_to_bytes(bit_proof["z0_serialized_hex"]))
            binding_preimage.extend(blob_hex_to_bytes(bit_proof["z1_serialized_hex"]))
        binding_actual = hash_gethex(bytes(binding_preimage))
        binding_expected = range_proof["expected_bit_proof_binding_hex"]
        if binding_actual != binding_expected:
            failures.append(
                f"range_proofs[{idx}].bit_proof_binding mismatch: expected {binding_expected}, got {binding_actual}"
            )

        transcript_preimage = bytearray()
        transcript_preimage.extend(ser_string("BTX_MatRiCT_RangeProof_Relation_V4"))
        transcript_preimage.extend(ser_u32(params["poly_n"]))
        transcript_preimage.extend(ser_i32(params["poly_q"]))
        transcript_preimage.extend(ser_u32(params["module_rank"]))
        transcript_preimage.extend(blob_hex_to_bytes(range_proof["relation_nonce_commitment_serialized_hex"]))
        transcript_preimage.extend(blob_hex_to_bytes(range_proof["value_commitment_serialized_hex"]))
        transcript_preimage.extend(ser_blob_vector(range_proof["bit_commitments_serialized_hex"]))
        transcript_preimage.extend(blob_hex_to_bytes(range_proof["statement_commitment_serialized_hex"]))
        transcript_actual = hash_gethex(bytes(transcript_preimage))
        transcript_expected = range_proof["expected_transcript_hash_hex"]
        if transcript_actual != transcript_expected:
            failures.append(
                f"range_proofs[{idx}].transcript_hash mismatch: expected {transcript_expected}, got {transcript_actual}"
            )
    return failures


def check_top_level(sample: dict) -> list[str]:
    fixture = sample["fixture"]
    top = sample["transcripts"]["top_level_proof"]
    preimage = bytearray()
    preimage.extend(ser_string("BTX_MatRiCT_Proof_V2"))
    preimage.extend(uint256_hex_to_ser_bytes(top["ring_signature_challenge_seed_hex"]))
    preimage.extend(uint256_hex_to_ser_bytes(top["balance_proof_transcript_hash_hex"]))
    for range_transcript in top["range_proof_transcript_hashes_hex"]:
        preimage.extend(uint256_hex_to_ser_bytes(range_transcript))
    preimage.extend(ser_uint256_vector(top["output_note_commitments_hex"]))
    preimage.extend(ser_i64(fixture["fee_sat"]))
    preimage.extend(uint256_hex_to_ser_bytes(fixture["tx_binding_hash_hex"]))
    actual = hash_gethex(bytes(preimage))
    expected = top["expected_challenge_seed_hex"]
    return [] if actual == expected else [f"top_level.challenge_seed mismatch: expected {expected}, got {actual}"]


def check_sample(sample: dict, params: dict) -> list[str]:
    failures: list[str] = []
    failures.extend(check_ring_signature(sample, params))
    failures.extend(check_balance_proof(sample, params))
    failures.extend(check_range_proofs(sample, params))
    failures.extend(check_top_level(sample))
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify MatRiCT+ transcript corpora independently from BTX verifier code.")
    parser.add_argument("corpus", type=Path, help="Path to transcript corpus JSON")
    args = parser.parse_args()

    corpus = json.loads(args.corpus.read_text(encoding="utf-8"))
    params = corpus["parameters"]
    failures: list[str] = []

    for sample in corpus["samples"]:
        sample_failures = check_sample(sample, params)
        if sample_failures:
            failures.extend(f"{sample['label']}: {failure}" for failure in sample_failures)

    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1

    print(
        f"PASS checked {len(corpus['samples'])} MatRiCT+ transcript samples "
        f"({corpus.get('random_sample_count', 0)} randomized) from {args.corpus}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
