// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <shielded/v2_types.h>
#include <streams.h>
#include <test/fuzz/fuzz.h>

#include <cassert>
#include <ios>
#include <string>
#include <vector>

namespace {

using namespace shielded::v2;

template <typename T>
bool TryDeserialize(FuzzBufferType buffer, T& obj)
{
    DataStream ds{buffer};
    try {
        ds >> obj;
    } catch (const std::ios_base::failure&) {
        return false;
    }
    return true;
}

template <typename T>
bool RoundTripCheck(const T& obj)
{
    DataStream ds{};
    try {
        ds << obj;
    } catch (const std::ios_base::failure&) {
        return false;
    }

    // Reading drains ds, so keep the first serialization to compare with.
    const std::string serialized{ds.str()};
    T decoded;
    try {
        ds >> decoded;
    } catch (const std::ios_base::failure&) {
        return false;
    }
    assert(ds.empty());

    DataStream ds2{};
    try {
        ds2 << decoded;
    } catch (const std::ios_base::failure&) {
        return false;
    }

    assert(serialized == ds2.str());
    return true;
}

} // namespace

FUZZ_TARGET(shielded_v2_note_deserialize)
{
    Note note;
    if (!TryDeserialize(buffer, note)) return;

    (void)note.IsValid();
    if (note.IsValid()) {
        (void)ComputeNoteCommitment(note);
    }
    RoundTripCheck(note);
}

FUZZ_TARGET(shielded_v2_encrypted_note_payload_deserialize)
{
    EncryptedNotePayload payload;
    if (!TryDeserialize(buffer, payload)) return;

    (void)payload.IsValid();
    RoundTripCheck(payload);
}

FUZZ_TARGET(shielded_v2_proof_envelope_deserialize)
{
    ProofEnvelope envelope;
    if (!TryDeserialize(buffer, envelope)) return;

    (void)envelope.IsValid();
    RoundTripCheck(envelope);
}

FUZZ_TARGET(shielded_v2_batch_leaf_deserialize)
{
    BatchLeaf leaf;
    if (!TryDeserialize(buffer, leaf)) return;

    (void)leaf.IsValid();
    if (leaf.IsValid()) {
        (void)ComputeBatchLeafHash(leaf);
    }
    RoundTripCheck(leaf);
}

FUZZ_TARGET(shielded_v2_proof_shard_deserialize)
{
    ProofShardDescriptor descriptor;
    if (!TryDeserialize(buffer, descriptor)) return;

    (void)descriptor.IsValid();
    if (descriptor.IsValid()) {
        (void)ComputeProofShardDescriptorHash(descriptor);
    }
    RoundTripCheck(descriptor);
}

FUZZ_TARGET(shielded_v2_output_chunk_deserialize)
{
    OutputChunkDescriptor descriptor;
    if (!TryDeserialize(buffer, descriptor)) return;

    (void)descriptor.IsValid();
    if (descriptor.IsValid()) {
        (void)ComputeOutputChunkDescriptorHash(descriptor);
    }
    RoundTripCheck(descriptor);
}

FUZZ_TARGET(shielded_v2_netting_manifest_deserialize)
{
    NettingManifest manifest;
    if (!TryDeserialize(buffer, manifest)) return;

    (void)manifest.IsValid();
    if (manifest.IsValid()) {
        (void)ComputeNettingManifestId(manifest);
    }
    RoundTripCheck(manifest);
}

FUZZ_TARGET(shielded_v2_transaction_header_deserialize)
{
    TransactionHeader header;
    if (!TryDeserialize(buffer, header)) return;

    (void)header.IsValid();
    if (header.IsValid()) {
        (void)ComputeTransactionHeaderId(header);
    }
    RoundTripCheck(header);
}
