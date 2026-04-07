// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/bundle.h>
#include <shielded/merkle_tree.h>
#include <shielded/note.h>
#include <shielded/ringct/matrict.h>
#include <shielded/ringct/balance_proof.h>
#include <shielded/ringct/range_proof.h>
#include <shielded/ringct/ring_signature.h>

#include <streams.h>
#include <test/fuzz/fuzz.h>

#include <cassert>
#include <cstdint>
#include <ios>

using namespace shielded::ringct;

namespace {

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

    T obj2;
    try {
        ds >> obj2;
    } catch (const std::ios_base::failure&) {
        return false;
    }

    // Re-serialize the round-tripped object and compare bytes.
    DataStream ds2{};
    try {
        ds2 << obj2;
    } catch (const std::ios_base::failure&) {
        return false;
    }

    assert(ds.str() == ds2.str());
    return true;
}

} // namespace

FUZZ_TARGET(shielded_matrict_proof_deserialize)
{
    MatRiCTProof proof;
    if (!TryDeserialize(buffer, proof)) return;

    // Exercise validity check on successfully deserialized proof.
    (void)proof.IsValid();

    // S20: Exercise serialized size computation after deserialization.
    (void)proof.GetSerializedSize();

    // Round-trip: serialize then deserialize and compare.
    RoundTripCheck(proof);
}

FUZZ_TARGET(shielded_range_proof_deserialize)
{
    RangeProof proof;
    if (!TryDeserialize(buffer, proof)) return;

    (void)proof.IsValid();
    RoundTripCheck(proof);
}

FUZZ_TARGET(shielded_balance_proof_deserialize)
{
    BalanceProof proof;
    if (!TryDeserialize(buffer, proof)) return;

    (void)proof.IsValid();
    RoundTripCheck(proof);
}

FUZZ_TARGET(shielded_ring_signature_deserialize)
{
    RingSignature sig;
    if (!TryDeserialize(buffer, sig)) return;

    // IsValid requires expected sizes; use the deserialized values.
    if (!sig.input_proofs.empty()) {
        size_t ring_size = sig.input_proofs[0].responses.size();
        (void)sig.IsValid(sig.input_proofs.size(), ring_size);
    }

    RoundTripCheck(sig);
}

FUZZ_TARGET(shielded_ring_input_proof_deserialize)
{
    RingInputProof proof;
    if (!TryDeserialize(buffer, proof)) return;

    if (!proof.responses.empty()) {
        (void)proof.IsValid(proof.responses.size());
    }

    RoundTripCheck(proof);
}

// S17: CShieldedBundle fuzz target
FUZZ_TARGET(shielded_bundle_deserialize)
{
    CShieldedBundle bundle;
    if (!TryDeserialize(buffer, bundle)) return;

    (void)bundle.IsEmpty();
    (void)bundle.IsShieldOnly();
    (void)bundle.IsUnshieldOnly();
    (void)bundle.IsFullyShielded();
    (void)bundle.CheckStructure();

    RoundTripCheck(bundle);
}

// S18: ShieldedMerkleTree fuzz target
FUZZ_TARGET(shielded_merkle_tree_deserialize)
{
    shielded::ShieldedMerkleTree tree;
    if (!TryDeserialize(buffer, tree)) return;

    (void)tree.Root();
    (void)tree.Size();
    (void)tree.IsEmpty();

    RoundTripCheck(tree);
}

// S18: ShieldedMerkleWitness fuzz target
FUZZ_TARGET(shielded_merkle_witness_deserialize)
{
    shielded::ShieldedMerkleWitness witness;
    if (!TryDeserialize(buffer, witness)) return;

    // Exercise root computation (may throw on inconsistent state).
    try {
        (void)witness.Root();
        (void)witness.Position();
    } catch (const std::runtime_error&) {
        // Expected for inconsistent deserialized witnesses.
    }

    RoundTripCheck(witness);
}

// S19: ShieldedNote fuzz target
FUZZ_TARGET(shielded_note_deserialize)
{
    ShieldedNote note;
    if (!TryDeserialize(buffer, note)) return;

    (void)note.IsValid();

    // S20: Exercise verification after deserialization.
    if (note.IsValid()) {
        (void)note.GetCommitment();
    }

    RoundTripCheck(note);
}

// S21: CViewGrant fuzz target
FUZZ_TARGET(shielded_view_grant_deserialize)
{
    CViewGrant grant;
    if (!TryDeserialize(buffer, grant)) return;

    RoundTripCheck(grant);
}
