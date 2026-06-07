// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// DS-4c FORGE HARNESS — recovery / MatRiCT key-image double-spend.
//
// Demonstrates the DS-4 residual hole: the linkable ring signature binds the
// signer-chosen key_image and member_public_key_offset into the Fiat-Shamir
// transcript, but NOTHING binds the key_image to the *canonical* secret of the
// note being spent. The signer supplies input_secrets directly, so a malicious
// spender can pick ANY small secret s' (s' != canonical s), set
//
//     key_image'                   = s' * DeriveLinkGenerator(real_commitment)
//     member_public_key_offset'[r] = A*s' - DerivePublicKey(real_commitment, r)
//     responses'                   = CreateRingSignature(..., {s'}, msg')
//
// and obtain a SECOND fully-valid ring signature over the SAME ring (same real
// commitment) with a DIFFERENT key image => DIFFERENT nullifier. Both spends
// pass VerifyRingSignature / VerifyMatRiCTProof => the same note is spent twice
// under two distinct nullifiers. That is the double-spend.
//
// LEGACY path (ds4c_* cases): both the canonical and the forged spend verify
//   with DIFFERENT nullifiers — the residual on the un-bound legacy ring
//   signature. This residual is gated OFF at/after the 125000 sunset (the
//   recovery family is non-exit -> rejected) and is closed cryptographically by
//   bound mode below.
// BOUND mode (ds4_bound_* cases): the SAME forge is REJECTED — anchors are
//   consensus-fixed (T = A*s), offsets are forbidden, and the key image is the
//   unique G*s. CreateBoundRingSignature with a forged secret cannot build a
//   verifying signature. These are the DS-4 closure regression targets.
//
// References:
//   - src/shielded/ringct/ring_signature.cpp (CreateRingSignature: key_image =
//     PolyVecMulPoly(secret, DeriveLinkGenerator(real_commitment)); the offset
//     row at real_index = signer_public_key - DerivePublicKey(real_commitment))
//   - src/shielded/ringct/matrict.cpp (VerifyMatRiCTProof / nullifier binding)

#include <hash.h>
#include <random.h>
#include <shielded/lattice/params.h>
#include <shielded/lattice/polyvec.h>
#include <shielded/lattice/sampling.h>
#include <shielded/note.h>
#include <shielded/ringct/balance_proof.h>
#include <shielded/ringct/commitment.h>
#include <shielded/ringct/matrict.h>
#include <shielded/ringct/range_proof.h>
#include <shielded/ringct/ring_signature.h>
#include <span.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

using namespace shielded::ringct;
namespace lattice = shielded::lattice;

namespace {

ShieldedNote MakeNote(CAmount value)
{
    ShieldedNote n;
    n.value = value;
    n.recipient_pk_hash = GetRandHash();
    n.rho = GetRandHash();
    n.rcm = GetRandHash();
    return n;
}

// A signer-chosen *forged* small secret for the same real commitment, derived
// from an arbitrary domain-separated seed under the signer's control. It is in
// no way tied to the note's canonical secret — that is the whole point.
lattice::PolyVec DeriveForgedSecret(uint32_t variant, const uint256& real_commitment)
{
    HashWriter hw;
    hw << std::string{"BTX_DS4c_ForgedSecret_V1"};
    hw << variant;
    hw << real_commitment;
    const uint256 seed = hw.GetSHA256();
    FastRandomContext rng(seed);
    // Same distribution CreateRingSignature requires: small ternary, eta=2.
    return lattice::SampleSmallVec(rng, lattice::MODULE_RANK, lattice::SECRET_SMALL_ETA);
}

uint256 PolyVecHash(const lattice::PolyVec& vec)
{
    HashWriter hw;
    hw << vec;
    return hw.GetSHA256();
}

// Mirror of the (file-private) ComputeProofChallenge in matrict.cpp:53. The
// proof carries a self-consistency seal (proof.challenge_seed) over its public
// fields, so after splicing a forged ring signature we must re-seal it exactly
// as the prover would, otherwise VerifyMatRiCTProof rejects on the seal alone
// (matrict.cpp:461) — which is NOT the key-image binding we are probing.
// Keep this byte-for-byte in sync with ComputeProofChallenge.
uint256 RecomputeProofChallenge(const MatRiCTProof& proof, CAmount fee, const uint256& tx_binding_hash)
{
    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_Proof_V2"};
    hw << proof.ring_signature.challenge_seed;
    hw << proof.balance_proof.transcript_hash;
    for (const auto& rp : proof.output_range_proofs) {
        hw << rp.transcript_hash;
    }
    hw << proof.output_note_commitments;
    hw << fee;
    hw << tx_binding_hash;
    return hw.GetSHA256();
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(ds4_keyimage_forge_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// DS-4c-1: Ring-signature-level forge. Two valid signatures over the SAME ring
//          (same real spent commitment) under two DIFFERENT secrets s, s' yield
//          two DIFFERENT key images => two DIFFERENT nullifiers, both verifying.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ds4c_ring_signature_double_spend)
{
    // One input, one ring of the same real commitment for both spends.
    const size_t ring_size = lattice::RING_SIZE;
    const size_t real_index = 3;

    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(ring_size));
    for (auto& m : ring_members[0]) m = GetRandHash();
    const uint256 real_commitment = ring_members[0][real_index];
    const std::vector<size_t> real_indices{real_index};

    // The message hash is opaque to the forge: the attacker only needs ANY two
    // distinct small secrets for the same ring member. Use one shared message
    // to show that the ring itself does not pin the key image.
    const uint256 message_hash = GetRandHash();

    // (a) "Honest" spend with secret s.
    const lattice::PolyVec secret_a = DeriveForgedSecret(/*variant=*/0xA, real_commitment);
    BOOST_REQUIRE(lattice::IsValidPolyVec(secret_a));
    BOOST_REQUIRE(lattice::PolyVecInfNorm(secret_a) != 0);

    // (b) Forged spend with a DIFFERENT signer-chosen secret s'.
    const lattice::PolyVec secret_b = DeriveForgedSecret(/*variant=*/0xB, real_commitment);
    BOOST_REQUIRE(lattice::IsValidPolyVec(secret_b));
    BOOST_REQUIRE(lattice::PolyVecInfNorm(secret_b) != 0);

    // Secrets must actually differ (sanity for the forge premise).
    BOOST_REQUIRE_MESSAGE(PolyVecHash(secret_a) != PolyVecHash(secret_b),
        "DS-4c-1: forge premise — s and s' must differ");

    RingSignature sig_a;
    BOOST_REQUIRE_MESSAGE(
        CreateRingSignature(sig_a, ring_members, real_indices, {secret_a}, message_hash),
        "DS-4c-1: honest signature creation must succeed");

    // The forge: CreateRingSignature with s' builds, internally and exactly:
    //   key_image'                   = s' * DeriveLinkGenerator(real_commitment)
    //   member_public_key_offset'[r] = A*s' - DerivePublicKey(real_commitment,r)
    //   responses'                   via the same ring equations
    RingSignature sig_b;
    BOOST_REQUIRE_MESSAGE(
        CreateRingSignature(sig_b, ring_members, real_indices, {secret_b}, message_hash),
        "DS-4c-1: forged-key-image signature creation must succeed");

    // Both signatures verify under the SAME ring + message today.
    const bool verify_a = VerifyRingSignature(sig_a, ring_members, message_hash);
    const bool verify_b = VerifyRingSignature(sig_b, ring_members, message_hash);

    BOOST_REQUIRE_MESSAGE(verify_a, "DS-4c-1: honest signature must verify");

    // Distinct key images => distinct nullifiers (the double-spend evidence).
    BOOST_REQUIRE_EQUAL(sig_a.key_images.size(), 1u);
    BOOST_REQUIRE_EQUAL(sig_b.key_images.size(), 1u);
    const Nullifier nf_a = ComputeNullifierFromKeyImage(sig_a.key_images[0]);
    const Nullifier nf_b = ComputeNullifierFromKeyImage(sig_b.key_images[0]);
    BOOST_REQUIRE(!nf_a.IsNull());
    BOOST_REQUIRE(!nf_b.IsNull());
    BOOST_CHECK_MESSAGE(nf_a != nf_b,
        "DS-4c-1: forged secret must yield a DIFFERENT nullifier for the same note "
        "(if equal, the forge premise is broken).");

    // ----- LEGACY RESIDUAL (gated off post-sunset; closed by bound mode) -----
    // In the LEGACY ring signature the forged-key-image signature still verifies
    // (verify_b == true): the offset lets the signer set effective_pk = A*s' for
    // any s'. This residual is (a) rejected at/after the 125000 sunset by the
    // consensus gate (V2_SPEND_PATH_RECOVERY is non-exit -> bad-shielded-sunset-non-exit),
    // and (b) closed CRYPTOGRAPHICALLY by bound mode — see
    // ds4_bound_mode_rejects_keyimage_forge below, where the SAME forge is REJECTED.
    BOOST_CHECK_MESSAGE(verify_b,
        "DS-4c-1: legacy forged-key-image ring signature verifies (the documented "
        "pre-bound residual). Closure is asserted in ds4_bound_mode_rejects_keyimage_forge, "
        "where CreateBoundRingSignature with a forged secret over the same anchors FAILS.");
}

// ---------------------------------------------------------------------------
// DS-4c-2: Full MatRiCT-proof-level forge. Build a real one-note spend, then
//          splice in a forged ring signature over the same ring under s', with
//          the forged nullifier, and show VerifyMatRiCTProof still accepts it
//          today (the same input note now has two valid nullifiers).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ds4c_matrict_proof_double_spend)
{
    const size_t ring_size = lattice::RING_SIZE;
    const size_t real_index = 2;
    const CAmount fee = 50;

    // One real input note, one output note. Balanced: in=500, out=450, fee=50.
    std::vector<ShieldedNote> inputs{MakeNote(500)};
    std::vector<ShieldedNote> outputs{MakeNote(450)};
    std::vector<unsigned char> spending_key(32, 0x4D);

    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(ring_size));
    for (auto& m : ring_members[0]) m = GetRandHash();
    ring_members[0][real_index] = inputs[0].GetCommitment();
    const uint256 real_commitment = ring_members[0][real_index];
    const std::vector<size_t> real_indices{real_index};

    // Canonical nullifier for the honest spend.
    std::vector<Nullifier> nullifiers(1);
    BOOST_REQUIRE(DeriveInputNullifierForNote(nullifiers[0], spending_key, inputs[0], real_commitment));

    // (a) Build a fully-valid MatRiCT proof for the honest spend.
    MatRiCTProof proof_honest;
    BOOST_REQUIRE_MESSAGE(
        CreateMatRiCTProof(proof_honest, inputs, outputs, nullifiers,
                           ring_members, real_indices, spending_key, fee),
        "DS-4c-2: honest MatRiCT proof creation must succeed");

    std::vector<uint256> out_commitments;
    for (const auto& n : outputs) out_commitments.push_back(n.GetCommitment());

    BOOST_REQUIRE_MESSAGE(
        VerifyMatRiCTProof(proof_honest, ring_members, nullifiers, out_commitments, fee),
        "DS-4c-2: honest MatRiCT proof must verify");

    // (b) Forge: a different signer-chosen small secret s' for the SAME real
    //     commitment, producing a different key image -> different nullifier.
    const lattice::PolyVec forged_secret = DeriveForgedSecret(/*variant=*/0xF, real_commitment);
    BOOST_REQUIRE(lattice::IsValidPolyVec(forged_secret));
    BOOST_REQUIRE(lattice::PolyVecInfNorm(forged_secret) != 0);

    // The forged nullifier is determined by the forged key image; both must be
    // baked into the ring-signature message hash, exactly as VerifyMatRiCTProof
    // recomputes it (RingSignatureMessageHash over commitments/fee/nullifiers).
    // We first need the forged key image to know the forged nullifier, so we
    // mirror CreateRingSignature's key_image derivation by signing once and
    // reading it back (the signature is self-consistent for any message_hash).
    //
    // Step 1: probe-sign with a placeholder message to learn the forged key
    //         image / nullifier (key_image depends only on s' and the ring).
    const uint256 probe_msg = GetRandHash();
    RingSignature probe_sig;
    BOOST_REQUIRE(CreateRingSignature(probe_sig, ring_members, real_indices,
                                      {forged_secret}, probe_msg));
    BOOST_REQUIRE_EQUAL(probe_sig.key_images.size(), 1u);
    std::vector<Nullifier> forged_nullifiers(1);
    forged_nullifiers[0] = ComputeNullifierFromKeyImage(probe_sig.key_images[0]);
    BOOST_REQUIRE(!forged_nullifiers[0].IsNull());
    BOOST_REQUIRE_MESSAGE(forged_nullifiers[0] != nullifiers[0],
        "DS-4c-2: forged nullifier must differ from the canonical nullifier");

    // Step 2: recompute the real message hash that VerifyMatRiCTProof will use,
    //         binding the FORGED nullifier, then re-sign over it with s'.
    const uint256 forged_message_hash = RingSignatureMessageHash(
        proof_honest.input_commitments,
        proof_honest.output_commitments,
        fee,
        forged_nullifiers,
        /*tx_binding_hash=*/uint256{});

    RingSignature forged_sig;
    BOOST_REQUIRE_MESSAGE(
        CreateRingSignature(forged_sig, ring_members, real_indices,
                            {forged_secret}, forged_message_hash),
        "DS-4c-2: forged ring signature creation must succeed");
    // The key image is independent of message_hash, so the nullifier we bound
    // above is the one this signature carries.
    BOOST_REQUIRE_EQUAL(forged_sig.key_images.size(), 1u);
    BOOST_REQUIRE(ComputeNullifierFromKeyImage(forged_sig.key_images[0]) == forged_nullifiers[0]);

    // Step 3: splice the forged ring signature into a copy of the honest proof.
    //         All balance/range data and output commitments are unchanged and
    //         still valid; only the spend authorization (ring sig + nullifier)
    //         is swapped for the forged double-spend.
    MatRiCTProof proof_forged = proof_honest;
    proof_forged.ring_signature = forged_sig;
    // Re-seal the proof self-consistency challenge exactly as the prover does,
    // so the only thing standing between this forged proof and acceptance is
    // (the absence of) the DS-4b key-image binding — not the seal.
    proof_forged.challenge_seed =
        RecomputeProofChallenge(proof_forged, fee, /*tx_binding_hash=*/uint256{});

    const bool verify_forged =
        VerifyMatRiCTProof(proof_forged, ring_members, forged_nullifiers, out_commitments, fee);

    // ----- LEGACY RESIDUAL (gated off post-sunset; closed by bound mode) -----
    // The forged MatRiCT proof verifies on the LEGACY path (verify_forged == true)
    // for the same offset reason. Closure: (a) the 125000 sunset gate rejects the
    // recovery family outright, and (b) bound mode rejects the underlying ring forge
    // — asserted in ds4_bound_mode_rejects_keyimage_forge.
    BOOST_CHECK_MESSAGE(verify_forged,
        "DS-4c-2: legacy forged MatRiCT proof verifies (documented pre-bound residual). "
        "Cryptographic closure is asserted in ds4_bound_mode_rejects_keyimage_forge.");

    // Independent of the flip: the two spends carry distinct nullifiers, so a
    // nullifier-set double-spend guard cannot catch the second spend on its own.
    BOOST_CHECK_MESSAGE(forged_nullifiers[0] != nullifiers[0],
        "DS-4c-2: the double-spend uses a DIFFERENT nullifier, so it evades "
        "nullifier-uniqueness checks — the binding fix is the real defense.");
}

namespace {
lattice::PolyVec SmallSecret(const uint256& seed)
{
    FastRandomContext rng(seed);
    return lattice::SampleSmallVec(rng, lattice::MODULE_RANK, lattice::SECRET_SMALL_ETA);
}
} // anonymous namespace

// ---------------------------------------------------------------------------
// DS-4 CLOSURE: bound mode. Each ring member is an explicit lattice anchor
// T = A*s (consensus-fixed), offsets are forbidden, and the key image uses a
// single global generator (KI = G*s). The forge that succeeds on the legacy
// path (a second secret s' over the SAME note/anchors) is REJECTED here:
//   - CreateBoundRingSignature with s' over anchor_real = A*s cannot close the
//     proof (effective_pk is pinned to A*s, not A*s'), so it FAILS to build.
//   - the key image of any valid bound signature is uniquely G*s.
//   - splicing a forged key image or a non-zero offset onto a valid signature
//     is rejected by the verifier.
// This is the regression target that flips the DS-4 forge story to "closed".
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ds4_bound_mode_rejects_keyimage_forge)
{
    const size_t ring_size = lattice::RING_SIZE;
    const size_t real_index = 3;

    // Real note authorising secret s and its consensus anchor T = A*s.
    const lattice::PolyVec s = SmallSecret(GetRandHash());
    BOOST_REQUIRE(lattice::IsValidPolyVec(s) && lattice::PolyVecInfNorm(s) != 0);
    const lattice::PolyVec anchor_real = ComputeBoundAnchor(s);
    BOOST_REQUIRE(!anchor_real.empty());

    // Ring of anchors: decoys are A*(other small secrets); real index holds anchor_real.
    std::vector<std::vector<lattice::PolyVec>> ring_anchors(1, std::vector<lattice::PolyVec>(ring_size));
    for (size_t j = 0; j < ring_size; ++j) {
        ring_anchors[0][j] = (j == real_index) ? anchor_real : ComputeBoundAnchor(SmallSecret(GetRandHash()));
        BOOST_REQUIRE(!ring_anchors[0][j].empty());
    }

    const uint256 msg = GetRandHash();

    // Legitimate bound spend verifies; its key image is exactly G*s.
    RingSignature legit;
    BOOST_REQUIRE_MESSAGE(CreateBoundRingSignature(legit, ring_anchors, {real_index}, {s}, msg),
        "bound signing with the real secret must succeed");
    BOOST_CHECK(VerifyBoundRingSignature(legit, ring_anchors, msg));
    BOOST_CHECK_MESSAGE(legit.key_images[0] == ComputeBoundKeyImage(s),
        "DS-4 bound: the key image is the unique G*s for the note secret");

    // FORGE: a different small secret s' over the SAME anchors (same note) must NOT
    // produce a verifying signature — this is the legacy double-spend, now closed.
    lattice::PolyVec s_forge = SmallSecret(GetRandHash());
    BOOST_REQUIRE(PolyVecHash(s_forge) != PolyVecHash(s));
    RingSignature forged;
    const bool forged_built = CreateBoundRingSignature(forged, ring_anchors, {real_index}, {s_forge}, msg);
    BOOST_CHECK_MESSAGE(!forged_built,
        "DS-4 CLOSED: a forged secret over the fixed anchor cannot build a verifying bound signature");

    // Splice a forged key image G*s' onto the valid proof -> rejected (KI not the proof's secret).
    RingSignature ki_spliced = legit;
    ki_spliced.key_images[0] = ComputeBoundKeyImage(s_forge);
    BOOST_CHECK_MESSAGE(!VerifyBoundRingSignature(ki_spliced, ring_anchors, msg),
        "DS-4 CLOSED: a key image that is not G*s for the proven secret is rejected");

    // Re-introduce the legacy forge surface (a non-zero offset) -> rejected by the bound rule.
    RingSignature offset_forge = legit;
    offset_forge.member_public_key_offsets[0][real_index] = anchor_real; // any non-zero vector
    BOOST_CHECK_MESSAGE(!VerifyBoundRingSignature(offset_forge, ring_anchors, msg),
        "DS-4 CLOSED: bound mode admits no public-key offset (the forge surface is removed)");
}

// A second, independent bound spend of a DIFFERENT note yields a DIFFERENT, valid
// key image — confirming bound mode does not collapse distinct notes.
BOOST_AUTO_TEST_CASE(ds4_bound_mode_distinct_notes_distinct_keyimages)
{
    const size_t ring_size = lattice::RING_SIZE;
    const size_t real_index = 1;
    const uint256 msg = GetRandHash();

    auto sign_one = [&](const lattice::PolyVec& secret, lattice::PolyVec& out_ki) -> bool {
        const lattice::PolyVec anchor = ComputeBoundAnchor(secret);
        if (anchor.empty()) return false;
        std::vector<std::vector<lattice::PolyVec>> anchors(1, std::vector<lattice::PolyVec>(ring_size));
        for (size_t j = 0; j < ring_size; ++j) {
            anchors[0][j] = (j == real_index) ? anchor : ComputeBoundAnchor(SmallSecret(GetRandHash()));
            if (anchors[0][j].empty()) return false;
        }
        RingSignature sig;
        if (!CreateBoundRingSignature(sig, anchors, {real_index}, {secret}, msg)) return false;
        if (!VerifyBoundRingSignature(sig, anchors, msg)) return false;
        out_ki = sig.key_images[0];
        return true;
    };

    const lattice::PolyVec s1 = SmallSecret(GetRandHash());
    const lattice::PolyVec s2 = SmallSecret(GetRandHash());
    BOOST_REQUIRE(PolyVecHash(s1) != PolyVecHash(s2));
    lattice::PolyVec ki1, ki2;
    BOOST_REQUIRE(sign_one(s1, ki1));
    BOOST_REQUIRE(sign_one(s2, ki2));
    BOOST_CHECK(PolyVecHash(ki1) != PolyVecHash(ki2));
}

BOOST_AUTO_TEST_SUITE_END()
