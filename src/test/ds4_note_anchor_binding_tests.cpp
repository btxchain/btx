// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// DS-4 ANCHOR-BINDING REGRESSION — bind the bound-mode spend anchor T = A*s into
// the note commitment so the ring-member anchor a spender presents is consensus-
// fixed by the note.
//
// Bound mode (ds4_keyimage_forge_tests.cpp::ds4_bound_mode_rejects_keyimage_forge)
// closes the key-image forge by representing each ring member as an explicit
// anchor T = A*s, forbidding offsets, and deriving the key image from a single
// global generator (KI = G*s). The residual gap it leaves open is that NOTHING in
// the note pins WHICH anchor the spender presents — an attacker could swap in a
// different anchor T' = A*s' it controls. This file's subject closes that gap: a
// non-empty spend_anchor promotes the note to the v2 commitment
//
//     cm = SHA256("BTX_Note_Commit_V2" || inner || rho || rcm || SHA256(spend_anchor))
//
// so the anchor is now bound into (and tamper-evident through) the commitment,
// while legacy (empty spend_anchor) notes keep the byte-identical v1 commitment.
//
// References:
//   - src/shielded/note.cpp (GetCommitment v1/v2 split; Set/GetNoteSpendAnchor)
//   - src/shielded/ringct/ring_signature.cpp (ComputeBoundAnchor / ComputeBoundKeyImage /
//     CreateBoundRingSignature / VerifyBoundRingSignature)

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <random.h>
#include <shielded/lattice/params.h>
#include <shielded/lattice/polyvec.h>
#include <shielded/lattice/sampling.h>
#include <shielded/lattice/poly.h>
#include <shielded/note.h>
#include <shielded/ringct/commitment.h>
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

lattice::PolyVec SmallSecret(const uint256& seed)
{
    FastRandomContext rng(seed);
    return lattice::SampleSmallVec(rng, lattice::MODULE_RANK, lattice::SECRET_SMALL_ETA);
}

// Modular arithmetic over the prime field Z_q (free functions: no lambda captures => no
// -Wunused-lambda-capture on any compiler). Used by the matrix-invertibility test below.
int64_t ModQ(int64_t x, int64_t q) { x %= q; if (x < 0) x += q; return x; }
int64_t ModPow(int64_t b, int64_t e, int64_t q)
{
    int64_t r = 1 % q; b = ModQ(b, q);
    while (e > 0) { if (e & 1) r = r * b % q; b = b * b % q; e >>= 1; }
    return r;
}
int64_t ModInv(int64_t a, int64_t q) { return ModPow(a, q - 2, q); } // q prime => Fermat inverse

uint256 PolyVecHash(const lattice::PolyVec& vec)
{
    HashWriter hw;
    hw << vec;
    return hw.GetSHA256();
}

// Independent re-implementation of the legacy v1 commitment formula, used to prove
// the v1 path is byte-identical. Keep in lockstep with ShieldedNote::GetCommitment's
// empty-spend_anchor branch in src/shielded/note.cpp.
uint256 RecomputeV1Commitment(const ShieldedNote& n)
{
    unsigned char value_le[8];
    WriteLE64(value_le, static_cast<uint64_t>(n.value));

    uint256 inner;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>("BTX_Note_Inner_V1"), sizeof("BTX_Note_Inner_V1") - 1)
        .Write(value_le, sizeof(value_le))
        .Write(n.recipient_pk_hash.begin(), uint256::size())
        .Finalize(inner.begin());

    uint256 cm;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>("BTX_Note_Commit_V1"), sizeof("BTX_Note_Commit_V1") - 1)
        .Write(inner.begin(), uint256::size())
        .Write(n.rho.begin(), uint256::size())
        .Write(n.rcm.begin(), uint256::size())
        .Finalize(cm.begin());
    return cm;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(ds4_note_anchor_binding_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// (a) A note with an empty spend_anchor produces the SAME (v1) commitment as
//     before, and round-trips through serialization byte-identically.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(note_v1_commitment_unchanged)
{
    const ShieldedNote n = MakeNote(1234);
    BOOST_REQUIRE(n.spend_anchor.empty());

    // The implemented commitment must equal the independently recomputed v1 formula.
    BOOST_CHECK_MESSAGE(n.GetCommitment() == RecomputeV1Commitment(n),
        "v1 (empty spend_anchor) commitment must be byte-identical to the legacy formula");

    // Serialization round-trip: bytes and decoded fields must be unchanged, and the
    // legacy note must carry no trailing spend_anchor on the wire.
    DataStream ss;
    ss << n;
    const std::vector<unsigned char> wire(MakeUCharSpan(ss).begin(), MakeUCharSpan(ss).end());

    ShieldedNote decoded;
    ss >> decoded;
    BOOST_CHECK(ss.empty());
    BOOST_CHECK(decoded.spend_anchor.empty());
    BOOST_CHECK_EQUAL(decoded.value, n.value);
    BOOST_CHECK(decoded.recipient_pk_hash == n.recipient_pk_hash);
    BOOST_CHECK(decoded.rho == n.rho);
    BOOST_CHECK(decoded.rcm == n.rcm);
    BOOST_CHECK(decoded.memo == n.memo);
    BOOST_CHECK(decoded.GetCommitment() == n.GetCommitment());

    // Re-encoding the decoded note must reproduce the identical wire bytes.
    DataStream ss2;
    ss2 << decoded;
    const std::vector<unsigned char> wire2(MakeUCharSpan(ss2).begin(), MakeUCharSpan(ss2).end());
    BOOST_CHECK(wire == wire2);
}

// ---------------------------------------------------------------------------
// (b) A v2 note binds the anchor into the commitment: GetNoteSpendAnchor returns
//     T, the v2 commitment differs from the same note's v1 commitment, and any
//     mutation of T changes the commitment (tamper-evidence).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(note_v2_binds_anchor_in_commitment)
{
    const lattice::PolyVec s = SmallSecret(GetRandHash());
    BOOST_REQUIRE(lattice::IsValidPolyVec(s) && lattice::PolyVecInfNorm(s) != 0);
    const lattice::PolyVec T = ComputeBoundAnchor(s);
    BOOST_REQUIRE(!T.empty());

    ShieldedNote n = MakeNote(7777);
    MarkShieldedNoteForModernDerivation(n); // so the anchor round-trips on the wire

    // v1 commitment of the same note (anchor not yet set).
    const uint256 cm_v1 = n.GetCommitment();
    BOOST_REQUIRE(n.spend_anchor.empty());

    // Bind the anchor.
    SetNoteSpendAnchor(n, T);
    BOOST_REQUIRE(!n.spend_anchor.empty());

    lattice::PolyVec recovered;
    BOOST_REQUIRE_MESSAGE(GetNoteSpendAnchor(n, recovered),
        "GetNoteSpendAnchor must recover the committed anchor");
    BOOST_CHECK_MESSAGE(PolyVecHash(recovered) == PolyVecHash(T),
        "recovered anchor must equal T = A*s");

    // v2 commitment must differ from the v1 commitment of the same note.
    const uint256 cm_v2 = n.GetCommitment();
    BOOST_CHECK_MESSAGE(cm_v2 != cm_v1,
        "binding an anchor must change the commitment (v2 != v1)");

    // Tamper-evidence: mutate T and re-bind => commitment changes.
    lattice::PolyVec T_tampered = T;
    T_tampered[0].coeffs[0] = (T_tampered[0].coeffs[0] + 1) % lattice::POLY_Q;
    BOOST_REQUIRE(PolyVecHash(T_tampered) != PolyVecHash(T));
    ShieldedNote n_tampered = n;
    SetNoteSpendAnchor(n_tampered, T_tampered);
    BOOST_CHECK_MESSAGE(n_tampered.GetCommitment() != cm_v2,
        "mutating the bound anchor must change the commitment (tamper-evident)");

    // The v2 note round-trips through serialization (marker present => anchor on wire).
    DataStream ss;
    ss << n;
    ShieldedNote decoded;
    ss >> decoded;
    BOOST_CHECK(ss.empty());
    BOOST_CHECK(decoded.spend_anchor == n.spend_anchor);
    BOOST_CHECK(decoded.GetCommitment() == cm_v2);
    lattice::PolyVec decoded_anchor;
    BOOST_REQUIRE(GetNoteSpendAnchor(decoded, decoded_anchor));
    BOOST_CHECK(PolyVecHash(decoded_anchor) == PolyVecHash(T));
}

// ---------------------------------------------------------------------------
// (c) End-to-end: build a ring of notes each carrying an anchor, extract the
//     anchors from the committed notes, and sign/verify in bound mode. A forge
//     with a different secret s' over the SAME committed anchors cannot build a
//     verifying signature, and splicing G*s' onto the valid signature is rejected.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(end_to_end_bound_spend_from_committed_notes)
{
    const size_t ring_size = lattice::RING_SIZE;
    const size_t real_index = 2;
    const uint256 msg = GetRandHash();

    // Real note: anchor = A*s for known s.
    const lattice::PolyVec s = SmallSecret(GetRandHash());
    BOOST_REQUIRE(lattice::IsValidPolyVec(s) && lattice::PolyVecInfNorm(s) != 0);
    const lattice::PolyVec anchor_real = ComputeBoundAnchor(s);
    BOOST_REQUIRE(!anchor_real.empty());

    // Build a ring of notes; the real note commits anchor_real, decoys commit A*(other secrets).
    std::vector<ShieldedNote> ring_notes(ring_size);
    for (size_t j = 0; j < ring_size; ++j) {
        ring_notes[j] = MakeNote(static_cast<CAmount>(100 + j));
        MarkShieldedNoteForModernDerivation(ring_notes[j]);
        const lattice::PolyVec anchor =
            (j == real_index) ? anchor_real : ComputeBoundAnchor(SmallSecret(GetRandHash()));
        BOOST_REQUIRE(!anchor.empty());
        SetNoteSpendAnchor(ring_notes[j], anchor);
    }

    // Extract the anchors back out of the COMMITTED notes (this is what consensus would do).
    std::vector<std::vector<lattice::PolyVec>> ring_anchors(1, std::vector<lattice::PolyVec>(ring_size));
    for (size_t j = 0; j < ring_size; ++j) {
        BOOST_REQUIRE_MESSAGE(GetNoteSpendAnchor(ring_notes[j], ring_anchors[0][j]),
            "each committed note must expose its bound anchor");
    }
    // Sanity: the extracted real anchor is the one for s.
    BOOST_REQUIRE(PolyVecHash(ring_anchors[0][real_index]) == PolyVecHash(anchor_real));

    // Legitimate bound spend over the committed anchors verifies; key image is G*s.
    RingSignature legit;
    BOOST_REQUIRE_MESSAGE(
        CreateBoundRingSignature(legit, ring_anchors, {real_index}, {s}, msg),
        "bound signing with the real secret over committed anchors must succeed");
    BOOST_CHECK(VerifyBoundRingSignature(legit, ring_anchors, msg));
    BOOST_REQUIRE_EQUAL(legit.key_images.size(), 1u);
    BOOST_CHECK_MESSAGE(legit.key_images[0] == ComputeBoundKeyImage(s),
        "the bound key image is the unique G*s for the note secret");

    // FORGE: a different small secret s' over the SAME committed anchors (anchor swap
    // is not possible because the anchor is fixed by the commitment) cannot build a
    // verifying bound signature — effective_pk is pinned to A*s != A*s'.
    const lattice::PolyVec s_forge = SmallSecret(GetRandHash());
    BOOST_REQUIRE(PolyVecHash(s_forge) != PolyVecHash(s));
    RingSignature forged;
    const bool forged_built =
        CreateBoundRingSignature(forged, ring_anchors, {real_index}, {s_forge}, msg);
    BOOST_CHECK_MESSAGE(!forged_built,
        "DS-4 CLOSED: a forged secret over the committed anchor cannot build a verifying signature");

    // Splice a forged key image G*s' onto the valid signature => rejected.
    RingSignature ki_spliced = legit;
    ki_spliced.key_images[0] = ComputeBoundKeyImage(s_forge);
    BOOST_CHECK_MESSAGE(!VerifyBoundRingSignature(ki_spliced, ring_anchors, msg),
        "DS-4 CLOSED: a key image that is not G*s for the proven secret is rejected");
}

// ---------------------------------------------------------------------------
// DS-4 soundness residual #2 (concrete security): resolve whether the bound-mode
// binding rests on a computational assumption or is information-theoretic.
//
// The anchor is T = A*s with A = CommitmentMatrix() (a fixed NUMS 4x4 over R_q).
// R_q = Z_q[X]/(X^256+1) splits FULLY under the NTT (Poly256::PointwiseMul is
// coeff-wise, q = 8380417 is the Dilithium prime), so A is invertible over R_q
// IFF each of the 256 NTT-slot 4x4 matrices over the field Z_q is invertible.
// If A is invertible, A*s = T has a UNIQUE solution s in R_q, so a note's anchor
// pins exactly one s and hence exactly one key image KI = G*s — the one-note-one-
// nullifier binding holds INFORMATION-THEORETICALLY, with no M-SIS assumption and
// regardless of the relaxed-witness norm. (The square A is therefore a feature for
// the binding, not the M-SIS-reduction defect it first appears to be.) This test
// settles it by checking full-rank in every slot via Gaussian elimination over Z_q.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(commitment_matrix_invertible_over_Rq_information_theoretic_binding)
{
    BOOST_REQUIRE_EQUAL(lattice::MODULE_RANK, 4u);
    const int64_t q = lattice::POLY_Q;

    // NTT every entry of A.
    lattice::PolyMat A = CommitmentMatrix();
    for (auto& row : A) for (auto& e : row) e.NTT();

    size_t singular_slots = 0;
    for (size_t slot = 0; slot < lattice::POLY_N; ++slot) {
        // Build the 4x4 Z_q matrix for this NTT slot (Montgomery scaling is a unit, irrelevant to rank).
        int64_t m[4][4];
        for (size_t r = 0; r < 4; ++r)
            for (size_t c = 0; c < 4; ++c) m[r][c] = ModQ(A[r][c].coeffs[slot], q);

        // Gaussian elimination over the field Z_q; count pivots.
        int pivots = 0;
        for (int col = 0, prow = 0; col < 4 && prow < 4; ++col) {
            int sel = -1;
            for (int r = prow; r < 4; ++r) { if (m[r][col] != 0) { sel = r; break; } }
            if (sel < 0) continue;
            for (int c = 0; c < 4; ++c) std::swap(m[prow][c], m[sel][c]);
            const int64_t inv = ModInv(m[prow][col], q);
            for (int r = 0; r < 4; ++r) {
                if (r == prow || m[r][col] == 0) continue;
                const int64_t f = m[r][col] * inv % q;
                for (int c = 0; c < 4; ++c) m[r][c] = ModQ(m[r][c] - f * m[prow][c] % q, q);
            }
            ++pivots; ++prow;
        }
        if (pivots < 4) ++singular_slots;
    }
    BOOST_CHECK_MESSAGE(singular_slots == 0,
        "CommitmentMatrix A must be invertible in all 256 NTT slots for information-theoretic "
        "anchor binding; singular slots = " << singular_slots);
}

BOOST_AUTO_TEST_SUITE_END()
