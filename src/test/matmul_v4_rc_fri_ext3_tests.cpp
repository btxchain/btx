// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_fri_ext3.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_fri_ext3_tests, BasicTestingSetup)

namespace {

uint256 MakeSeed(uint8_t fill)
{
    uint256 seed;
    for (int i = 0; i < 32; ++i) seed.data()[i] = fill;
    return seed;
}

std::vector<rc::Fp3> MakeCoeffs(size_t n)
{
    std::vector<rc::Fp3> c(n);
    for (size_t i = 0; i < n; ++i) c[i] = gf::FromSigned3(static_cast<int64_t>(i * 3 + 1));
    return c;
}

} // namespace

BOOST_AUTO_TEST_CASE(fri3_constants_and_soundness_bits)
{
    // Fp3 substrate: query proximity term is FIELD-INDEPENDENT — k=40 grinding,
    // blowup=16, Q=128 unique-decoding gives floor(128·log2(32/17)) − 40 = 76
    // (real 76.80). The Fp3 lift moves the FS union terms to ~2^-192 scale so
    // the composed bound is query-dominated, not FS-capped.
    BOOST_CHECK_EQUAL(rc::kRCFriBlowup, 16u);
    BOOST_CHECK_EQUAL(rc::kRCFriNumQueries, 128u);
    BOOST_CHECK_EQUAL(rc::kRCFriGrindingBits, 40u);
    BOOST_CHECK_EQUAL(rc::kRCFri3ProofVersion, 5u);
    BOOST_CHECK_EQUAL(rc::kRCFri3BatchProofVersion, 5u);
    BOOST_CHECK(!rc::kRCFriConjecturedBoundEnabled);
    BOOST_CHECK(rc::Fri3ClaimedBitsMeetTarget());
    BOOST_CHECK_EQUAL(rc::Fri3SoundnessBoundBits(), 76); // floor(128*log2(32/17))-40
    BOOST_CHECK_GE(rc::Fri3SoundnessBoundBits(), rc::kRCFriTargetSoundnessBits);
    BOOST_CHECK(std::string(rc::kRCFri3SoundnessStatement).find("Q=128") != std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3SoundnessStatement).find("blowup=16") != std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3SoundnessStatement).find("UNIQUE-DECODING") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3SoundnessStatement).find("DEEP/OOD") != std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3SoundnessStatement).find("NOT conjectured") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3SoundnessStatement).find("half-domain") != std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3SoundnessStatement).find("B-constant") != std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3SoundnessStatement).find("(c1,c2)!=(0,0)") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3SoundnessStatement).find("Haböck") != std::string::npos);
    // Fp3 substrate marker: |F| = p^3 ≈ 2^192.
    BOOST_CHECK(std::string(rc::kRCFri3SoundnessStatement).find("2^192") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(fri3_honest_commit_verify)
{
    const auto coeffs = MakeCoeffs(16);
    const uint256 seed = MakeSeed(0x42);
    const auto c = rc::Fri3CommitAndFold(coeffs, seed, /*pow_grind_nonce=*/7);
    BOOST_REQUIRE(c.ok);
    BOOST_CHECK_EQUAL(c.proof.queries.size(), rc::kRCFriNumQueries);
    BOOST_CHECK_EQUAL(c.proof.pow_grind_nonce, 7u);
    BOOST_CHECK_EQUAL(c.lde_evals.size(), 16u * rc::kRCFriBlowup);
    BOOST_CHECK(c.proof.layers.size() >= 2);
    std::string why;
    BOOST_CHECK_MESSAGE(rc::Fri3Verify(c.proof, seed, &why), why);

    // Byte-exact serialize/deserialize round trip.
    std::vector<unsigned char> bytes;
    BOOST_CHECK(rc::SerializeFri3Proof(c.proof, bytes) > 0);
    const auto back = rc::DeserializeFri3Proof(bytes);
    BOOST_REQUIRE(back.has_value());
    std::vector<unsigned char> bytes2;
    BOOST_REQUIRE(rc::SerializeFri3Proof(*back, bytes2) > 0);
    BOOST_CHECK(bytes == bytes2);
    BOOST_CHECK(rc::Fri3Verify(*back, seed, &why));
}

BOOST_AUTO_TEST_CASE(fri3_wrong_leaf_rejected)
{
    const auto c = rc::Fri3CommitAndFold(MakeCoeffs(8), MakeSeed(0x11));
    BOOST_REQUIRE(c.ok);
    auto bad = c.proof;
    bad.queries[0].steps[0].even.c0 ^= 1;
    std::string why;
    BOOST_CHECK(!rc::Fri3Verify(bad, MakeSeed(0x11), &why));
}

BOOST_AUTO_TEST_CASE(fri3_wrong_sibling_rejected)
{
    const auto c = rc::Fri3CommitAndFold(MakeCoeffs(8), MakeSeed(0x22));
    BOOST_REQUIRE(c.ok);
    BOOST_REQUIRE(!c.proof.queries[0].steps[0].even_siblings.empty());
    auto bad = c.proof;
    bad.queries[0].steps[0].even_siblings[0].data()[0] ^= 0xff;
    std::string why;
    BOOST_CHECK(!rc::Fri3Verify(bad, MakeSeed(0x22), &why));
}

BOOST_AUTO_TEST_CASE(fri3_wrong_fold_challenge_rejected)
{
    const auto c = rc::Fri3CommitAndFold(MakeCoeffs(8), MakeSeed(0x33));
    BOOST_REQUIRE(c.ok);
    BOOST_REQUIRE(!c.proof.fold_challenges.empty());
    auto bad = c.proof;
    bad.fold_challenges[0].c0 ^= 1;
    std::string why;
    BOOST_CHECK(!rc::Fri3Verify(bad, MakeSeed(0x33), &why));
}

BOOST_AUTO_TEST_CASE(fri3_truncated_openings_rejected)
{
    const auto c = rc::Fri3CommitAndFold(MakeCoeffs(8), MakeSeed(0x44));
    BOOST_REQUIRE(c.ok);
    auto bad = c.proof;
    BOOST_REQUIRE(!bad.queries[0].steps.empty());
    bad.queries[0].steps.pop_back();
    std::string why;
    BOOST_CHECK(!rc::Fri3Verify(bad, MakeSeed(0x44), &why));

    auto bad2 = c.proof;
    bad2.queries.pop_back();
    BOOST_CHECK(!rc::Fri3Verify(bad2, MakeSeed(0x44), &why));
}

BOOST_AUTO_TEST_CASE(fri3_query_count_matches_constant)
{
    const auto c = rc::Fri3CommitAndFold(MakeCoeffs(4), MakeSeed(0x55));
    BOOST_REQUIRE(c.ok);
    BOOST_CHECK_EQUAL(c.proof.queries.size(), rc::kRCFriNumQueries);
}

BOOST_AUTO_TEST_CASE(fri3_proof_much_smaller_than_lde_for_large_n)
{
    // With DEEP (nested quot FRI) openings grow; still ≪ shipping full LDE at large N.
    const size_t n = 65536;
    const auto c = rc::Fri3CommitAndFold(MakeCoeffs(n), MakeSeed(0x66));
    BOOST_REQUIRE(c.ok);
    BOOST_REQUIRE(c.proof.has_deep);
    const size_t lde_bytes = c.lde_evals.size() * sizeof(rc::Fp3);
    BOOST_CHECK_LT(c.proof_bytes, lde_bytes);
    BOOST_CHECK_EQUAL(c.proof.queries.size(), rc::kRCFriNumQueries);
}

BOOST_AUTO_TEST_CASE(fri3_deep_ood_tamper_rejects)
{
    const auto c = rc::Fri3CommitAndFold(MakeCoeffs(16), MakeSeed(0x71));
    BOOST_REQUIRE(c.ok);
    BOOST_REQUIRE(c.proof.has_deep);
    auto bad = c.proof;
    bad.deep_eval.c0 ^= 1;
    std::string why;
    BOOST_CHECK(!rc::Fri3Verify(bad, MakeSeed(0x71), &why));
}

BOOST_AUTO_TEST_CASE(fri3_deep_ood_ext_coeff_nonzero)
{
    // OOD z must have a nonzero Fp3 extension part ((c1, c2) != (0, 0)).
    const auto c = rc::Fri3CommitAndFold(MakeCoeffs(16), MakeSeed(0x72));
    BOOST_REQUIRE(c.ok);
    BOOST_REQUIRE(c.proof.has_deep);
    BOOST_REQUIRE(!c.proof.deep_z_forced);
    BOOST_CHECK(gf::Canonical(c.proof.deep_z.c1) != 0 || gf::Canonical(c.proof.deep_z.c2) != 0);
    // Forged base-field deep_z (extension part zeroed) must be rejected by FS replay.
    auto bad = c.proof;
    bad.deep_z.c1 = 0;
    bad.deep_z.c2 = 0;
    std::string why;
    BOOST_CHECK(!rc::Fri3Verify(bad, MakeSeed(0x72), &why));
}

BOOST_AUTO_TEST_CASE(fri3_deep_quot_root_must_match_nested_layer0)
{
    const auto c = rc::Fri3CommitAndFold(MakeCoeffs(16), MakeSeed(0x73));
    BOOST_REQUIRE(c.ok);
    BOOST_REQUIRE(c.proof.has_deep);
    BOOST_REQUIRE(c.proof.deep_quot_fri);
    BOOST_REQUIRE(!c.proof.deep_quot_fri->layers.empty());
    BOOST_CHECK(c.proof.deep_quot_root == c.proof.deep_quot_fri->layers[0].root);
    BOOST_CHECK_EQUAL(c.proof.deep_quot_n_leaves, c.proof.deep_quot_fri->layers[0].n_leaves);

    // Tamper deep_quot_root independently of nested FRI → REJECT (not absorb-only).
    auto bad = c.proof;
    bad.deep_quot_root.data()[0] ^= 0xff;
    std::string why;
    BOOST_CHECK(!rc::Fri3Verify(bad, MakeSeed(0x73), &why));
    BOOST_CHECK(why.find("deep_quot_root") != std::string::npos ||
                why.find("nested") != std::string::npos || !why.empty());

    auto bad2 = c.proof;
    bad2.deep_quot_n_leaves ^= 1u;
    BOOST_CHECK(!rc::Fri3Verify(bad2, MakeSeed(0x73), &why));
}

BOOST_AUTO_TEST_CASE(fri3_deep_habock_z1_merkle_opening)
{
    // Forced z=1 is IN-domain → layer-0 Merkle opening of P(1), no quotient FRI.
    const auto coeffs = MakeCoeffs(16);
    const uint256 seed = MakeSeed(0x74);
    const auto c = rc::Fri3CommitAndFoldDeepAt(coeffs, seed, gf::Fp3::One());
    BOOST_REQUIRE_MESSAGE(c.ok, c.note);
    BOOST_REQUIRE(c.proof.has_deep);
    BOOST_REQUIRE(c.proof.deep_z_forced);
    BOOST_CHECK(gf::Eq(c.proof.deep_z, gf::Fp3::One()));
    BOOST_CHECK(!c.proof.deep_quot_fri);
    BOOST_CHECK_EQUAL(c.proof.deep_quot_n_leaves, 0u);
    BOOST_CHECK_EQUAL(c.proof.deep_domain_index, 0u);
    BOOST_CHECK(!c.proof.deep_domain_siblings.empty());
    // P(1) = sum of coeffs.
    rc::Fp3 sum = gf::Fp3::Zero();
    for (const auto& a : coeffs) sum = gf::Add(sum, a);
    BOOST_CHECK(gf::Eq(c.proof.deep_eval, sum));
    std::string why;
    BOOST_CHECK_MESSAGE(rc::Fri3Verify(c.proof, seed, &why), why);

    // Round-trip serialization (empty nested quot).
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE(rc::SerializeFri3Proof(c.proof, bytes) > 0);
    const auto back = rc::DeserializeFri3Proof(bytes);
    BOOST_REQUIRE(back.has_value());
    BOOST_CHECK(!back->deep_quot_fri);
    BOOST_CHECK_MESSAGE(rc::Fri3Verify(*back, seed, &why), why);

    // Tamper Haböck opening → REJECT.
    auto bad = c.proof;
    bad.deep_eval.c0 ^= 1;
    BOOST_CHECK(!rc::Fri3Verify(bad, seed, &why));
    auto bad2 = c.proof;
    BOOST_REQUIRE(!bad2.deep_domain_siblings.empty());
    bad2.deep_domain_siblings[0].data()[0] ^= 0xff;
    BOOST_CHECK(!rc::Fri3Verify(bad2, seed, &why));
}

BOOST_AUTO_TEST_CASE(fri3_forge_flipped_eval_rejected)
{
    const uint256 seed = MakeSeed(0x77);
    const auto c = rc::Fri3CommitAndFold(MakeCoeffs(16), seed);
    BOOST_REQUIRE(c.ok);
    std::string why;
    BOOST_CHECK_MESSAGE(rc::Fri3ForgeFlippedEvalMustFail(c, seed, /*flip_index=*/3, &why), why);
}

BOOST_AUTO_TEST_CASE(fri3_bad_seed_rejected)
{
    const auto c = rc::Fri3CommitAndFold(MakeCoeffs(8), MakeSeed(0x88));
    BOOST_REQUIRE(c.ok);
    std::string why;
    BOOST_CHECK(!rc::Fri3Verify(c.proof, MakeSeed(0x99), &why));
}

BOOST_AUTO_TEST_CASE(fri3_v5_linear_fold_produces_expected_constant)
{
    // f(X) = a + b·X → one half-domain fold yields the constant a + β·b —
    // the even/odd fold matches the polynomial decomposition
    // f_even(X²) = a, f_odd(X²) = b, f_even + β·f_odd = a + β·b.
    const rc::Fp3 a = gf::FromSigned3(3);
    const rc::Fp3 b = gf::FromSigned3(5);
    std::vector<rc::Fp3> coeffs = {a, b};
    const uint256 seed = MakeSeed(0xA1);
    const auto c = rc::Fri3CommitAndFold(coeffs, seed, /*pow_grind_nonce=*/0, /*enable_deep=*/false);
    BOOST_REQUIRE_MESSAGE(c.ok, c.note);
    BOOST_CHECK_EQUAL(c.proof.n_coeffs, 2u);
    BOOST_CHECK_EQUAL(c.proof.fold_challenges.size(), 1u); // log2(2)
    BOOST_CHECK_EQUAL(c.proof.layers.size(), 2u);
    BOOST_CHECK_EQUAL(c.proof.layers.back().n_leaves, rc::kRCFriBlowup);
    BOOST_REQUIRE(!c.proof.fold_challenges.empty());
    const rc::Fp3 beta = c.proof.fold_challenges[0];
    const rc::Fp3 expect = gf::Add(a, gf::Mul(beta, b));
    BOOST_CHECK(gf::Eq(c.proof.final_value, expect));
    // Terminal layer evaluations are B copies of the constant.
    BOOST_REQUIRE_EQUAL(c.layer_evals.back().size(), rc::kRCFriBlowup);
    for (const auto& v : c.layer_evals.back()) {
        BOOST_CHECK(gf::Eq(v, expect));
    }
    std::string why;
    BOOST_CHECK_MESSAGE(rc::Fri3Verify(c.proof, seed, &why), why);
}

BOOST_AUTO_TEST_CASE(fri3_v5_inconsistent_fold_rejected)
{
    // Honest low-degree proof; flip a fold opening so the algebraic fold path
    // no longer matches the committed next-layer / terminal constant.
    const auto c = rc::Fri3CommitAndFold(MakeCoeffs(8), MakeSeed(0xA2));
    BOOST_REQUIRE(c.ok);
    BOOST_REQUIRE(!c.proof.queries.empty());
    BOOST_REQUIRE(!c.proof.queries[0].steps.empty());
    auto bad = c.proof;
    bad.queries[0].steps[0].odd.c0 ^= 1; // breaks Merkle OR fold algebra
    std::string why;
    BOOST_CHECK(!rc::Fri3Verify(bad, MakeSeed(0xA2), &why));

    // Terminal constant bound: forged final_value with matching forged root of
    // B identical leaves still fails fold-path consistency into that constant.
    auto bad2 = c.proof;
    bad2.final_value.c0 ^= 1;
    BOOST_CHECK(!rc::Fri3Verify(bad2, MakeSeed(0xA2), &why));
}

BOOST_AUTO_TEST_CASE(fri3_v5_non_constant_terminal_root_rejected)
{
    // After honest prove, replace terminal root with a non-constant-layer root
    // while keeping final_value — verifier reconstructs B-constant Merkle and rejects.
    const auto c = rc::Fri3CommitAndFold(MakeCoeffs(4), MakeSeed(0xA3), 0, /*enable_deep=*/false);
    BOOST_REQUIRE(c.ok);
    auto bad = c.proof;
    bad.layers.back().root.data()[0] ^= 0xff;
    std::string why;
    BOOST_CHECK(!rc::Fri3Verify(bad, MakeSeed(0xA3), &why));

    // Terminal codeword binds low degree: a SINGLETON terminal (n_leaves = 1)
    // does not bind and MUST be rejected — the verifier demands the terminal
    // layer be exactly blowup-sized (B = 16 identical constant leaves).
    auto bad2 = c.proof;
    bad2.layers.back().n_leaves = 1;
    BOOST_CHECK(!rc::Fri3Verify(bad2, MakeSeed(0xA3), &why));
    BOOST_CHECK(why.find("blowup") != std::string::npos || why.find("layer") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(fri3_v5_fold_depth_and_terminal_blowup)
{
    const auto c = rc::Fri3CommitAndFold(MakeCoeffs(16), MakeSeed(0xA4));
    BOOST_REQUIRE(c.ok);
    BOOST_CHECK_EQUAL(c.proof.fold_challenges.size(), 4u); // log2(16)
    BOOST_CHECK_EQUAL(c.proof.layers.size(), 5u);
    BOOST_CHECK_EQUAL(c.proof.layers.back().n_leaves, rc::kRCFriBlowup);
    BOOST_CHECK_EQUAL(c.proof.layers[0].n_leaves, 16u * rc::kRCFriBlowup);
    // Nested quotient FRI also uses v5 fold depth.
    BOOST_REQUIRE(c.proof.has_deep);
    BOOST_REQUIRE(c.proof.deep_quot_fri);
    BOOST_CHECK_EQUAL(c.proof.deep_quot_fri->fold_challenges.size(), 4u);
    BOOST_CHECK_EQUAL(c.proof.deep_quot_fri->layers.back().n_leaves, rc::kRCFriBlowup);
}

// ============================================================================
// Batched FRI over Fp3: single instance + dual-OOD DEEP.
// ============================================================================

namespace {

std::vector<std::vector<rc::Fp3>> MakeBatchColumns()
{
    // Mixed lengths incl. non-pow2 (5) and a singleton — exercises the
    // degree-shift (maximal-degree enforcement) path.
    std::vector<std::vector<rc::Fp3>> cols;
    cols.push_back(MakeCoeffs(16));
    std::vector<rc::Fp3> c2(5);
    for (size_t i = 0; i < c2.size(); ++i) c2[i] = gf::FromSigned3(-static_cast<int64_t>(i) - 9);
    cols.push_back(std::move(c2));
    cols.push_back(MakeCoeffs(32));
    cols.push_back({gf::FromSigned3(424242)});
    return cols;
}

} // namespace

BOOST_AUTO_TEST_CASE(frib3_constants_and_soundness_bits)
{
    // Query term (field-independent): Q=128 → floor(128·log2(32/17)) − 40 = 76
    // (real 76.80). The Fp3 substrate is what makes the composed bound
    // query-dominated: FS terms are ~2^-192 scale pre-grind (RLC ≈ 2^-180,
    // dual-OOD ≈ 2^-326), i.e. ≥ 63 bits under the query floor post-grind.
    BOOST_CHECK_EQUAL(rc::kRCFriBatchNumQueries, 128u);
    BOOST_CHECK_EQUAL(rc::Fri3BatchSoundnessBoundBits(), 76);
    BOOST_CHECK_GE(rc::Fri3BatchSoundnessBoundBits(), rc::kRCFriTargetSoundnessBits);
    BOOST_CHECK(rc::Fri3BatchClaimedBitsMeetTarget());
    // κ: 2-adicity wall — blowup·κ = 2^32 = max power-of-two subgroup of Fp^×.
    BOOST_CHECK_EQUAL(rc::kRCFriMaxColumnLog2, 28u);
    BOOST_CHECK(std::string(rc::kRCFri3BatchSoundnessStatement).find("Q=128") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3BatchSoundnessStatement).find("DUAL-OOD") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3BatchSoundnessStatement).find("(c1,c2)!=(0,0)") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3BatchSoundnessStatement).find("half-domain") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3BatchSoundnessStatement).find("Fp3") !=
                std::string::npos);
    BOOST_CHECK_EQUAL(rc::kRCFri3BatchProofVersion, 5u);
}

BOOST_AUTO_TEST_CASE(frib3_honest_commit_verify_serde_byte_exact)
{
    const auto cols = MakeBatchColumns();
    const uint256 seed = MakeSeed(0xB1);
    const auto c = rc::Fri3BatchCommit(cols, seed, /*pow_grind_nonce=*/11);
    BOOST_REQUIRE_MESSAGE(c.ok, c.note);
    const auto& p = c.proof;
    BOOST_CHECK_EQUAL(p.n_coeffs, 32u); // max column len 32 (canonical pow2)
    BOOST_CHECK_EQUAL(p.queries.size(), rc::kRCFriBatchNumQueries);
    BOOST_CHECK_EQUAL(p.columns.size(), cols.size());
    // Dual OOD: two distinct points, both off the LDE domain (nonzero extension
    // part suffices for off-domain; distinctness checked by the verifier).
    BOOST_CHECK(!gf::Eq(p.z1, p.z2));
    std::string why;
    BOOST_CHECK_MESSAGE(rc::Fri3BatchVerify(p, seed, &why), why);
    BOOST_CHECK(gf::Canonical(p.z1.c1) != 0 || gf::Canonical(p.z1.c2) != 0);
    BOOST_CHECK(gf::Canonical(p.z2.c1) != 0 || gf::Canonical(p.z2.c2) != 0);
    BOOST_CHECK(!gf::Eq(p.z1, p.z2));

    // The opening primitive: bound per-column evaluations at BOTH OOD points
    // are byte-exact against direct polynomial evaluation.
    for (size_t i = 0; i < cols.size(); ++i) {
        BOOST_CHECK(gf::Eq(p.evals_z1[i], rc::Fri3EvalPoly(cols[i], p.z1)));
        BOOST_CHECK(gf::Eq(p.evals_z2[i], rc::Fri3EvalPoly(cols[i], p.z2)));
    }

    // Column-root helper (two-epoch discipline) matches the committed roots.
    for (size_t i = 0; i < cols.size(); ++i) {
        BOOST_CHECK(rc::Fri3BatchColumnRoot(cols[i], p.n_coeffs) == p.columns[i].root);
    }

    // Serialization is byte-exact round-trip and still verifies.
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE(rc::SerializeFri3BatchProof(p, bytes) > 0);
    const auto back = rc::DeserializeFri3BatchProof(bytes);
    BOOST_REQUIRE(back.has_value());
    std::vector<unsigned char> bytes2;
    BOOST_REQUIRE(rc::SerializeFri3BatchProof(*back, bytes2) > 0);
    BOOST_CHECK(bytes == bytes2);
    BOOST_CHECK(rc::Fri3BatchVerify(*back, seed, &why));
}

BOOST_AUTO_TEST_CASE(frib3_forged_ood_opening_rejected)
{
    // A forged column opening at an OOD point must be rejected: the dual-OOD
    // DEEP identity at the query sites catches it.
    const auto cols = MakeBatchColumns();
    const uint256 seed = MakeSeed(0xB2);
    const auto c = rc::Fri3BatchCommit(cols, seed);
    BOOST_REQUIRE(c.ok);
    std::string why;
    auto bad = c.proof;
    bad.evals_z1[1].c0 ^= 1;
    BOOST_CHECK(!rc::Fri3BatchVerify(bad, seed, &why));
    auto bad2 = c.proof;
    bad2.evals_z2[2].c1 ^= 1;
    BOOST_CHECK(!rc::Fri3BatchVerify(bad2, seed, &why));
    auto bad3 = c.proof;
    bad3.evals_z2[0].c2 ^= 1;
    BOOST_CHECK(!rc::Fri3BatchVerify(bad3, seed, &why));
}

BOOST_AUTO_TEST_CASE(frib3_forged_column_or_path_rejected)
{
    const auto cols = MakeBatchColumns();
    const uint256 seed = MakeSeed(0xB3);
    const auto c = rc::Fri3BatchCommit(cols, seed);
    BOOST_REQUIRE(c.ok);
    std::string why;

    auto bad = c.proof; // query-site column value forged
    bad.queries[0].columns[0].value.c0 ^= 1;
    BOOST_CHECK(!rc::Fri3BatchVerify(bad, seed, &why));

    auto bad2 = c.proof; // Merkle sibling forged
    BOOST_REQUIRE(!bad2.queries[0].columns[0].siblings.empty());
    bad2.queries[0].columns[0].siblings[0].data()[0] ^= 0xff;
    BOOST_CHECK(!rc::Fri3BatchVerify(bad2, seed, &why));

    auto bad3 = c.proof; // column commitment forged → FS challenges shift
    bad3.columns[0].root.data()[0] ^= 0xff;
    BOOST_CHECK(!rc::Fri3BatchVerify(bad3, seed, &why));

    auto bad4 = c.proof; // fold challenge forged
    BOOST_REQUIRE(!bad4.fold_challenges.empty());
    bad4.fold_challenges[0].c0 ^= 1;
    BOOST_CHECK(!rc::Fri3BatchVerify(bad4, seed, &why));

    auto bad5 = c.proof; // final value forged
    bad5.final_value.c0 ^= 1;
    BOOST_CHECK(!rc::Fri3BatchVerify(bad5, seed, &why));

    auto bad6 = c.proof; // truncated queries
    bad6.queries.pop_back();
    BOOST_CHECK(!rc::Fri3BatchVerify(bad6, seed, &why));

    auto bad7 = c.proof; // degree-bound (len) forged → shift/v recompute breaks
    bad7.column_len[1] = 4;
    BOOST_CHECK(!rc::Fri3BatchVerify(bad7, seed, &why));

    // Wrong FS seed → every challenge differs.
    BOOST_CHECK(!rc::Fri3BatchVerify(c.proof, MakeSeed(0xB4), &why));
}

BOOST_AUTO_TEST_CASE(frib3_column_exceeding_kappa_or_empty_rejected)
{
    const uint256 seed = MakeSeed(0xB5);
    // Empty column list / empty column rejected.
    BOOST_CHECK(!rc::Fri3BatchCommit({}, seed).ok);
    BOOST_CHECK(!rc::Fri3BatchCommit({std::vector<rc::Fp3>{}}, seed).ok);
    // CPU LDE guard (protocol κ cap is 2^28; CPU soft guard is LDE 2^24).
    std::vector<std::vector<rc::Fp3>> big;
    big.push_back(std::vector<rc::Fp3>((1u << 20) + 1, gf::FromSigned3(1)));
    const auto r = rc::Fri3BatchCommit(big, seed);
    BOOST_CHECK(!r.ok);
}

BOOST_AUTO_TEST_SUITE_END()
