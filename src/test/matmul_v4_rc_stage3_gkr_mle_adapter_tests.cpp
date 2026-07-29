// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_gkr_mle_adapter.h>

#include <cstdlib>
#include <limits>

namespace adapter =
    matmul::v4::rc::stage3_gkr_mle_adapter;
namespace wireless =
    matmul::v4::rc::stage3_gkr_wireless_receipt;
namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_gkr_mle_adapter_tests)

namespace {

uint256 Root(uint8_t seed)
{
    uint256 out;
    for (uint32_t index = 0; index < 32; ++index) {
        out.data()[index] =
            static_cast<uint8_t>(
                seed + 13 * index);
    }
    return out;
}

rc::RCEpisodeParams TinyParams()
{
    rc::RCEpisodeParams out;
    out.rounds = 1;
    out.d_head = 32;
    out.n_q = 32;
    out.n_ctx = 32;
    out.L_lyr = 1;
    out.d_model = 32;
    out.d_ff = 32;
    out.b_seq = 32;
    out.T_leaf = 64;
    return out;
}

wireless::PublicDescriptorV1 Descriptor()
{
    const std::vector<uint256> round_roots{
        Root(0x21)};
    const uint256 digest =
        rc::RCGkrEpisodeDigestFromRoots(
            round_roots);
    wireless::PublicDescriptorV1 out;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        wireless::BuildPublicDescriptorV1(
            TinyParams(), 191, digest,
            rc::RCGkrDerivePowBind(digest),
            Root(0x32), round_roots,
            Root(0x43), out, &why),
        why);
    return out;
}

std::vector<std::vector<gf::Fp3>> Columns(
    const wireless::PublicDescriptorV1& descriptor,
    const wireless::ChunkRangeV1& range,
    uint64_t salt = 0)
{
    std::vector<std::vector<gf::Fp3>> out(
        range.column_count);
    for (uint32_t local = 0;
         local < range.column_count; ++local) {
        const uint32_t global =
            range.first_column + local;
        out[local].resize(
            descriptor.columns[global].logical_len);
        for (uint32_t row = 0;
             row < out[local].size(); ++row) {
            out[local][row] = {
                gf::FromU64(
                    1 + salt + 17 * global + 3 * row),
                gf::FromU64(
                    2 + salt + 19 * global + 5 * row),
                gf::FromU64(
                    3 + salt + 23 * global + 7 * row),
            };
        }
    }
    return out;
}

std::vector<gf::Fp3> Point(uint32_t dimension)
{
    std::vector<gf::Fp3> out(dimension);
    for (uint32_t index = 0;
         index < dimension; ++index) {
        out[index] = {
            gf::FromU64(3 + 5 * index),
            gf::FromU64(7 + 11 * index),
            gf::FromU64(13 + 17 * index)};
    }
    return out;
}

struct HonestFixture {
    wireless::PublicDescriptorV1 descriptor;
    wireless::ChunkRangeV1 range;
    std::vector<std::vector<gf::Fp3>> columns;
    wireless::ReceiptV1 receipt;
    std::vector<adapter::OpeningClaimV1> claims;
    adapter::ProveResultV1 proved;

    HonestFixture()
    {
        descriptor = Descriptor();
        // One canonical Lambda column keeps the proof-level regression below
        // five minutes while exercising the real Q192/V13 implementation.
        range = {0, 1};
        columns = Columns(descriptor, range);
        const uint256 seed =
            wireless::DeriveChunkFsSeedV1(
                descriptor, range);
        BOOST_REQUIRE(!seed.IsNull());
        const auto oracle =
            rc::Fri3AlgSafeQ192K2V13BatchCommit(
                columns, seed, 0);
        BOOST_REQUIRE_MESSAGE(
            oracle.ok, oracle.note);
        const auto receipt_audit =
            wireless::BuildReceiptV1(
                descriptor, range,
                oracle.proof, receipt);
        BOOST_REQUIRE_MESSAGE(
            receipt_audit.valid,
            receipt_audit.note);
        rc::Fri3AlgRowTreeCache main_cache;
        std::string cache_why;
        BOOST_REQUIRE_MESSAGE(
            rc::Fri3AlgBuildRowTreeCacheStreaming(
                columns, receipt.fri_proof.n_coeffs,
                main_cache, &cache_why),
            cache_why);
        BOOST_CHECK(
            main_cache.root ==
            receipt.fri_proof.row_commit.root);

        const uint32_t dimension = [](
            uint32_t n) {
            uint32_t log = 0;
            while ((uint32_t{1} << log) < n) ++log;
            return log;
        }(receipt.fri_proof.n_coeffs);
        auto point = Point(dimension);
        std::vector<gf::Fp3> padded =
            columns.front();
        padded.resize(
            receipt.fri_proof.n_coeffs,
            gf::Fp3::Zero());
        claims.push_back({
            range.first_column,
            point,
            rc::RCGkrMleEval1D3(
                padded, point)});
        proved = adapter::ProveV1(
            descriptor, receipt,
            columns, claims);
        BOOST_REQUIRE_MESSAGE(
            proved.ok, proved.note);
    }
};

const HonestFixture& Honest()
{
    static const HonestFixture fixture;
    return fixture;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    adapter_scope_is_executable_and_authority_remains_fail_closed)
{
    BOOST_CHECK(
        adapter::
            kDualSafeFp3EvaluationArgumentExecutableV1);
    BOOST_CHECK(
        adapter::kArbitraryMleAdapterExecutableV1);
    BOOST_CHECK(
        !adapter::
            kEpisodeRelationSemanticsExecutableV1);
    BOOST_CHECK(
        !adapter::
            kNormalizedRecursiveConsumptionExecutableV1);
    BOOST_CHECK(
        !adapter::kProductionAuthorityReadyV1);
}

BOOST_AUTO_TEST_CASE(
    n128_ntt_witness_matches_direct_reference_and_lemma_identity)
{
    const auto audit =
        adapter::AuditNttWitnessConstructionV1();
    BOOST_CHECK_MESSAGE(audit.valid, audit.note);
    BOOST_CHECK_EQUAL(audit.n_coeffs, 128U);
    BOOST_CHECK_EQUAL(audit.claims, 3U);
    BOOST_CHECK(audit.ntt_path_executed);
    BOOST_CHECK(audit.dual_sigma_matches);
    BOOST_CHECK(
        audit.all_witness_coefficients_match);
    BOOST_CHECK(
        audit.both_families_hold_at_both_points);
}

BOOST_AUTO_TEST_CASE(
    exact_estimator_and_chunk_plan_reserve_four_witness_columns)
{
    uint32_t adapter_width = 0;
    uint32_t wireless_width = 0;
    for (uint32_t width = 1;
         width <=
             adapter::kMaxReceiptColumnsPerProofV1;
         ++width) {
        const auto bytes =
            adapter::EstimateProofBytesV1(
                width,
                rc::kRCGkrColumnMaxCoeffs);
        BOOST_REQUIRE(bytes.has_value());
        if (*bytes > adapter::kMaxProofBytesV1) break;
        adapter_width = width;
    }
    for (uint32_t width = 1;
         width <=
             wireless::
                 kMaxOracleColumnsPerReceiptV1;
         ++width) {
        const auto bytes =
            wireless::EstimateQ192V13ProofBytesV1(
                width,
                rc::kRCGkrColumnMaxCoeffs);
        BOOST_REQUIRE(bytes.has_value());
        if (*bytes > rc::kRCFriMaxProofBytesHard) break;
        wireless_width = width;
    }
    BOOST_REQUIRE_GT(adapter_width, 0U);
    BOOST_CHECK_LT(adapter_width, wireless_width);
    BOOST_CHECK_LE(
        *adapter::EstimateProofBytesV1(
            adapter_width,
            rc::kRCGkrColumnMaxCoeffs),
        adapter::kMaxProofBytesV1);
    BOOST_CHECK_GT(
        *adapter::EstimateProofBytesV1(
            adapter_width + 1U,
            rc::kRCGkrColumnMaxCoeffs),
        adapter::kMaxProofBytesV1);

    const auto descriptor = Descriptor();
    const auto plan =
        adapter::BuildChunkPlanV1(descriptor);
    BOOST_REQUIRE(!plan.empty());
    uint32_t next = 0;
    for (const auto& range : plan) {
        BOOST_CHECK_EQUAL(range.first_column, next);
        uint32_t n = 1;
        for (uint32_t local = 0;
             local < range.column_count; ++local) {
            const uint64_t length =
                descriptor.columns[
                    range.first_column + local]
                    .logical_len;
            while (n < length) n <<= 1;
        }
        BOOST_REQUIRE_LE(
            *adapter::EstimateProofBytesV1(
                range.column_count, n),
            adapter::kMaxProofBytesV1);
        BOOST_REQUIRE_LE(
            *wireless::EstimateQ192V13ProofBytesV1(
                range.column_count, n),
            rc::kRCFriMaxProofBytesHard);
        next += range.column_count;
    }
    BOOST_CHECK_EQUAL(
        next, descriptor.columns.size());
}

BOOST_AUTO_TEST_CASE(
    v13_same_root_dual_safe_mle_attack_matrix)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_GKR_MLE_ADAPTER_V13") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_GKR_MLE_ADAPTER_V13=1 "
            "for the proof-level adapter attack matrix");
        return;
    }
    const auto& honest = Honest();
    const auto& proof = honest.proved.proof;
    const auto& audit = honest.proved.audit;
    BOOST_REQUIRE(audit.valid);
    BOOST_CHECK(audit.receipt_verified);
    BOOST_CHECK(audit.canonical_claims);
    BOOST_CHECK(audit.claim_transcript_bound);
    BOOST_CHECK(audit.receipt_row_root_reused);
    BOOST_CHECK(audit.dual_safe_challenges_replayed);
    BOOST_CHECK(audit.v13_multirow_fri_verified);
    BOOST_CHECK(
        audit.dual_evaluation_identities_verified);
    BOOST_CHECK(audit.arbitrary_mle_claims_verified);
    BOOST_CHECK(
        !audit.episode_relation_semantics_verified);
    BOOST_CHECK(!audit.recursively_consumed);
    BOOST_CHECK_LE(
        honest.proved.proof_bytes,
        adapter::kMaxProofBytesV1);
    BOOST_REQUIRE(
        adapter::EstimateProofBytesV1(
            honest.range.column_count,
            honest.receipt.fri_proof.n_coeffs)
            .has_value());
    BOOST_CHECK_EQUAL(
        honest.proved.proof_bytes,
        *adapter::EstimateProofBytesV1(
            honest.range.column_count,
            honest.receipt.fri_proof.n_coeffs));
    BOOST_REQUIRE_EQUAL(proof.batch.groups.size(), 3U);
    BOOST_CHECK(
        proof.batch.groups[0].row_commit.root ==
        honest.receipt.fri_proof.row_commit.root);

    std::vector<unsigned char> encoded;
    BOOST_REQUIRE_EQUAL(
        adapter::SerializeProofV1(proof, encoded),
        encoded.size());
    const auto decoded =
        adapter::DeserializeProofV1(encoded);
    BOOST_REQUIRE(decoded.has_value());
    std::vector<unsigned char> encoded_again;
    BOOST_REQUIRE_EQUAL(
        adapter::SerializeProofV1(
            *decoded, encoded_again),
        encoded.size());
    BOOST_CHECK(encoded_again == encoded);

    // Claimed value transplant: the public claim commitment moves before any
    // expensive receipt or FRI verification.
    {
        auto claims = honest.claims;
        claims[0].value =
            gf::Add(
                claims[0].value,
                gf::Fp3::One());
        const auto rejected =
            adapter::VerifyV1(
                honest.descriptor,
                honest.receipt,
                claims, proof);
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(!rejected.claim_transcript_bound);
        const auto forged =
            adapter::ProveV1(
                honest.descriptor,
                honest.receipt,
                honest.columns, claims);
        BOOST_CHECK(!forged.ok);
        BOOST_CHECK(
            !forged.audit
                 .dual_evaluation_identities_verified);
    }

    // MLE point transplant.
    {
        auto claims = honest.claims;
        claims[0].point[0] =
            gf::Add(
                claims[0].point[0],
                gf::Fp3::One());
        const auto rejected =
            adapter::VerifyV1(
                honest.descriptor,
                honest.receipt,
                claims, proof);
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(!rejected.claim_transcript_bound);
        const auto forged =
            adapter::ProveV1(
                honest.descriptor,
                honest.receipt,
                honest.columns, claims);
        BOOST_CHECK(!forged.ok);
        BOOST_CHECK(
            !forged.audit
                 .dual_evaluation_identities_verified);
    }

    // Column-claim transplant.
    {
        auto claims = honest.claims;
        ++claims[0].global_column_id;
        const auto rejected =
            adapter::VerifyV1(
                honest.descriptor,
                honest.receipt,
                claims, proof);
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(!rejected.canonical_claims);
    }

    // Goldilocks x / x+p alias: malformed raw limbs are rejected before any
    // Canonical() call can collapse them.
    {
        auto claims = honest.claims;
        BOOST_REQUIRE_LE(
            claims[0].point[0].c0,
            std::numeric_limits<uint64_t>::max() -
                gf::kP);
        claims[0].point[0].c0 += gf::kP;
        const auto rejected =
            adapter::VerifyV1(
                honest.descriptor,
                honest.receipt,
                claims, proof);
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(!rejected.canonical_claims);
    }

    // Receipt transplant / wrapper splice.
    {
        auto receipt = honest.receipt;
        receipt.receipt_root[0] =
            gf::Add(
                receipt.receipt_root[0], 1);
        const auto rejected =
            adapter::VerifyV1(
                honest.descriptor, receipt,
                honest.claims, proof);
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(!rejected.receipt_verified);
    }

    // Native proof/transcript tamper: reaches the unmodified V13 verifier and
    // is rejected by transcript replay, not a witness-violation counter.
    {
        auto changed = proof;
        changed.batch.lambda =
            gf::Add(
                changed.batch.lambda,
                gf::Fp3::One());
        const auto rejected =
            adapter::VerifyV1(
                honest.descriptor,
                honest.receipt,
                honest.claims, changed);
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(
            !rejected.v13_multirow_fri_verified);
    }

    // SAFE mu-family transcript mutation: sigma is proof-carried but verifier
    // recomputes it from both independent SAFE challenge families.
    {
        auto changed = proof;
        changed.evaluation_argument.sigma[1] =
            gf::Add(
                changed.evaluation_argument.sigma[1],
                gf::Fp3::One());
        const auto rejected =
            adapter::VerifyV1(
                honest.descriptor,
                honest.receipt,
                honest.claims, changed);
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(
            !rejected
                 .dual_evaluation_identities_verified);
    }

    // f/g proof-cell tamper: the unmodified V13 proof owns each evaluation.
    {
        auto changed = proof;
        const uint32_t f =
            changed.evaluation_argument.f_column[0];
        changed.batch.evals_z1[f] =
            gf::Add(
                changed.batch.evals_z1[f],
                gf::Fp3::One());
        const auto rejected =
            adapter::VerifyV1(
                honest.descriptor,
                honest.receipt,
                honest.claims, changed);
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(
            !rejected.v13_multirow_fri_verified);
    }

    // Auxiliary-root transplant: it changes the derived V13 FRI seed and the
    // opened Merkle statement.
    {
        auto changed = proof;
        changed.batch.groups[1].row_commit.root[0] =
            gf::Add(
                changed.batch.groups[1]
                    .row_commit.root[0],
                1);
        const auto rejected =
            adapter::VerifyV1(
                honest.descriptor,
                honest.receipt,
                honest.claims, changed);
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(
            !rejected.v13_multirow_fri_verified);
    }

    // Quotient-root transplant is independently bound; neither witness
    // family can borrow the other group's authenticated root.
    {
        auto changed = proof;
        changed.batch.groups[2].row_commit.root[0] =
            gf::Add(
                changed.batch.groups[2]
                    .row_commit.root[0],
                1);
        const auto rejected =
            adapter::VerifyV1(
                honest.descriptor,
                honest.receipt,
                honest.claims, changed);
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(
            !rejected.v13_multirow_fri_verified);
    }

    // Public receipt/chunk seed transplant.
    {
        auto receipt = honest.receipt;
        receipt.chunk_fs_seed.data()[0] ^= 1;
        const auto rejected =
            adapter::VerifyV1(
                honest.descriptor, receipt,
                honest.claims, proof);
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(!rejected.claim_transcript_bound);
    }

    // Noncanonical codec alias is rejected at decode.
    {
        auto bad = encoded;
        // First descriptor-root lane begins after magic/version/reserved.
        const size_t lane = 8;
        const uint64_t noncanonical = gf::kP;
        for (uint32_t byte = 0; byte < 8; ++byte) {
            bad[lane + byte] =
                static_cast<unsigned char>(
                    noncanonical >> (8 * byte));
        }
        BOOST_CHECK(
            !adapter::DeserializeProofV1(
                 bad).has_value());
    }
}

BOOST_AUTO_TEST_SUITE_END()
