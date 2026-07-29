// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_safe_v15_superprogram.h>

#include <cstdlib>
#include <string>
#include <vector>

namespace {

namespace v15 =
    matmul::v4::rc::stage3_safe_v15_superprogram;
namespace rc = matmul::v4::rc;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;

uint256 Seed(uint8_t tag)
{
    uint256 out;
    for (uint32_t i = 0; i < out.size(); ++i) {
        out.data()[i] =
            static_cast<uint8_t>(tag + 17 * i);
    }
    return out;
}

struct NativeChildFixture {
    aq::AirConstraintSystem<gf::Fp3> cs;
    aq::AirQuotientSplitRapRowsProof proof;
    std::vector<uint32_t> base_indices{0, 1};
    uint256 seed{Seed(0x81)};
};

NativeChildFixture BuildNativeChild()
{
    constexpr uint32_t N = 8;
    NativeChildFixture out;
    std::vector<std::vector<gf::Fp3>> columns(
        4, std::vector<gf::Fp3>(
               N, gf::Fp3::Zero()));
    for (uint32_t row = 0; row < N; ++row) {
        columns[0][row] =
            gf::Fp3::FromFp(
                gf::FromU64(
                    5 + 3 * row + row * row));
        columns[1][row] =
            gf::Fp3::FromFp(
                gf::FromU64(11 + 7 * row));
    }
    const auto make_cs =
        [](const gf::Fp3& relation_challenge) {
            aq::AirConstraintSystem<gf::Fp3> cs;
            cs.n_rows = N;
            cs.n_columns = 4;
            aq::AirConstraint<gf::Fp3> relation;
            relation.name = "test.v15.native_relation";
            relation.kind = aq::AirKind::kEverywhere;
            relation.alg_degree = 1;
            relation.eval =
                [relation_challenge](
                    const auto& cur, const auto&) {
                    return gf::Sub(
                        cur[2],
                        gf::Add(
                            cur[0],
                            gf::Mul(
                                relation_challenge,
                                cur[1])));
                };
            cs.constraints.push_back(std::move(relation));
            aq::AirConstraint<gf::Fp3> transition;
            transition.name = "test.v15.native_next";
            transition.kind = aq::AirKind::kTransition;
            transition.alg_degree = 1;
            transition.eval =
                [](const auto& cur, const auto& next) {
                    return gf::Sub(
                        next[3],
                        gf::Add(cur[3], cur[2]));
                };
            cs.constraints.push_back(std::move(transition));
            return cs;
        };
    const auto shape = make_cs(gf::Fp3::Zero());
    const auto r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            shape, columns, out.base_indices);
    BOOST_REQUIRE_MESSAGE(r0.valid, r0.note);
    const uint256 relation_digest =
        aq::AirChallengeDigest(
            out.seed,
            "test_v15_native_relation",
            {r0.base_row_commitment},
            {N, 4});
    const gf::Fp3 challenge =
        gf::FromChallengeBytes3(
            relation_digest.data());
    out.cs = make_cs(challenge);
    for (uint32_t row = 0; row < N; ++row) {
        columns[2][row] =
            gf::Add(
                columns[0][row],
                gf::Mul(challenge, columns[1][row]));
        if (row + 1 < N) {
            columns[3][row + 1] =
                gf::Add(columns[3][row], columns[2][row]);
        }
    }
    out.cs.preprocessed.emplace_back(1, columns[1]);
    out.cs.preprocessed_pin_ood = true;
    out.cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role = aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns = out.base_indices,
        .root = r0.base_row_commitment,
    });
    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeV2(
            out.cs, columns, out.base_indices,
            out.seed, {}, &r0);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    out.proof = proved.proof;
    return out;
}

v15::ProductV15 BuildProduct(
    const NativeChildFixture& child)
{
    v15::ProductV15 product;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        v15::BuildCanonicalSourceToV14V15(
            child.cs, child.proof,
            child.base_indices, child.seed,
            product, &why),
        why);
    return product;
}

void CheckViolation(
    const v15::ProductV15& product,
    const std::vector<std::vector<gf::Fp3>>& columns,
    const char* label)
{
    BOOST_CHECK_MESSAGE(
        matmul::v4::rc::
            stage3_safe_v12_recursive_bridge::
                CountViolationsV12(
                    product.cs, columns) > 0,
        label);
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_safe_v15_superprogram_tests)

BOOST_AUTO_TEST_CASE(
    canonical_decoder_sources_join_actual_v14_message_cells)
{
    const auto child = BuildNativeChild();
    const auto product = BuildProduct(child);
    BOOST_CHECK(product.valid);
    BOOST_CHECK(product.external_child_proof_required);
    BOOST_CHECK(!product.child_proof_tape_in_v15);
    BOOST_CHECK(
        product.host_decoder_reconstructed_external_child);
    BOOST_CHECK(product.no_free_source_vector);
    BOOST_CHECK(product.canonical_source_values_preprocessed);
    BOOST_CHECK(product.exact_public_schedule);
    BOOST_CHECK(product.source_and_consumer_values_in_r0);
    BOOST_CHECK(product.dual_ctl_challenges_after_r0);
    BOOST_CHECK(product.dual_fp3_terminal_zero);
    BOOST_CHECK(product.canonical_source_subset_complete);
    BOOST_CHECK_EQUAL(
        product.producer_terms,
        product.consumer_terms);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(!product.prior_event_sources_complete);
    BOOST_CHECK(!product.derived_hash_sources_complete);
    BOOST_CHECK(
        !product.v14_outputs_to_verifier_consumers);
    BOOST_CHECK(!product.recursively_consumed);
    BOOST_CHECK(!product.recursive_authority_ready);
    BOOST_CHECK(!v15::kRecursiveAuthorityReadyV15);

    {
        auto changed_child = child.proof;
        changed_child.batch.pow_grind_nonce ^= UINT64_C(1);
        v15::ProductV15 rebound;
        std::string why;
        BOOST_CHECK(
            !v15::BuildCanonicalSourceToV14V15(
                child.cs, changed_child,
                child.base_indices, child.seed,
                rebound, &why));
        BOOST_CHECK(!rebound.valid);
    }

    const auto& source = product.sources.front();
    const auto& record = product.records.front();
    {
        auto forged = product.columns;
        forged[
            product.layout.ProducerValue(
                source.producer_slot)]
              [source.producer_row] =
            gf::Add(
                forged[
                    product.layout.ProducerValue(
                        source.producer_slot)]
                      [source.producer_row],
                gf::Fp3::One());
        CheckViolation(
            product, forged,
            "source-only forgery must violate V15");
    }
    {
        auto forged = product.columns;
        forged[record.v14_column][record.v14_row] =
            gf::Add(
                forged[record.v14_column][record.v14_row],
                gf::Fp3::One());
        CheckViolation(
            product, forged,
            "consumer-only forgery must violate V15/V14");
    }
    {
        auto forged = product.columns;
        const uint32_t producer_byte =
            product.layout.ProducerByte(
                source.producer_slot,
                record.source_byte);
        forged[producer_byte][source.producer_row] =
            gf::Add(
                forged[producer_byte][source.producer_row],
                gf::Fp3::One());
        forged[
            product.layout.ConsumerByte(
                record.consumer_port)]
              [record.v14_row] =
            gf::Add(
                forged[
                    product.layout.ConsumerByte(
                        record.consumer_port)]
                      [record.v14_row],
                gf::Fp3::One());
        CheckViolation(
            product, forged,
            "coordinated equal-value forgery must still violate "
            "decoder/V14 decompositions");
    }
    {
        auto forged = product.columns;
        forged[
            product.layout.consumer_active_base +
                record.consumer_port]
              [record.v14_row] = gf::Fp3::Zero();
        CheckViolation(
            product, forged,
            "consumer omission must violate the CTL");
    }
    {
        auto second = std::find_if(
            product.records.begin() + 1,
            product.records.end(),
            [&](const auto& candidate) {
                return candidate.source_address !=
                    record.source_address;
            });
        BOOST_REQUIRE(second != product.records.end());
        auto forged = product.columns;
        std::swap(
            forged[
                product.layout.consumer_address_base +
                    record.consumer_port]
                  [record.v14_row],
            forged[
                product.layout.consumer_address_base +
                    second->consumer_port]
                  [second->v14_row]);
        CheckViolation(
            product, forged,
            "reorder/transplant must violate the dual CTL");
    }
}

BOOST_AUTO_TEST_CASE(
    oversized_declared_proof_rejected_before_decode)
{
    v15::ProductV15 product;
    v15::ProofV15 proof;
    proof.serialized_proof_bytes =
        rc::kRCFriMaxProofBytesHard + 1;
    std::string why;
    BOOST_CHECK(
        !v15::VerifyCanonicalSourceToV14V15(
            product, proof, Seed(0xa1), &why));
    BOOST_CHECK_EQUAL(
        why,
        "stage3:safe_v15_superprogram:proof_size_bound");
}

BOOST_AUTO_TEST_CASE(
    proof_level_accept_and_tamper_wrong_seed_rejects)
{
    if (std::getenv("BTX_RUN_SAFE_V15_PROOF") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_SAFE_V15_PROOF=1 for the long V15 proof");
        return;
    }
    const auto child = BuildNativeChild();
    const auto product = BuildProduct(child);
    const uint256 seed = Seed(0x92);
    v15::ProofV15 proof;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        v15::ProveCanonicalSourceToV14V15(
            product, seed, proof, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        v15::VerifyCanonicalSourceToV14V15(
            product, proof, seed, &why),
        why);
    BOOST_CHECK_GT(proof.serialized_proof_bytes, 0U);
    BOOST_CHECK_LE(
        proof.serialized_proof_bytes,
        rc::kRCFriMaxProofBytesHard);
    BOOST_TEST_MESSAGE(
        "SAFE_V15_PROOF_BYTES="
        << proof.serialized_proof_bytes
        << " W=" << proof.trace_columns
        << " N=" << proof.trace_rows
        << " records=" << proof.record_count);
    BOOST_CHECK(!proof.child_proof_tape_in_v15);
    {
        auto bad = proof;
        bad.schedule_commitment[0] =
            gf::Add(
                bad.schedule_commitment[0],
                gf::FromU64(1));
        BOOST_CHECK(
            !v15::VerifyCanonicalSourceToV14V15(
                product, bad, seed, &why));
    }
    {
        auto bad = proof;
        bad.serialized_proof_bytes =
            rc::kRCFriMaxProofBytesHard + 1;
        BOOST_CHECK(
            !v15::VerifyCanonicalSourceToV14V15(
                product, bad, seed, &why));
    }
    {
        auto bad = proof;
        BOOST_REQUIRE(
            !bad.proof.batch.queries.empty());
        BOOST_REQUIRE(
            !bad.proof.batch.queries[0]
                 .group_rows.empty());
        BOOST_REQUIRE(
            !bad.proof.batch.queries[0]
                 .group_rows[0].values.empty());
        bad.proof.batch.queries[0]
            .group_rows[0].values[0] =
            gf::Add(
                bad.proof.batch.queries[0]
                    .group_rows[0].values[0],
                gf::Fp3::One());
        BOOST_CHECK(
            !v15::VerifyCanonicalSourceToV14V15(
                product, bad, seed, &why));
    }
    {
        uint256 wrong = seed;
        wrong.data()[0] ^= 0x80;
        BOOST_CHECK(
            !v15::VerifyCanonicalSourceToV14V15(
                product, proof, wrong, &why));
    }
}

BOOST_AUTO_TEST_SUITE_END()
