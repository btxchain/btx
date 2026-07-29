// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_relation_quotient_join.h>

#include <chrono>
#include <cstdlib>

namespace matmul::v4::rc::stage3_multirow_v11_relation_quotient_join {
namespace {

using gf::Fp3;
namespace np = stage3_multirow_v11_normalized_program;
namespace cb = constraint_bytecode;

alg_hash::Digest TaggedDigest(uint32_t domain, uint32_t a, uint32_t b)
{
    return alg_hash::SpongeHashFp({
        gf::FromU64(domain),
        gf::FromU64(a),
        gf::FromU64(b),
    });
}

InputV1 MakeInput()
{
    cb::ProgramTable full;
    np::ManifestV1 manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        np::BuildCanonicalProgramTableV1(
            full, &manifest, &why),
        why);
    InputV1 out;
    out.relation_plan = rs::BuildPlanV1(full);
    BOOST_REQUIRE_MESSAGE(
        out.relation_plan.valid_foundation,
        out.relation_plan.note);
    out.full_q192_transcript_root =
        TaggedDigest(UINT32_C(0x54524e53), 192, 1);
    for (uint32_t range = 0;
         range < kQueryRangesV1;
         ++range) {
        for (uint32_t shard = 0;
             shard < kRelationShardsV1;
             ++shard) {
            out.leaf_receipt_roots[range][shard] =
                TaggedDigest(
                    UINT32_C(0x52435054),
                    range, shard);
        }
    }
    out.queries.resize(kRealQueryRowsV1);
    for (uint32_t query = 0;
         query < kRealQueryRowsV1;
         ++query) {
        auto& item = out.queries[query];
        item.query_ordinal = query;
        item.y = Fp3{
            gf::FromU64(1000 + query),
            gf::FromU64(2000 + 3 * query),
            gf::FromU64(3000 + 7 * query)};
        item.zh = Fp3{
            gf::FromU64(17 + query),
            gf::FromU64(29 + 2 * query),
            gf::FromU64(43 + 5 * query)};
        for (uint32_t shard = 0;
             shard < kRelationShardsV1;
             ++shard) {
            item.partial_quotients[shard] =
                Fp3{
                    gf::FromU64(
                        101 + query + 11 * shard),
                    gf::FromU64(
                        211 + 3 * query + 13 * shard),
                    gf::FromU64(
                        307 + 5 * query + 17 * shard)};
            item.partial_compositions[shard] =
                gf::Mul(
                    item.zh,
                    item.partial_quotients[shard]);
        }
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_relation_quotient_join_tests)

BOOST_AUTO_TEST_CASE(
    q64x3_join_executes_with_explicit_scheduler_reserve)
{
    const auto input = MakeInput();
    const auto product = BuildProductV1(input);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK(product.q64x3_production_safe_fallback);
    BOOST_CHECK(product.exact_q192_partition);
    BOOST_CHECK(product.exact_relation_partition);
    BOOST_CHECK(product.ordered_quotient_sum_identity);
    BOOST_CHECK(product.preprocessed_values_root_pinned);
    BOOST_CHECK_EQUAL(product.active_query_rows, 192U);
    BOOST_CHECK_EQUAL(product.scheduler_reserve_rows, 64U);
    BOOST_CHECK_EQUAL(product.trace_rows, 256U);
    BOOST_CHECK_EQUAL(product.trace_columns, 250U);
    BOOST_CHECK_EQUAL(product.constraints, 178U);
    BOOST_CHECK_EQUAL(product.max_constraint_degree, 2U);
    BOOST_CHECK_EQUAL(product.quotient_len, 255U);
    BOOST_CHECK_EQUAL(product.leaf_receipts, 18U);
    BOOST_CHECK_EQUAL(
        product.materialized_trace_cells,
        UINT64_C(64000));
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(!product.fiat_shamir_query_derivation_verified);
    BOOST_CHECK(!product.relation_leaf_receipt_payloads_verified);
    BOOST_CHECK(!product.recursive_authority_ready);
    BOOST_CHECK(kRelationQuotientJoinExecutableV1);
    BOOST_CHECK(!kRelationLeafReceiptPayloadsVerifiedV1);
    BOOST_CHECK(!kRecursiveAuthorityReadyV1);
    BOOST_TEST_MESSAGE(
        "V11_RELATION_QJOIN rows=" << product.trace_rows
        << " active_queries=" << product.active_query_rows
        << " scheduler_reserve=" << product.scheduler_reserve_rows
        << " columns=" << product.trace_columns
        << " constraints=" << product.constraints
        << " quotient_len=" << product.quotient_len
        << " leaf_receipts=" << product.leaf_receipts);
}

BOOST_AUTO_TEST_CASE(
    arithmetic_routing_and_program_root_forgeries_are_rejected)
{
    const auto input = MakeInput();
    const auto product = BuildProductV1(input);
    BOOST_REQUIRE(product.valid);

    auto forged = product.columns;
    forged[
        product.layout.leaves[2]
            .partial_composition][17] =
        gf::Add(
            forged[
                product.layout.leaves[2]
                    .partial_composition][17],
            Fp3::One());
    BOOST_CHECK_GT(
        RecountViolationsV1(product, forged), 0U);

    forged = product.columns;
    forged[
        product.layout.leaves[4]
            .partial_quotient][83] =
        gf::Add(
            forged[
                product.layout.leaves[4]
                    .partial_quotient][83],
            Fp3::One());
    BOOST_CHECK_GT(
        RecountViolationsV1(product, forged), 0U);

    forged = product.columns;
    forged[
        product.layout.leaves[1]
            .query_ordinal_alias][129] =
        Fp3::FromFp(gf::FromU64(128));
    BOOST_CHECK_GT(
        RecountViolationsV1(product, forged), 0U);

    forged = product.columns;
    forged[
        product.layout.leaves[5]
            .local_program_root.claim[0]][3] =
        gf::Add(
            forged[
                product.layout.leaves[5]
                    .local_program_root.claim[0]][3],
            Fp3::One());
    BOOST_CHECK_GT(
        RecountViolationsV1(product, forged), 0U);

    forged = product.columns;
    forged[
        product.layout.leaves[0]
            .relation_ordinal.claim][7] =
        Fp3::FromFp(gf::FromU64(5));
    BOOST_CHECK_GT(
        RecountViolationsV1(product, forged), 0U);
}

BOOST_AUTO_TEST_CASE(
    simultaneous_claim_expected_mutation_is_stopped_by_ordered_r0_root)
{
    const auto input = MakeInput();
    const auto product = BuildProductV1(input);
    BOOST_REQUIRE(product.valid);
    auto forged = product.columns;
    const auto& receipt =
        product.layout.leaves[3].receipt_root;
    forged[receipt.claim[2]][130] =
        gf::Add(
            forged[receipt.claim[2]][130],
            Fp3::One());
    forged[receipt.expected[2]][130] =
        forged[receipt.claim[2]][130];
    BOOST_CHECK_GT(
        RecountViolationsV1(product, forged), 0U);

    auto reordered = product;
    std::swap(
        reordered.preprocessed_columns[0],
        reordered.preprocessed_columns[1]);
    BOOST_CHECK_GT(
        RecountViolationsV1(
            reordered, reordered.columns),
        0U);
}

BOOST_AUTO_TEST_CASE(
    split_rap_roundtrip_measurement_and_proof_level_tamper_reject)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_V11_RELATION_QJOIN_PROOF") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_V11_RELATION_QJOIN_PROOF=1 "
            "for the bounded quotient-join proof measurement");
        return;
    }
    const auto input = MakeInput();
    const auto proved = ProveV1(input, uint256::ONE);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    const auto verified =
        VerifyV1(input, proved.proof, uint256::ONE);
    BOOST_REQUIRE_MESSAGE(
        verified.accepted, verified.note);
    BOOST_CHECK(!verified.relation_leaf_receipt_payloads_verified);
    BOOST_CHECK(!verified.recursive_authority_ready);
    BOOST_CHECK_NE(proved.proof_wire_bytes, 0U);

    auto forged = proved.proof;
    BOOST_REQUIRE(!forged.batch.groups.empty());
    forged.batch.groups[0].row_commit.root[0] =
        gf::Add(
            forged.batch.groups[0]
                .row_commit.root[0],
            gf::FromU64(1));
    const auto rejected =
        VerifyV1(input, forged, uint256::ONE);
    BOOST_CHECK(!rejected.accepted);
    BOOST_TEST_MESSAGE(
        "V11_RELATION_QJOIN_PROOF proof_bytes="
        << proved.proof_wire_bytes
        << " prove_us=" << proved.prove_micros
        << " verify_us=" << verified.verify_micros
        << " proof_level_root_tamper_rejected=1"
        << " child_payloads_verified=0"
        << " authority=0");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_relation_quotient_join
