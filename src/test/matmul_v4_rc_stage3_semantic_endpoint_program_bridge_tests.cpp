// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_semantic_endpoint_program_bridge.h>

#include <algorithm>
#include <chrono>

namespace {

namespace bridge =
    matmul::v4::rc::semantic_endpoint_program_bridge;
namespace gf = matmul::v4::rc::gkr_field;
using matmul::v4::rc::RCStage3RelationEndpoint;
using matmul::v4::rc::RCStage3RelationRole;

const bridge::SemanticEndpointProgramBindingV1& Endpoint(
    const bridge::SemanticEndpointProgramBridgeManifestV1& manifest,
    RCStage3RelationEndpoint endpoint)
{
    const auto found = std::find_if(
        manifest.endpoints.begin(),
        manifest.endpoints.end(),
        [endpoint](const auto& value) {
            return value.endpoint == endpoint;
        });
    BOOST_REQUIRE(found != manifest.endpoints.end());
    return *found;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_semantic_endpoint_program_bridge_tests)

BOOST_AUTO_TEST_CASE(
    exact_program_tables_expand_to_all_executed_relation_cells)
{
    const auto manifest =
        bridge::BuildSemanticEndpointProgramBridgeManifestV1();
    std::string why;
    BOOST_REQUIRE(
        bridge::ValidateSemanticEndpointProgramBridgeManifestV1(
            manifest, &why));
    BOOST_CHECK_EQUAL(manifest.endpoints.size(), 52U);
    BOOST_CHECK_EQUAL(manifest.families.size(), 28U);
    BOOST_CHECK_EQUAL(
        manifest.registry_semantic_claim_endpoints, 14U);
    BOOST_CHECK_EQUAL(
        manifest.selected_program_key_endpoints, 52U);
    BOOST_CHECK_EQUAL(
        manifest.canonical_output_metadata_endpoints, 52U);
    BOOST_CHECK_EQUAL(
        manifest.executed_relation_cell_endpoints, 28U);
    BOOST_CHECK_EQUAL(
        manifest.exact_relation_column_endpoints, 28U);
    BOOST_CHECK_EQUAL(manifest.direct_alias_endpoints, 28U);
    BOOST_CHECK_EQUAL(
        manifest.recursive_child_accepted_endpoints, 0U);
    BOOST_CHECK_EQUAL(manifest.complete_roles, 0U);
    BOOST_CHECK(!manifest.recursive_semantic_closure_complete);
    BOOST_CHECK(!manifest.production_authority);

    for (const auto endpoint : {
             RCStage3RelationEndpoint::EpisodeBuilderParams,
             RCStage3RelationEndpoint::EpisodeBuilderSeedChain,
             RCStage3RelationEndpoint::EpisodeBuilderOperandXof,
             RCStage3RelationEndpoint::EpisodeBuilderTrace}) {
        const auto& builder = Endpoint(manifest, endpoint);
        BOOST_CHECK(builder.selected_program_key);
        BOOST_CHECK(builder.exact_program_table_match);
        BOOST_CHECK(builder.canonical_output_metadata);
        BOOST_CHECK(builder.executed_relation_cell);
        BOOST_CHECK(builder.relation_column_exact);
        BOOST_CHECK(builder.same_trace_ctl_alias);
        BOOST_CHECK(builder.direct_alias_ready);
        BOOST_CHECK(!builder.recursive_child_accepted);
    }

    std::vector<RCStage3RelationEndpoint> observed_missing;
    for (const auto& endpoint : manifest.endpoints) {
        if (!endpoint.canonical_output_metadata) {
            observed_missing.push_back(endpoint.endpoint);
        }
    }
    BOOST_CHECK(observed_missing.empty());

    for (const auto endpoint : {
             RCStage3RelationEndpoint::EpisodeExtractChaCha,
             RCStage3RelationEndpoint::CoupledBankSeedXof,
             RCStage3RelationEndpoint::CoupledBankRoot,
             RCStage3RelationEndpoint::CoupledExchangeHashXof,
             RCStage3RelationEndpoint::CoupledExtractChaCha}) {
        const auto& fixed = Endpoint(manifest, endpoint);
        BOOST_CHECK(fixed.selected_program_key);
        BOOST_CHECK(fixed.exact_program_table_match);
        BOOST_CHECK(fixed.canonical_output_metadata);
        BOOST_CHECK_EQUAL(
            fixed.relation_column,
            matmul::v4::rc::kRCStage3HashKernelOutputColumnV1);
        BOOST_CHECK(!fixed.registry_semantic_claim);
        BOOST_CHECK(!fixed.direct_alias_ready);
    }

    // A single exact family genuinely owns three endpoint cells.  This is the
    // one-to-many expansion the old single semantic_endpoints claim omitted.
    const auto& a = Endpoint(
        manifest, RCStage3RelationEndpoint::EpisodeGemmOperandA);
    const auto& b = Endpoint(
        manifest, RCStage3RelationEndpoint::EpisodeGemmOperandB);
    const auto& y = Endpoint(
        manifest, RCStage3RelationEndpoint::EpisodeGemmOutputY);
    BOOST_CHECK_EQUAL(a.family_index, b.family_index);
    BOOST_CHECK_EQUAL(a.family_index, y.family_index);
    BOOST_CHECK_EQUAL(a.relation_column, 1U);
    BOOST_CHECK_EQUAL(b.relation_column, 2U);
    BOOST_CHECK_EQUAL(y.relation_column, 0U);
    BOOST_CHECK(a.direct_alias_ready);
    BOOST_CHECK(b.direct_alias_ready);
    BOOST_CHECK(y.direct_alias_ready);
    BOOST_CHECK(!a.registry_semantic_claim);

    const auto& sumcheck = Endpoint(
        manifest, RCStage3RelationEndpoint::EpisodeGemmSumcheck);
    BOOST_CHECK(sumcheck.selected_program_key);
    BOOST_CHECK(sumcheck.registry_semantic_claim);
    BOOST_CHECK_EQUAL(sumcheck.relation_column, 0U);
    BOOST_CHECK(sumcheck.canonical_output_metadata);
    BOOST_CHECK(!sumcheck.direct_alias_ready);

    const auto& signed_range = Endpoint(
        manifest, RCStage3RelationEndpoint::EpisodeGemmSignedRange);
    BOOST_CHECK_EQUAL(signed_range.relation_column, 2U);
    BOOST_CHECK(signed_range.canonical_output_metadata);
    BOOST_CHECK(signed_range.direct_alias_ready);

    const auto& barrier = Endpoint(
        manifest, RCStage3RelationEndpoint::CoupledBarrierHash);
    BOOST_CHECK_EQUAL(
        barrier.relation_column,
        matmul::v4::rc::universal_topology::
            production_family_col_v1::CoupledHashOutput);
    BOOST_CHECK(barrier.canonical_output_metadata);
    BOOST_CHECK(!barrier.direct_alias_ready);
}

BOOST_AUTO_TEST_CASE(
    every_unclosed_endpoint_has_an_exact_residual)
{
    const auto manifest =
        bridge::BuildSemanticEndpointProgramBridgeManifestV1();
    for (const auto& endpoint : manifest.endpoints) {
        BOOST_CHECK(!endpoint.residual.empty());
        BOOST_CHECK(
            endpoint.missing_sources &
            bridge::MissingRecursiveChildAcceptanceV1);
        if (endpoint.direct_alias_ready) {
            BOOST_CHECK_EQUAL(
                endpoint.missing_sources,
                bridge::MissingRecursiveChildAcceptanceV1);
        }
    }

    const auto& signed_range = Endpoint(
        manifest,
        RCStage3RelationEndpoint::EpisodeGemmSignedRange);
    BOOST_CHECK(signed_range.executed_relation_cell);
    BOOST_CHECK(signed_range.selected_program_key);
    BOOST_CHECK(signed_range.canonical_output_metadata);
    BOOST_CHECK_EQUAL(signed_range.relation_column, 2U);
    BOOST_CHECK(signed_range.same_trace_ctl_alias);
    BOOST_CHECK(signed_range.direct_alias_ready);
}

BOOST_AUTO_TEST_CASE(
    canonical_validation_rejects_omission_reorder_duplicate_and_cross_role)
{
    const auto canonical =
        bridge::BuildSemanticEndpointProgramBridgeManifestV1();
    std::string why;

    auto omitted = canonical;
    omitted.endpoints.pop_back();
    omitted.bridge_commitment =
        bridge::ComputeSemanticEndpointProgramBridgeCommitmentV1(
            omitted);
    BOOST_CHECK(
        !bridge::ValidateSemanticEndpointProgramBridgeManifestV1(
            omitted, &why));

    auto reordered = canonical;
    std::swap(reordered.endpoints[0], reordered.endpoints[1]);
    reordered.bridge_commitment =
        bridge::ComputeSemanticEndpointProgramBridgeCommitmentV1(
            reordered);
    BOOST_CHECK(
        !bridge::ValidateSemanticEndpointProgramBridgeManifestV1(
            reordered, &why));

    auto duplicate = canonical;
    duplicate.endpoints[1] = duplicate.endpoints[0];
    duplicate.bridge_commitment =
        bridge::ComputeSemanticEndpointProgramBridgeCommitmentV1(
            duplicate);
    BOOST_CHECK(
        !bridge::ValidateSemanticEndpointProgramBridgeManifestV1(
            duplicate, &why));

    auto cross_role = canonical;
    cross_role.endpoints[0].role =
        RCStage3RelationRole::CoupledDigest;
    cross_role.bridge_commitment =
        bridge::ComputeSemanticEndpointProgramBridgeCommitmentV1(
            cross_role);
    BOOST_CHECK(
        !bridge::ValidateSemanticEndpointProgramBridgeManifestV1(
            cross_role, &why));
}

BOOST_AUTO_TEST_CASE(
    exact_keys_columns_and_commitment_fail_closed)
{
    const auto canonical =
        bridge::BuildSemanticEndpointProgramBridgeManifestV1();
    std::string why;

    auto key = canonical;
    auto& a = key.endpoints[4];
    a.program_recursive_alg_hash_words[0] ^= 1U;
    key.bridge_commitment =
        bridge::ComputeSemanticEndpointProgramBridgeCommitmentV1(key);
    BOOST_CHECK(
        !bridge::ValidateSemanticEndpointProgramBridgeManifestV1(
            key, &why));

    auto column = canonical;
    column.endpoints[4].relation_column ^= 1U;
    column.bridge_commitment =
        bridge::ComputeSemanticEndpointProgramBridgeCommitmentV1(
            column);
    BOOST_CHECK(
        !bridge::ValidateSemanticEndpointProgramBridgeManifestV1(
            column, &why));

    auto commitment = canonical;
    commitment.bridge_commitment.begin()[0] ^= 1U;
    BOOST_CHECK(
        !bridge::ValidateSemanticEndpointProgramBridgeManifestV1(
            commitment, &why));
}

BOOST_AUTO_TEST_CASE(
    u32_receipt_cells_reject_extension_overflow_and_raw_x_plus_p)
{
    uint32_t out = 0;
    std::string why;
    BOOST_REQUIRE(
        bridge::DecodeSemanticEndpointProgramCanonicalU32V1(
            gf::Fp3{123, 0, 0}, out, &why));
    BOOST_CHECK_EQUAL(out, 123U);

    BOOST_CHECK(
        !bridge::DecodeSemanticEndpointProgramCanonicalU32V1(
            gf::Fp3{123, 1, 0}, out, &why));
    BOOST_CHECK(
        !bridge::DecodeSemanticEndpointProgramCanonicalU32V1(
            gf::Fp3{uint64_t{1} << 32, 0, 0}, out, &why));

    // Raw representatives are checked before canonicalization.  Reducing this
    // cell first would erase the x/(x+p) distinction and is forbidden.
    BOOST_CHECK(
        !bridge::DecodeSemanticEndpointProgramCanonicalU32V1(
            gf::Fp3{gf::kP + 1U, 0, 0}, out, &why));
}

BOOST_AUTO_TEST_CASE(
    mapping_commitment_air_roundtrip_and_proof_level_tamper_reject)
{
    const auto manifest =
        bridge::BuildSemanticEndpointProgramBridgeManifestV1();
    const auto product =
        bridge::BuildSemanticEndpointProgramBridgeAirV1(
            manifest);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK_EQUAL(product.cs.n_rows, 64U);
    BOOST_CHECK_EQUAL(product.active_rows, 52U);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(product.mapping_commitment_bound);
    BOOST_CHECK(
        product.only_expected_schedule_preprocessed);
    BOOST_CHECK(!product.recursive_child_consumption);
    BOOST_CHECK(!product.production_authority);

    const auto prove_begin =
        std::chrono::steady_clock::now();
    const auto proved =
        matmul::v4::rc::air_quotient::
            AirQuotientProveRows(
                product.cs, product.columns,
                product.proof_seed);
    const auto prove_end =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    std::string why;
    const auto verify_begin =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        matmul::v4::rc::air_quotient::
            AirQuotientVerifyRows(
                product.cs, proved.proof,
                product.proof_seed, &why),
        why);
    const auto verify_end =
        std::chrono::steady_clock::now();

    matmul::v4::rc::AirQuotientProofAlg canonical;
    canonical.batch = proved.proof.batch;
    canonical.next_openings =
        proved.proof.next_openings;
    canonical.trace_commit =
        proved.proof.trace_commit;
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE_MESSAGE(
        matmul::v4::rc::SerializeAirQuotientProofAlg(
            canonical, bytes, &why),
        why);
    BOOST_TEST_MESSAGE(
        "SEMANTIC_ENDPOINT_PROGRAM_BRIDGE measured_bytes="
        << bytes.size()
        << " prove_us="
        << std::chrono::duration_cast<
               std::chrono::microseconds>(
               prove_end - prove_begin).count()
        << " verify_us="
        << std::chrono::duration_cast<
               std::chrono::microseconds>(
               verify_end - verify_begin).count()
        << " rows=" << product.cs.n_rows
        << " cols=" << product.cs.n_columns
        << " constraints="
        << product.cs.constraints.size());

    auto row_tamper = proved.proof;
    BOOST_REQUIRE(!row_tamper.batch.queries.empty());
    BOOST_REQUIRE_GT(
        row_tamper.batch.queries[0].row.values.size(),
        product.layout.claimed_relation_column);
    row_tamper.batch.queries[0]
        .row.values[
            product.layout.claimed_relation_column] =
        gf::Add(
            row_tamper.batch.queries[0]
                .row.values[
                    product.layout
                        .claimed_relation_column],
            gf::Fp3::One());
    std::string row_reject;
    BOOST_CHECK_MESSAGE(
        !matmul::v4::rc::air_quotient::
            AirQuotientVerifyRows(
                product.cs, row_tamper,
                product.proof_seed, &row_reject),
        "proof-level output-column tamper accepted");

    auto pin_tamper_cs = product.cs;
    const auto pin = std::find_if(
        pin_tamper_cs.preprocessed.begin(),
        pin_tamper_cs.preprocessed.end(),
        [&product](const auto& entry) {
            return entry.first ==
                product.layout.expected_endpoint;
        });
    BOOST_REQUIRE(
        pin != pin_tamper_cs.preprocessed.end());
    BOOST_REQUIRE(!pin->second.empty());
    pin->second[0] =
        gf::Add(pin->second[0], gf::Fp3::One());
    std::string pin_reject;
    BOOST_CHECK_MESSAGE(
        !matmul::v4::rc::air_quotient::
            AirQuotientVerifyRows(
                pin_tamper_cs, proved.proof,
                product.proof_seed, &pin_reject),
        "proof-level expected schedule tamper accepted");
}

BOOST_AUTO_TEST_SUITE_END()
