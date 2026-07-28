// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_canonical_parent_production_verifier.h>
#include <test/util/setup_common.h>

#include <consensus/params.h>
#include <matmul/matmul_v4_rc_stage3_universal_topology.h>
#include <primitives/block.h>

#include <boost/test/unit_test.hpp>

namespace {

namespace cpv =
    matmul::v4::rc::canonical_parent_production_verifier;
namespace ut =
    matmul::v4::rc::universal_topology;

CBlock Block()
{
    CBlock out;
    out.nVersion = 4;
    out.nTime = 1;
    out.nBits = 0x207fffffU;
    out.nNonce64 = 7;
    out.matmul_dim = 256;
    return out;
}

Consensus::Params Params()
{
    Consensus::Params out;
    out.fMatMulPOW = true;
    out.nMatMulV4Height = 1;
    out.nMatMulRCHeight = 1;
    out.nMatMulRCProfile = 2;
    out.fMatMulRCUseToyDims = true;
    out.nMatMulV4Dimension = 256;
    out.nMatMulRCCoupledHeight = 1;
    out.nMatMulRCCoupledProfile = 3;
    out.fMatMulRCCoupledUseToyDims = true;
    return out;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_canonical_parent_production_verifier_tests,
    BasicTestingSetup)

BOOST_AUTO_TEST_CASE(
    immutable_derivation_reports_real_open_inputs_and_ignores_receipt_words)
{
    CBlock block = Block();
    Consensus::Params params = Params();
    auto first =
        cpv::AssessFrozenBinaryParentSpecV1(
            block, params, 101);
    BOOST_REQUIRE(first.block_dimensions_canonical);
    BOOST_REQUIRE(first.manifest_canonical);
    BOOST_REQUIRE(
        first.aggregation_schedule_canonical);
    BOOST_REQUIRE(
        first.registry_rebuilt_from_canonical_sources);
    BOOST_CHECK(!first.registry.authority_eligible);
    BOOST_CHECK(!first.spec_derivable);
    BOOST_CHECK(!first.authority);
    BOOST_CHECK(
        first.residual_mask &
        cpv::kResidualCanonicalRegistry);
    BOOST_REQUIRE_MESSAGE(
        first.role_half_programs_available,
        first.role_half_adapter_note);
    BOOST_REQUIRE_MESSAGE(
        first.role_half_shapes_available,
        first.role_half_adapter_note);
    BOOST_REQUIRE_MESSAGE(
        first.public_output_abi_available,
        first.role_half_adapter_note);
    BOOST_CHECK_EQUAL(
        first.residual_mask &
            cpv::kResidualRoleHalfPrograms,
        0U);
    BOOST_CHECK_EQUAL(
        first.residual_mask &
            cpv::kResidualRoleHalfShapes,
        0U);
    BOOST_CHECK_EQUAL(
        first.residual_mask &
            cpv::kResidualPublicOutputAbi,
        0U);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cpv::ValidateDiagnosticRoleHalfAdapterV1(
            first, first.diagnostic_frozen_spec,
            &why),
        why);
    for (uint32_t child = 0; child < 2; ++child) {
        const auto& shape =
            first.diagnostic_frozen_spec
                .child_shape[child];
        const auto& registry =
            first.diagnostic_frozen_spec
                .child_registry[child];
        BOOST_CHECK_EQUAL(
            shape.child_rows,
            first.site_manifest.policy
                .relation_rows_per_site);
        BOOST_CHECK_EQUAL(
            shape.child_columns,
            registry.child_relation_program
                .current_width);
        BOOST_CHECK_EQUAL(
            first.diagnostic_frozen_spec
                    .child_public_output[child]
                    .first_trace_column +
                matmul::v4::rc::
                    canonical_parent_consensus::
                        CanonicalChildPublicOutputCellCountV1(
                            first.diagnostic_frozen_spec,
                            child),
            shape.child_columns);
    }

    const auto pin =
        ut::BuildProductionProgramConsensusPinV1(
            first.registry.diagnostic_registry);
    params.hashMatMulRCStage3ProgramRegistryAlgRoot =
        pin.recursive_alg_hash_root;
    params.hashMatMulRCStage3ProgramRegistryShaAuditRoot =
        pin.external_sha256d_audit_root;
    params.hashMatMulRCStage3ProgramRegistryBinding =
        pin.registry_binding;
    first = cpv::AssessFrozenBinaryParentSpecV1(
        block, params, 101);
    BOOST_CHECK(first.consensus_registry_pin_matches);

    // Simulate receipt-controlled program/count/order bytes. Frozen-spec
    // derivation has no receipt input and therefore must be identical.
    CBlock substituted = block;
    substituted.matrix_c_data = {
        0x424e5633, 0x7fffffff, 0x11223344,
        0x55667788};
    const auto second =
        cpv::AssessFrozenBinaryParentSpecV1(
            substituted, params, 101);
    BOOST_CHECK_EQUAL(
        first.block_dimension_commitment,
        second.block_dimension_commitment);
    BOOST_CHECK_EQUAL(
        first.site_manifest.commitment,
        second.site_manifest.commitment);
    BOOST_CHECK_EQUAL(
        first.aggregation_schedule.commitment,
        second.aggregation_schedule.commitment);
    BOOST_CHECK(
        first.diagnostic_role_schedule ==
        second.diagnostic_role_schedule);
    BOOST_CHECK(
        first.diagnostic_frozen_spec.child_shape ==
        second.diagnostic_frozen_spec.child_shape);
    BOOST_CHECK(
        first.diagnostic_frozen_spec.child_registry ==
        second.diagnostic_frozen_spec.child_registry);
    BOOST_CHECK(
        first.diagnostic_frozen_spec.child_public_output ==
        second.diagnostic_frozen_spec.child_public_output);
    BOOST_CHECK_EQUAL(
        first.residual_mask,
        second.residual_mask);

    matmul::v4::rc::canonical_parent_consensus::
        FrozenBinaryParentSpecV1 frozen;
    cpv::FrozenSpecAssessmentV1 assessed;
    BOOST_CHECK(
        !cpv::BuildFrozenBinaryParentSpecV1(
            substituted, params, 101,
            frozen, &assessed, &why));
    BOOST_CHECK(
        why.find("frozen_spec_unavailable") !=
        std::string::npos);
    BOOST_CHECK(
        frozen.role_schedule.empty());
}

BOOST_AUTO_TEST_CASE(
    canonical_role_half_adapter_rejects_inventory_abi_and_root_substitution)
{
    const CBlock block = Block();
    Consensus::Params params = Params();
    const auto assessed =
        cpv::AssessFrozenBinaryParentSpecV1(
            block, params, 101);
    BOOST_REQUIRE_MESSAGE(
        assessed.role_half_programs_available,
        assessed.role_half_adapter_note);
    BOOST_REQUIRE_MESSAGE(
        assessed.role_half_shapes_available,
        assessed.role_half_adapter_note);
    BOOST_REQUIRE_MESSAGE(
        assessed.public_output_abi_available,
        assessed.role_half_adapter_note);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cpv::ValidateDiagnosticRoleHalfAdapterV1(
            assessed, assessed.diagnostic_frozen_spec,
            &why),
        why);

    {
        auto omitted = assessed.diagnostic_frozen_spec;
        omitted.role_schedule.pop_back();
        BOOST_CHECK(
            !cpv::ValidateDiagnosticRoleHalfAdapterV1(
                assessed, omitted, &why));
    }
    {
        auto duplicate = assessed.diagnostic_frozen_spec;
        duplicate.role_schedule[1] =
            duplicate.role_schedule[0];
        BOOST_CHECK(
            !cpv::ValidateDiagnosticRoleHalfAdapterV1(
                assessed, duplicate, &why));
    }
    {
        auto wrong_abi = assessed.diagnostic_frozen_spec;
        ++wrong_abi.child_public_output[0]
              .first_trace_column;
        BOOST_CHECK(
            !cpv::ValidateDiagnosticRoleHalfAdapterV1(
                assessed, wrong_abi, &why));
    }
    {
        auto wrong_root = assessed.diagnostic_frozen_spec;
        wrong_root.child_registry[1].program_root.SetNull();
        BOOST_CHECK(
            !cpv::ValidateDiagnosticRoleHalfAdapterV1(
                assessed, wrong_root, &why));
    }
}

BOOST_AUTO_TEST_SUITE_END()
