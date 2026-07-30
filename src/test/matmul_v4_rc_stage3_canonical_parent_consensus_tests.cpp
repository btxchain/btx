// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_canonical_parent_consensus.h>

#include <crypto/common.h>
#include <boost/test/unit_test.hpp>

#include <array>

namespace {

namespace rc = matmul::v4::rc;
namespace cpc =
    matmul::v4::rc::canonical_parent_consensus;
namespace cb =
    matmul::v4::rc::constraint_bytecode;
namespace aq =
    matmul::v4::rc::air_quotient;
namespace gf =
    matmul::v4::rc::gkr_field;
namespace nav3 =
    matmul::v4::rc::normalized_authority;
namespace ncb =
    matmul::v4::rc::normalized_consensus_binding;

uint256 H(uint32_t value)
{
    std::array<unsigned char, 32> bytes{};
    for (uint32_t index = 0;
         index < bytes.size(); ++index) {
        bytes[index] = static_cast<unsigned char>(
            value + 17U * index);
    }
    return uint256{
        Span<const unsigned char>{
            bytes.data(), bytes.size()}};
}

cb::ProgramTable ConstantPublicOutputProgram(
    uint32_t width)
{
    cb::ProgramTable table;
    table.role =
        rc::RCStage3RelationRole::CompositionLink;
    table.current_width = width;
    table.next_width = width;
    table.programs.reserve(width);
    for (uint32_t column = 0;
         column < width; ++column) {
        cb::Program program;
        program.role = table.role;
        program.constraint_ordinal = column;
        program.kind = aq::AirKind::kTransition;
        program.declared_degree = 1;
        program.current_width = width;
        program.next_width = width;
        program.instructions = {
            {cb::Opcode::Next, column, 0,
             gf::Fp3::Zero()},
            {cb::Opcode::Current, column, 0,
             gf::Fp3::Zero()},
            {cb::Opcode::Sub, 0, 1,
             gf::Fp3::Zero()},
        };
        table.programs.push_back(
            std::move(program));
    }
    return table;
}

struct Fixture {
    cpc::FrozenBinaryParentSpecV1 frozen;
    cpc::CompleteChildStatementsV1 children;

    static Fixture Build()
    {
        Fixture out;
        const auto& roles =
            rc::RCStage3UnifiedRoleOrder();
        uint32_t nonce = 1;
        for (uint32_t role_index = 0;
             role_index < roles.size();
             ++role_index) {
            nav3::RolePinV3 role;
            role.role = roles[role_index];
            role.program_root = H(nonce++);
            role.relation_statement_root =
                H(nonce++);
            cpc::FrozenRoleScheduleV1 schedule;
            schedule.role = role.role;
            schedule.program_root =
                role.program_root;
            const auto& endpoints =
                rc::RequiredRCStage3RelationEndpoints(
                    role.role);
            for (const auto endpoint_kind :
                 endpoints) {
                nav3::EndpointPinV3 endpoint;
                endpoint.endpoint = endpoint_kind;
                endpoint.instance_count =
                    1000U + nonce++;
                endpoint.manifest_root = H(nonce++);
                endpoint.relation_proof_root =
                    H(nonce++);
                endpoint.semantic_root = H(nonce++);
                endpoint.ctl_terminal_root = H(nonce++);
                endpoint
                    .recursive_child_statement_root =
                    H(nonce++);
                schedule.endpoints.push_back(
                    {endpoint.endpoint,
                     endpoint.instance_count,
                     endpoint.manifest_root});
                role.endpoints.push_back(
                    std::move(endpoint));
            }
            role.endpoint_manifest_root =
                nav3::ComputeRoleEndpointManifestRootV3(
                    role);
            role.role_statement_root =
                nav3::ComputeRoleStatementRootV3(role);
            out.children.roles.push_back(
                std::move(role));
            out.frozen.role_schedule.push_back(
                std::move(schedule));
        }
        for (uint32_t child = 0;
             child < 2; ++child) {
            const uint32_t width =
                cpc::CanonicalChildPublicOutputCellCountV1(
                    out.frozen, child);
            BOOST_REQUIRE_GT(width, 1U);
            out.frozen.child_shape[child]
                .child_columns = width;
            auto& registry =
                out.frozen.child_registry[child];
            registry.child_relation_program =
                ConstantPublicOutputProgram(width);
            registry.program_root =
                cb::CommitProgramTable(
                    registry.child_relation_program);
        }
        return out;
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_canonical_parent_consensus_tests)

BOOST_AUTO_TEST_CASE(
    frozen_inventory_and_constant_output_abi_reject_substitution)
{
    const Fixture honest = Fixture::Build();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cpc::ValidateCanonicalChildPublicOutputAbiV1(
            honest.frozen, honest.children, &why),
        why);

    {
        auto changed = honest.children;
        ++changed.roles[0].endpoints[0].instance_count;
        changed.roles[0].endpoint_manifest_root =
            nav3::ComputeRoleEndpointManifestRootV3(
                changed.roles[0]);
        changed.roles[0].role_statement_root =
            nav3::ComputeRoleStatementRootV3(
                changed.roles[0]);
        BOOST_CHECK(
            !cpc::ValidateCanonicalChildPublicOutputAbiV1(
                honest.frozen, changed, &why));
    }
    {
        auto changed = honest.children;
        changed.roles[0].endpoints[0].manifest_root =
            H(0xface);
        changed.roles[0].endpoint_manifest_root =
            nav3::ComputeRoleEndpointManifestRootV3(
                changed.roles[0]);
        changed.roles[0].role_statement_root =
            nav3::ComputeRoleStatementRootV3(
                changed.roles[0]);
        BOOST_CHECK(
            !cpc::ValidateCanonicalChildPublicOutputAbiV1(
                honest.frozen, changed, &why));
    }
    {
        auto nonconstant = honest.frozen;
        auto& table =
            nonconstant.child_registry[0]
                .child_relation_program;
        table.programs.erase(table.programs.begin());
        nonconstant.child_registry[0].program_root =
            cb::CommitProgramTable(table);
        BOOST_CHECK(
            !cpc::ValidateCanonicalChildPublicOutputAbiV1(
                nonconstant, honest.children, &why));
        BOOST_CHECK(
            why.find(
                "public_output_not_constant_in_child_air") !=
            std::string::npos);
    }
    {
        auto changed = honest.children;
        changed.roles[0].program_root = H(0xbeef);
        changed.roles[0].role_statement_root =
            nav3::ComputeRoleStatementRootV3(
                changed.roles[0]);
        BOOST_CHECK(
            !cpc::ValidateCanonicalChildPublicOutputAbiV1(
                honest.frozen, changed, &why));
    }
    {
        auto changed = honest.children;
        std::swap(changed.roles[0], changed.roles[1]);
        BOOST_CHECK(
            !cpc::ValidateCanonicalChildPublicOutputAbiV1(
                honest.frozen, changed, &why));
    }
}

BOOST_AUTO_TEST_CASE(
    rebuilt_parent_contains_exact_public_output_equalities)
{
    Fixture fixture = Fixture::Build();
    for (uint32_t child = 0;
         child < 2; ++child) {
        auto& shape =
            fixture.frozen.child_shape[child];
        shape.child_rows = 2;
        shape.child_quotient_len = 1;
        shape.child_coefficients = 2;
        shape.child_lde =
            shape.child_coefficients *
            rc::kRCFriBlowup;
        shape.merkle_depth = 5;
        shape.folds = 1;
        shape.queries =
            rc::kRCFri3AlgNumQueries;
        shape.independent_fri_batching =
            rc::Fri3AlgQ192IndependentBatching();
        shape.column_lengths.assign(
            uint64_t{shape.child_columns} + 1U,
            shape.child_rows);
        shape.column_lengths.back() =
            shape.child_quotient_len;
    }
    ncb::DirectReceiptConsensusStatementV3 block;
    block.public_statement.height = 101;
    block.public_statement.header_commitment =
        H(0x1001);
    block.public_statement.params_commitment =
        H(0x1002);
    block.public_statement.target = H(0x1003);
    block.public_statement.sigma = H(0x1004);
    block.public_statement.episode_digest =
        H(0x1005);
    block.public_statement.coupled_digest =
        H(0x1006);
    block.public_statement.final_digest = H(0x1007);
    block.public_statement.program_consensus_pin
        .recursive_alg_hash_root = H(0x1008);
    block.public_statement.program_consensus_pin
        .external_sha256d_audit_root = H(0x1009);
    block.public_statement.program_consensus_pin
        .registry_binding = H(0x100a);
    block.expected_program_registry_root =
        block.public_statement.program_consensus_pin
            .recursive_alg_hash_root;

    cpc::RebuiltCanonicalParentV1 rebuilt;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cpc::RebuildCanonicalParentV1(
            block, fixture.frozen,
            fixture.children, H(0x100b),
            rebuilt, &why),
        why);
    BOOST_CHECK(
        rebuilt.frozen_occurrence_inventory_enforced);
    BOOST_CHECK(
        rebuilt
            .child_public_output_polynomials_constant);
    BOOST_CHECK(
        rebuilt
            .child_public_outputs_equality_constrained);
    BOOST_CHECK(!rebuilt.authority);
    const uint64_t cells =
        uint64_t{
            cpc::CanonicalChildPublicOutputCellCountV1(
                fixture.frozen, 0)} +
        cpc::CanonicalChildPublicOutputCellCountV1(
            fixture.frozen, 1);
    BOOST_CHECK_GE(
        rebuilt.verifier.parent_cs.constraints.size(),
        2U * cells);
    BOOST_CHECK_EQUAL(
        rebuilt.verifier.fixed_trace.n_columns,
        rebuilt.verifier.parent_cs.n_columns);

    // A proof-owned statement-root substitution is allowed to form a new
    // claim, but it changes both the child FS seed and the parent pin
    // equation. Therefore an honest receipt for the original claim cannot
    // be replayed under the coherently recomputed substituted role root.
    auto substituted = fixture.children;
    const uint256 honest_relation =
        substituted.roles[0]
            .relation_statement_root;
    substituted.roles[0].relation_statement_root =
        H(0x2001);
    substituted.roles[0].role_statement_root =
        nav3::ComputeRoleStatementRootV3(
            substituted.roles[0]);
    cpc::RebuiltCanonicalParentV1 changed;
    BOOST_REQUIRE_MESSAGE(
        cpc::RebuildCanonicalParentV1(
            block, fixture.frozen,
            substituted, H(0x100b),
            changed, &why),
        why);
    BOOST_CHECK(
        changed.child_fs_seed[0] !=
        rebuilt.child_fs_seed[0]);
    BOOST_CHECK_EQUAL(
        changed.verifier.parent_cs.constraints.size(),
        rebuilt.verifier.parent_cs.constraints.size());
    const uint32_t total_cells =
        static_cast<uint32_t>(cells);
    const uint32_t fixed_base =
        changed.verifier.parent_cs.n_columns -
        total_cells;
    const uint32_t relation_word_offset =
        1U + 8U; // acceptance then program-root words
    const uint32_t added_constraint_base =
        static_cast<uint32_t>(
            changed.verifier.parent_cs
                .constraints.size()) -
        2U * total_cells;
    std::vector<gf::Fp3> row(
        changed.verifier.parent_cs.n_columns,
        gf::Fp3::Zero());
    row[fixed_base + relation_word_offset] =
        gf::Fp3::FromFp(gf::FromU64(
            ReadLE32(honest_relation.data())));
    const auto violation =
        changed.verifier.parent_cs.constraints[
            added_constraint_base +
            2U * relation_word_offset]
            .eval(row, row);
    BOOST_CHECK(!gf::IsZero(violation));
}

BOOST_AUTO_TEST_SUITE_END()
