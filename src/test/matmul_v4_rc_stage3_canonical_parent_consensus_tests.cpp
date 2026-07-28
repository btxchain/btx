// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_canonical_parent_consensus.h>

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
}

BOOST_AUTO_TEST_SUITE_END()
