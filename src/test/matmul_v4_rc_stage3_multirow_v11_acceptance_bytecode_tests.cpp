// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_acceptance_bytecode.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>
#include <hash.h>

#include <algorithm>
#include <array>
#include <utility>
#include <vector>

namespace av =
    matmul::v4::rc::
    stage3_multirow_v11_acceptance_bytecode;
namespace cb = matmul::v4::rc::constraint_bytecode;
namespace gf = matmul::v4::rc::gkr_field;
namespace ut = matmul::v4::rc::universal_topology;
namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_acceptance_bytecode_tests,
    BasicTestingSetup)

namespace {

uint256 H(uint32_t tag)
{
    HashWriter hash;
    hash << uint64_t{0x31434241'31315652ULL};
    hash << tag;
    return hash.GetHash();
}

av::AcceptanceInstanceV1 Instance(uint32_t tag = 1)
{
    std::array<gf::Fp3, av::kAcceptanceSemanticColumnsV1> first{};
    std::array<gf::Fp3, av::kAcceptanceSemanticColumnsV1> second{};
    const auto layout =
        av::rp::CanonicalLayoutV1();
    for (uint32_t column = 0;
         column < first.size(); ++column) {
        first[column] =
            gf::FromU64_3(
                1000 + uint64_t{tag} * 100 + column);
        second[column] =
            gf::FromU64_3(
                2000 + uint64_t{tag} * 100 + column);
    }
    first[layout.active] = gf::Fp3::One();
    first[layout.ordinal] = gf::Fp3::Zero();
    first[layout.accepted] = gf::Fp3::One();
    second[layout.active] = gf::Fp3::One();
    second[layout.ordinal] = gf::Fp3::One();
    second[layout.accepted] = gf::Fp3::One();
    return av::BuildAcceptanceInstanceV1(
        first, second, H(tag));
}

void Renumber(cb::ProgramTable& table)
{
    for (uint32_t ordinal = 0;
         ordinal < table.programs.size();
         ++ordinal) {
        table.programs[ordinal].constraint_ordinal =
            ordinal;
    }
}

cb::ProgramTable StubOneColumnProgram()
{
    cb::Program program;
    program.role =
        rc::RCStage3RelationRole::CompositionLink;
    program.constraint_ordinal = 0;
    program.kind =
        rc::air_quotient::AirKind::kEverywhere;
    program.declared_degree = 1;
    program.current_width = 1;
    program.next_width = 1;
    program.instructions.push_back({
        cb::Opcode::Current, 0, 0,
        gf::Fp3::Zero()});
    cb::ProgramTable table;
    table.role = program.role;
    table.current_width = 1;
    table.next_width = 1;
    table.programs.push_back(std::move(program));
    return table;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    canonical_static_table_is_exact_and_statement_independent)
{
    const auto first = Instance(1);
    const auto second = Instance(2);
    BOOST_REQUIRE_MESSAGE(first.valid, first.note);
    BOOST_REQUIRE_MESSAGE(second.valid, second.note);

    cb::ProgramTable a;
    cb::ProgramTable b;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        av::BuildCanonicalProgramTableV1(
            first, a, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        av::BuildCanonicalProgramTableV1(
            second, b, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(a, &why), why);
    BOOST_CHECK_EQUAL(
        a.programs.size(),
        av::kAcceptanceConstraintCountV1);
    BOOST_CHECK(a == b);
    BOOST_CHECK_EQUAL(
        cb::CommitProgramTable(a),
        cb::CommitProgramTable(b));
    BOOST_CHECK(
        cb::CommitProgramTableAlgHash(a) ==
        cb::CommitProgramTableAlgHash(b));
    BOOST_CHECK_NE(
        first.fixed_trace_row_root,
        second.fixed_trace_row_root);

    const auto audit =
        av::AuditAgainstCallbacksV1(first, a, 16);
    BOOST_REQUIRE_MESSAGE(audit.valid, audit.note);
    BOOST_CHECK_EQUAL(audit.callback_constraints, 11U);
    BOOST_CHECK_EQUAL(audit.bytecode_programs, 11U);
    BOOST_CHECK_EQUAL(audit.mismatches, 0U);

    const auto redundancy =
        av::AuditFixedTracePinRedundancyV1(first);
    BOOST_REQUIRE_MESSAGE(
        redundancy.valid, redundancy.note);
    BOOST_CHECK_EQUAL(
        redundancy.legacy_pin_constraints, 222U);
    BOOST_CHECK_EQUAL(
        redundancy.legacy_full_constraints, 233U);
    BOOST_CHECK_EQUAL(
        redundancy.pin_family_mutations_rejected,
        redundancy.pin_family_mutations_tested);
    BOOST_CHECK(
        redundancy.no_full_callback_equation_nonredundant);

    const auto binding =
        av::BuildProgramBindingV1(first);
    BOOST_REQUIRE_MESSAGE(binding.valid, binding.note);
    BOOST_CHECK(binding.statement_independent_program);
    BOOST_CHECK(
        binding.fixed_trace_pin_redundancy_proved);
    BOOST_CHECK(
        binding.canonical_bytecode_residual_removable);
    BOOST_CHECK_EQUAL(
        binding.residual_mask,
        av::kResidualConsensusRegistryRoot);
    BOOST_CHECK(!binding.consensus_registry_bound);

    std::vector<unsigned char> bytes;
    BOOST_REQUIRE(
        cb::SerializeProgramTable(a, bytes, &why));
    cb::ProgramTable decoded;
    BOOST_REQUIRE(
        cb::DeserializeProgramTable(
            bytes, decoded, &why));
    BOOST_CHECK(decoded == a);
}

BOOST_AUTO_TEST_CASE(
    callback_bytecode_drift_and_all_canonical_mutations_reject)
{
    auto instance = Instance();
    BOOST_REQUIRE(instance.valid);
    cb::ProgramTable canonical;
    BOOST_REQUIRE(
        av::BuildCanonicalProgramTableV1(
            instance, canonical));

    auto callback_drift = instance;
    callback_drift.structural_cs.constraints[0].eval =
        [](const auto&, const auto&) {
            return gf::Fp3::Zero();
        };
    const auto drift =
        av::AuditAgainstCallbacksV1(
            callback_drift, canonical, 8);
    BOOST_CHECK(!drift.valid);
    BOOST_CHECK_GT(drift.mismatches, 0U);

    auto omitted = canonical;
    omitted.programs.erase(
        omitted.programs.begin() + 3);
    Renumber(omitted);
    BOOST_REQUIRE(cb::ValidateProgramTable(omitted));
    BOOST_CHECK(
        !av::AssessCanonicalProgramV1(
            instance, omitted).valid);

    auto reordered = canonical;
    std::swap(
        reordered.programs[0],
        reordered.programs[1]);
    Renumber(reordered);
    BOOST_REQUIRE(cb::ValidateProgramTable(reordered));
    BOOST_CHECK(
        !av::AssessCanonicalProgramV1(
            instance, reordered).valid);

    auto opcode = canonical;
    opcode.programs[2].instructions.back().opcode =
        cb::Opcode::Add;
    BOOST_REQUIRE(cb::ValidateProgramTable(opcode));
    BOOST_CHECK(
        !av::AssessCanonicalProgramV1(
            instance, opcode).valid);

    auto column = canonical;
    column.programs[0].instructions[0].lhs =
        instance.layout.accepted;
    BOOST_REQUIRE(cb::ValidateProgramTable(column));
    BOOST_CHECK(
        !av::AssessCanonicalProgramV1(
            instance, column).valid);

    auto selector = canonical;
    selector.programs[6].instructions[0].lhs =
        instance.layout.accepted;
    BOOST_REQUIRE(cb::ValidateProgramTable(selector));
    BOOST_CHECK(
        !av::AssessCanonicalProgramV1(
            instance, selector).valid);

    auto constant = canonical;
    constant.programs[0].instructions[1].constant =
        gf::FromU64_3(2);
    BOOST_REQUIRE(cb::ValidateProgramTable(constant));
    BOOST_CHECK(
        !av::AssessCanonicalProgramV1(
            instance, constant).valid);
}

BOOST_AUTO_TEST_CASE(
    version_shape_manifest_and_structural_stub_substitutions_reject)
{
    auto instance = Instance();
    BOOST_REQUIRE(instance.valid);
    cb::ProgramTable canonical;
    BOOST_REQUIRE(
        av::BuildCanonicalProgramTableV1(
            instance, canonical));

    auto version = canonical;
    ++version.version;
    BOOST_CHECK(
        !av::AssessCanonicalProgramV1(
            instance, version).valid);

    auto width = canonical;
    ++width.current_width;
    for (auto& program : width.programs) {
        ++program.current_width;
    }
    BOOST_REQUIRE(cb::ValidateProgramTable(width));
    BOOST_CHECK(
        !av::AssessCanonicalProgramV1(
            instance, width).valid);

    auto manifest = instance;
    manifest.fixed_trace_manifest_root = H(300);
    BOOST_CHECK(
        !av::AssessCanonicalProgramV1(
            manifest, canonical).valid);

    auto shape = instance;
    --shape.version;
    BOOST_CHECK(
        !av::AssessCanonicalProgramV1(
            shape, canonical).valid);

    const auto stub = StubOneColumnProgram();
    BOOST_REQUIRE(cb::ValidateProgramTable(stub));
    BOOST_CHECK(
        !av::AssessCanonicalProgramV1(
            instance, stub).valid);
}

BOOST_AUTO_TEST_CASE(
    registry_interface_accepts_only_authenticated_static_leaf)
{
    const auto instance = Instance();
    const auto binding =
        av::BuildProgramBindingV1(instance);
    BOOST_REQUIRE(binding.valid);

    ut::ProductionProgramRegistryV1 registry;
    auto absent = av::AssessRegistryMembershipV1(
        binding, registry, {});
    BOOST_CHECK(!absent.consensus_root_supplied);
    BOOST_CHECK(!absent.raw_table_membership_proved);
    BOOST_CHECK(!absent.bound_program_membership_proved);
    BOOST_CHECK(!absent.production_authority);

    registry.universal_parent_verifier =
        binding.table_commitment;
    registry.universal_parent_columns =
        av::kAcceptanceProofColumnsV1;
    const auto preimage =
        ut::BuildProductionProgramRegistryAlgHashPreimageV1(
            registry);
    BOOST_REQUIRE(!preimage.empty());
    registry.recursive_registry_commitment =
        rc::alg_hash::SpongeHashFp(preimage);
    const auto authenticated =
        av::AssessRegistryMembershipV1(
            binding, registry,
            registry.recursive_registry_commitment);
    BOOST_CHECK(
        authenticated.registry_root_matches_consensus);
    BOOST_CHECK(
        authenticated.exact_program_leaf_matches);
    BOOST_CHECK(
        authenticated.static_program_schema_compatible);
    BOOST_CHECK(
        authenticated.raw_table_membership_proved);
    BOOST_CHECK(
        authenticated.bound_program_membership_proved);
    // This proves the precise leaf/root interface, not that a network has
    // adopted the synthetic expected root used by this test.
    BOOST_CHECK(!authenticated.production_authority);

    auto leaf_mutation = registry;
    leaf_mutation.universal_parent_columns = 1;
    const auto rejected =
        av::AssessRegistryMembershipV1(
            binding, leaf_mutation,
            registry.recursive_registry_commitment);
    BOOST_CHECK(!rejected.registry_root_matches_consensus);
    BOOST_CHECK(!rejected.bound_program_membership_proved);
}

BOOST_AUTO_TEST_SUITE_END()
