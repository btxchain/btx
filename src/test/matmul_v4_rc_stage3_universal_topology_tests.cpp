// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_universal_topology.h>

#include <map>

namespace rc = matmul::v4::rc;
namespace aq = rc::air_quotient;
namespace cb = rc::constraint_bytecode;
namespace ss = rc::soundness_scenarios;
namespace sch = rc::aggregation_scheduler;
namespace ut = rc::universal_topology;
namespace gf = rc::gkr_field;

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_universal_topology_tests)

namespace {

cb::ProgramTable OneColumnProgram(rc::RCStage3RelationRole role)
{
    cb::ProgramTable table;
    table.role = role;
    table.current_width = 1;
    table.next_width = 1;
    cb::Program program;
    program.role = role;
    program.kind = aq::AirKind::kEverywhere;
    program.declared_degree = 1;
    program.current_width = 1;
    program.next_width = 1;
    program.instructions.push_back(
        {cb::Opcode::Current, 0, 0, gf::Fp3::Zero()});
    table.programs.push_back(std::move(program));
    BOOST_REQUIRE(cb::ValidateProgramTable(table));
    return table;
}

std::vector<ut::ProductionFamilyProgramSourceV1>
Sources(const ss::ProductionProofSiteManifest& manifest)
{
    std::map<rc::RCStage3RelationRole, bool> assigned;
    std::vector<ut::ProductionFamilyProgramSourceV1> out;
    for (size_t i = 0; i < manifest.entries.size(); ++i) {
        const auto& site = manifest.entries[i];
        ut::ProductionFamilyProgramSourceV1 source;
        source.family_index = i;
        source.kind = site.kind;
        source.role = site.role;
        source.program = OneColumnProgram(site.role);
        source.public_input_schema = {
            static_cast<unsigned char>(i),
            static_cast<unsigned char>(
                static_cast<uint16_t>(site.role))};
        // These generic topology fixtures are challenge-free.  Model their
        // producer-owned phase manifest explicitly instead of relying on a
        // default descriptor: the sole witness column is committed in R0.
        source.phase.family_index =
            static_cast<uint32_t>(i);
        source.phase.kind = site.kind;
        source.phase.role = site.role;
        source.phase.program_root =
            cb::CommitProgramTable(source.program);
        source.phase.current_width =
            source.program.current_width;
        source.phase.challenge_width = 0;
        source.phase.challenge_epoch =
            ut::ProductionChallengeEpochV1::None;
        source.phase.r0_base_columns = {0};
        source.phase.producer_manifest_exported = true;
        if (!assigned[site.role]) {
            for (const auto endpoint :
                 rc::RequiredRCStage3RelationEndpoints(
                     site.role)) {
                source.semantic_endpoints.push_back(
                    static_cast<uint16_t>(endpoint));
            }
            assigned[site.role] = true;
        }
        source.semantic_relation_complete = true;
        out.push_back(std::move(source));
    }
    return out;
}

rc::alg_hash::Digest NonzeroDigest(uint64_t value)
{
    return rc::alg_hash::SpongeHashFp({
        gf::FromU64(value)});
}

} // namespace

BOOST_AUTO_TEST_CASE(
    exact_heterogeneous_topology_rejects_width_product_multiplicity)
{
    const auto manifest =
        ss::BuildProductionProofSiteManifest(
            ss::SelectedProductionProofSitePolicy());
    const auto schedule =
        sch::BuildProductionAggregationSchedule(manifest);
    const auto parent =
        OneColumnProgram(
            rc::RCStage3RelationRole::CompositionLink);
    const auto root = parent;
    const auto registry =
        ut::BuildProductionProgramRegistryV1(
            manifest, schedule, Sources(manifest),
            parent, root);
    BOOST_REQUIRE(
        !registry.external_registry_commitment.IsNull());
    BOOST_CHECK(
        registry.every_semantic_relation_complete);
    BOOST_CHECK(ut::ValidateProductionProgramRegistryV1(
        manifest, schedule, registry,
        registry.external_registry_commitment,
        registry.recursive_registry_commitment));
    const auto public_pin =
        ut::BuildProductionProgramRegistryPublicPinV1(
            registry);
    BOOST_REQUIRE(!public_pin.binding.IsNull());
    BOOST_CHECK(
        ut::ValidateProductionProgramRegistryPublicPinV1(
            registry, public_pin,
            registry.external_registry_commitment,
            registry.recursive_registry_commitment));
    const auto consensus_pin =
        ut::BuildProductionProgramConsensusPinV1(registry);
    BOOST_REQUIRE(
        rc::ValidateProductionProgramConsensusPinV1(
            consensus_pin));
    BOOST_CHECK(
        consensus_pin.external_sha256d_audit_root ==
        registry.external_registry_commitment);
    BOOST_CHECK(
        consensus_pin.registry_binding ==
        public_pin.binding);
    for (size_t limb_index = 0; limb_index < 4;
         ++limb_index) {
        uint64_t packed{0};
        for (size_t byte_index = 0; byte_index < 8;
             ++byte_index) {
            packed |= static_cast<uint64_t>(
                          consensus_pin.recursive_alg_hash_root
                              .data()[8 * limb_index +
                                      byte_index])
                      << (8 * byte_index);
        }
        BOOST_CHECK_EQUAL(
            packed,
            gf::Canonical(
                registry.recursive_registry_commitment[
                    limb_index]));
    }
    auto changed_pin = public_pin;
    changed_pin.recursive_registry_commitment[0] =
        gf::Add(
            changed_pin.recursive_registry_commitment[0],
            gf::Fp{1});
    BOOST_CHECK(
        !ut::ValidateProductionProgramRegistryPublicPinV1(
            registry, changed_pin,
            registry.external_registry_commitment,
            registry.recursive_registry_commitment));

    const auto topology =
        ut::AssessUniversalProductionTopologyV1(
            manifest, schedule, registry);
    BOOST_CHECK_EQUAL(
        topology.relation_leaf_sites, 44'639'077'288ULL);
    BOOST_CHECK_EQUAL(
        topology.arity_four_parent_sites, 14'879'692'506ULL);
    BOOST_CHECK_EQUAL(
        topology.final_tree_parent_sites, 15ULL);
    BOOST_CHECK_EQUAL(
        topology.exact_total_sites,
        ss::kSelectedProductionProofSitesV1);
    BOOST_CHECK_EQUAL(
        topology.rejected_product_site_diagnostic,
        19'403'118'957'734ULL);
    BOOST_CHECK_EQUAL(
        topology.shard_proof_instances,
        ss::kSelectedProductionProofSitesV1);
    BOOST_CHECK_EQUAL(
        topology.shard_coverage_and_recursion_events,
        ss::kSelectedProductionProofSitesV1);
    BOOST_CHECK_EQUAL(
        topology.family_batched_leaf_proof_instances, 28ULL);
    BOOST_CHECK_EQUAL(
        topology.family_batched_parent_proof_instances, 23ULL);
    BOOST_CHECK_EQUAL(
        topology.family_batched_total_proof_instances, 51ULL);
    BOOST_CHECK(
        !topology.family_batched_single_quotient_fri_executable);
    BOOST_CHECK(
        !topology.family_batched_candidate_selectable);
    BOOST_CHECK(
        !topology.shard_tree_economically_production_candidate);
    BOOST_CHECK(topology.exact_schedule_manifest_derived);
    BOOST_CHECK(topology.one_program_selector_per_family);
    BOOST_CHECK(
        topology.parent_is_constant_width_universal_program);
    BOOST_CHECK(
        topology.normalized_root_is_constant_width_program);
    BOOST_CHECK(
        topology.width_shards_are_not_site_multiplicity);
    BOOST_CHECK(!topology.production_topology_enforced);

    auto changed = registry;
    changed.families[3].maximum_columns++;
    BOOST_CHECK(!ut::ValidateProductionProgramRegistryV1(
        manifest, schedule, changed,
        registry.external_registry_commitment,
        registry.recursive_registry_commitment));
    uint256 wrong_external =
        registry.external_registry_commitment;
    wrong_external.begin()[0] ^= 1;
    BOOST_CHECK(!ut::ValidateProductionProgramRegistryV1(
        manifest, schedule, registry, wrong_external,
        registry.recursive_registry_commitment));
    auto wrong_recursive =
        registry.recursive_registry_commitment;
    wrong_recursive[0] =
        gf::Add(wrong_recursive[0], gf::Fp{1});
    BOOST_CHECK(!ut::ValidateProductionProgramRegistryV1(
        manifest, schedule, registry,
        registry.external_registry_commitment,
        wrong_recursive));
}

BOOST_AUTO_TEST_CASE(
    leaf_and_parent_statements_bind_program_schema_public_input_and_order)
{
    const auto manifest =
        ss::BuildProductionProofSiteManifest(
            ss::SelectedProductionProofSitePolicy());
    const auto schedule =
        sch::BuildProductionAggregationSchedule(manifest);
    const auto verifier =
        OneColumnProgram(
            rc::RCStage3RelationRole::CompositionLink);
    const auto registry =
        ut::BuildProductionProgramRegistryV1(
            manifest, schedule, Sources(manifest),
            verifier, verifier);
    BOOST_REQUIRE(
        !registry.external_registry_commitment.IsNull());

    ut::UniversalLeafSelectorV1 leaf;
    leaf.unified_root_seed = uint256{1};
    leaf.registry_external_commitment =
        registry.external_registry_commitment;
    leaf.registry_recursive_commitment =
        registry.recursive_registry_commitment;
    leaf.family_index = 0;
    leaf.global_leaf_site =
        schedule.families[0].first_leaf_site;
    leaf.family_local_site = 0;
    leaf.public_input_commitment = uint256{2};
    leaf.trace_commitment = NonzeroDigest(3);
    std::string why;
    const auto bound =
        ut::BindUniversalLeafStatementV1(
            manifest, schedule, registry, leaf, &why);
    BOOST_CHECK(
        bound.program_and_schema_resolved_from_registry);
    BOOST_CHECK(bound.manifest_schedule_and_site_bound);
    BOOST_CHECK(bound.public_inputs_bound);
    BOOST_CHECK(!bound.external_sha256d.IsNull());

    auto wrong_site = leaf;
    ++wrong_site.global_leaf_site;
    BOOST_CHECK(
        ut::BindUniversalLeafStatementV1(
            manifest, schedule, registry,
            wrong_site, &why)
            .external_sha256d.IsNull());
    auto changed_pi = leaf;
    changed_pi.public_input_commitment = uint256{4};
    const auto changed =
        ut::BindUniversalLeafStatementV1(
            manifest, schedule, registry,
            changed_pi, &why);
    BOOST_CHECK(
        changed.external_sha256d !=
        bound.external_sha256d);

    const auto work =
        sch::ProductionAggregationParentWorkItem(
            schedule, leaf.unified_root_seed, 0);
    BOOST_REQUIRE(work.has_value());
    ut::UniversalParentSelectorV1 parent;
    parent.unified_root_seed = leaf.unified_root_seed;
    parent.registry_external_commitment =
        registry.external_registry_commitment;
    parent.registry_recursive_commitment =
        registry.recursive_registry_commitment;
    parent.parent_ordinal = 0;
    parent.public_input_commitment = uint256{5};
    for (uint8_t i = 0; i < work->child_count; ++i) {
        parent.child_receipt_roots.push_back(
            NonzeroDigest(10 + i));
    }
    const auto parent_bound =
        ut::BindUniversalParentStatementV1(
            manifest, schedule, registry, parent, &why);
    BOOST_CHECK(!parent_bound.external_sha256d.IsNull());
    BOOST_REQUIRE_GT(parent.child_receipt_roots.size(), 1U);
    std::swap(
        parent.child_receipt_roots[0],
        parent.child_receipt_roots[1]);
    const auto reordered =
        ut::BindUniversalParentStatementV1(
            manifest, schedule, registry, parent, &why);
    BOOST_CHECK(
        reordered.external_sha256d !=
        parent_bound.external_sha256d);
    parent.child_receipt_roots.pop_back();
    BOOST_CHECK(
        ut::BindUniversalParentStatementV1(
            manifest, schedule, registry, parent, &why)
            .external_sha256d.IsNull());
}

BOOST_AUTO_TEST_CASE(
    relation_leaf_policy_screens_keep_rows18_selected_and_rows20_unmeasured)
{
    const auto rows18_policy =
        ss::SelectedProductionProofSitePolicy();
    const auto rows18 =
        ss::BuildProductionProofSiteManifest(
            rows18_policy);
    auto rows16_policy = rows18_policy;
    rows16_policy.relation_rows_per_site = 1U << 16;
    const auto rows16 =
        ss::BuildProductionProofSiteManifest(
            rows16_policy);
    auto rows20_policy = rows18_policy;
    rows20_policy.relation_rows_per_site = 1U << 20;
    const auto rows20 =
        ss::BuildProductionProofSiteManifest(
            rows20_policy);
    BOOST_REQUIRE(!rows16.commitment.IsNull());
    BOOST_REQUIRE(!rows18.commitment.IsNull());
    BOOST_REQUIRE(!rows20.commitment.IsNull());
    BOOST_CHECK_LT(
        rows18.total_proof_sites,
        rows16.total_proof_sites);
    BOOST_CHECK_LT(
        rows20.total_proof_sites,
        rows18.total_proof_sites);
    BOOST_CHECK(
        !sch::BuildProductionAggregationSchedule(rows18)
             .commitment.IsNull());
    BOOST_CHECK(
        sch::BuildProductionAggregationSchedule(rows16)
            .commitment.IsNull());
    BOOST_CHECK(
        sch::BuildProductionAggregationSchedule(rows20)
            .commitment.IsNull());
    BOOST_TEST_MESSAGE(
        "relation_rows=2^16 sites="
        << rows16.total_proof_sites
        << "; 2^18 sites=" << rows18.total_proof_sites
        << "; 2^20 sites=" << rows20.total_proof_sites);
    auto packed7_rows16_policy = rows16_policy;
    packed7_rows16_policy.hash_parallel_lanes = 7;
    const auto packed7_rows16 =
        ss::BuildProductionProofSiteManifest(
            packed7_rows16_policy);
    auto packed7_rows18_policy = rows18_policy;
    packed7_rows18_policy.hash_parallel_lanes = 7;
    const auto packed7_rows18 =
        ss::BuildProductionProofSiteManifest(
            packed7_rows18_policy);
    auto packed7_rows20_policy = rows20_policy;
    packed7_rows20_policy.hash_parallel_lanes = 7;
    const auto packed7_rows20 =
        ss::BuildProductionProofSiteManifest(
            packed7_rows20_policy);
    BOOST_REQUIRE(!packed7_rows16.commitment.IsNull());
    BOOST_REQUIRE(!packed7_rows18.commitment.IsNull());
    BOOST_REQUIRE(!packed7_rows20.commitment.IsNull());
    BOOST_TEST_MESSAGE(
        "packed7 relation_rows=2^16 sites="
        << packed7_rows16.total_proof_sites
        << "; 2^18 sites="
        << packed7_rows18.total_proof_sites
        << "; 2^20 sites="
        << packed7_rows20.total_proof_sites);
    BOOST_CHECK(
        !rows18.executable_backend_enforces_policy);
    BOOST_CHECK(
        !rows20.executable_backend_enforces_policy);
}

BOOST_AUTO_TEST_SUITE_END()
