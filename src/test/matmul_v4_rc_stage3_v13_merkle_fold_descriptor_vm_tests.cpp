// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_v13_merkle_fold_descriptor_vm.h>
#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>

#include <algorithm>

namespace vm =
    matmul::v4::rc::
        stage3_v13_merkle_fold_descriptor_vm;
namespace proof_abi =
    matmul::v4::rc::stage3_multirow_v11_proof_abi;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace merkle =
    matmul::v4::rc::stage3_v13_merkle_fold_parent;
using Fp3 = gf::Fp3;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_v13_merkle_fold_descriptor_vm_tests)

namespace {

uint256 Seed(uint8_t byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

proof_abi::SourceKeyV1 Key(uint32_t address)
{
    return {
        proof_abi::FieldKindV1::PublicFsSeed,
        address, 0, 0, 0, 0};
}

struct Fixture {
    std::array<vm::SourceShardV1,
               vm::kTapeShardsV1>
        shards{};
    proof_abi::DecodedV1 decoded{};
    merkle::TypedHashPlanV1 hash_plan{};
};

Fixture BuildFixture()
{
    Fixture out;
    matmul::v4::rc::alg_hash::State state{};
    uint64_t begin = 0;
    for (uint32_t shard = 0;
         shard < vm::kTapeShardsV1; ++shard) {
        auto& item = out.shards[shard];
        item.shard_ordinal = shard;
        item.global_ordinal_begin = begin;
        item.trace_rows = 2;
        item.global_ordinal_end =
            begin +
            uint64_t{item.trace_rows} *
                vm::kShardSourceSlotsV1;
        item.source_domain_root[0] =
            gf::FromU64(shard + 1);
        item.state_in = state;
        for (uint32_t lane = 0;
             lane < matmul::v4::rc::alg_hash::kAlgHashT;
             ++lane) {
            state[lane] =
                gf::FromU64(
                    100 + 17 * shard + lane);
        }
        item.state_out = state;
        item.last_shard =
            shard + 1 == vm::kTapeShardsV1;
        item.exact_contiguous_interval = true;
        item.state_boundary_bound = true;
        item.valid = true;
        begin = item.global_ordinal_end;
    }
    for (uint32_t address = 0; address < 5; ++address) {
        const uint32_t shard =
            std::min<uint32_t>(
                address, vm::kTapeShardsV1 - 1);
        const uint32_t slot =
            static_cast<uint32_t>(
                out.shards[shard].cells.size());
        out.shards[shard].cells.push_back({
            out.shards[shard].global_ordinal_begin +
                slot,
            address, Key(address), 0, slot});
        out.decoded.sources.push_back({
            address, Key(address),
            11U + 7U * address,
            proof_abi::OwnershipClassV1::
                ChildProofEnvelope});
    }
    out.decoded.canonical = true;
    out.decoded.complete = true;
    out.decoded.addresses_unique = true;
    out.decoded.semantic_keys_unique = true;

    constexpr uint32_t task_rows = 2;
    for (uint32_t row = 0; row < task_rows; ++row) {
        for (uint32_t lane = 0;
             lane < vm::kHashLanesV1; ++lane) {
            merkle::HashLaneExpressionV1 expression;
            expression.task_row = row;
            expression.lane = lane;
            expression.kind =
                merkle::HashLaneExpressionKindV1::
                    Constant;
            expression.constant =
                gf::FromU64_3(3 + row + lane);
            expression.resolved = true;
            if (row == 0 && lane == 0) {
                expression.kind =
                    merkle::HashLaneExpressionKindV1::
                        AbiU32;
                expression.source_addresses[0] = 0;
            }
            if (row == 1 && lane == 0) {
                expression.kind =
                    merkle::HashLaneExpressionKindV1::
                        PriorOutputPlusAbiU32;
                expression.source_addresses[0] = 1;
                expression.prior_task_row = 0;
                expression.prior_output_lane = 0;
            }
            if (row == 1 && lane == 1) {
                expression.kind =
                    merkle::HashLaneExpressionKindV1::
                        DerivedNextIndex;
                expression.selector_address = 4;
                expression.selector_bit = 1;
                expression.selector_is_derived_next = true;
            }
            out.hash_plan.inputs.push_back(expression);
        }
    }
    out.hash_plan.outputs.push_back({
        1, 0, {2, 3}});
    out.hash_plan.task_rows = task_rows;
    out.hash_plan.resolved_input_lanes =
        task_rows * vm::kHashLanesV1;
    out.hash_plan.expected_input_lanes =
        out.hash_plan.resolved_input_lanes;
    out.hash_plan.output_aliases = 1;
    out.hash_plan.expected_output_aliases = 1;
    out.hash_plan.every_input_lane_resolved = true;
    out.hash_plan.every_prior_precedes_consumer = true;
    out.hash_plan.every_source_address_canonical = true;
    out.hash_plan.lane_ownership_unique = true;
    out.hash_plan.output_inventory_complete = true;
    out.hash_plan.valid = true;
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    cross_shard_v3_descriptor_proves_and_rejects_forgery)
{
    const Fixture fixture = BuildFixture();
    vm::PlanV1 plan;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        vm::BuildHashPlanV1(
            fixture.shards,
            Seed(0x55),
            UINT64_C(0x53484152445f5631),
            16, 64, 8, fixture.hash_plan,
            plan, &why),
        why);
    BOOST_CHECK_EQUAL(plan.manifest_reads, 5U);
    BOOST_CHECK(plan.exact_manifest_count);

    aq::AirConstraintSystem<Fp3> cs;
    cs.n_rows = 16;
    std::vector<std::vector<Fp3>> columns;
    vm::DeterministicAttachmentV1 deterministic;
    BOOST_REQUIRE_MESSAGE(
        vm::AppendDeterministicWitnessV1(
            plan, fixture.decoded,
            cs, columns, deterministic, &why),
        why);
    BOOST_CHECK_EQUAL(cs.n_columns, 511U);
    BOOST_CHECK(deterministic.v3_scalar_challenges);
    BOOST_CHECK(deterministic.degree_caps_closed);
    const auto deterministic_cs = cs;
    const auto deterministic_columns = columns;

    vm::ChallengesV1 rejected_challenges;
    auto substituted_root_plan = plan;
    substituted_root_plan.proof_tape_root[0] =
        gf::Add(
            substituted_root_plan
                .proof_tape_root[0],
            gf::FromU64(1));
    BOOST_CHECK(
        !vm::DeriveChallengesV1(
            substituted_root_plan,
            rejected_challenges, &why));
    auto reordered_plan = plan;
    std::swap(
        reordered_plan.source_shards[0],
        reordered_plan.source_shards[1]);
    BOOST_CHECK(
        !vm::DeriveChallengesV1(
            reordered_plan,
            rejected_challenges, &why));
    auto duplicate_plan = plan;
    duplicate_plan.source_shards[0]
        .cells.push_back(
            duplicate_plan.source_shards[0]
                .cells.front());
    BOOST_CHECK(
        !vm::DeriveChallengesV1(
            duplicate_plan,
            rejected_challenges, &why));
    vm::FinalizationV1 final;
    BOOST_REQUIRE_MESSAGE(
        vm::AppendFinalWitnessV1(
            deterministic, cs, columns,
            final, &why),
        why);
    BOOST_CHECK_EQUAL(cs.n_columns, 730U);
    BOOST_CHECK(final.v3_scalar_challenges);
    BOOST_CHECK(final.degree_caps_closed);
    BOOST_CHECK(final.receipt.full_state_bound);
    uint32_t max_everywhere_degree = 0;
    uint32_t max_transition_degree = 0;
    uint32_t max_boundary_degree = 0;
    for (const auto& constraint : cs.constraints) {
        switch (constraint.kind) {
        case aq::AirKind::kEverywhere:
            max_everywhere_degree =
                std::max(
                    max_everywhere_degree,
                    constraint.alg_degree);
            break;
        case aq::AirKind::kTransition:
            max_transition_degree =
                std::max(
                    max_transition_degree,
                    constraint.alg_degree);
            break;
        default:
            max_boundary_degree =
                std::max(
                    max_boundary_degree,
                    constraint.alg_degree);
            break;
        }
    }
    BOOST_CHECK_LE(max_everywhere_degree, 3U);
    BOOST_CHECK_LE(max_transition_degree, 3U);
    BOOST_CHECK_LE(max_boundary_degree, 2U);
    auto production_shape = cs;
    production_shape.n_rows = UINT32_C(1) << 19;
    const uint64_t production_degree =
        production_shape.MaxComposedDegreeBound();
    const uint32_t production_quotient =
        production_shape.QuotientLen();
    const uint32_t production_n_coeffs =
        matmul::v4::rc::FriNextPow2(
            std::max(
                production_shape.n_rows,
                production_quotient));
    const uint32_t production_lde =
        production_n_coeffs *
        matmul::v4::rc::kRCFriBlowup;
    BOOST_CHECK_EQUAL(
        production_degree, UINT64_C(1572861));
    BOOST_CHECK_EQUAL(
        production_quotient, UINT32_C(1048574));
    BOOST_CHECK_EQUAL(
        production_n_coeffs, UINT32_C(1048576));
    BOOST_CHECK_EQUAL(
        production_lde, UINT32_C(16777216));
    const uint256 proof_seed =
        vm::ComputePublicTapeChallengeSeedV1(
            plan.proof_tape_root,
            plan.source_inventory_root);
    BOOST_REQUIRE(!proof_seed.IsNull());
    for (uint32_t lane = 0;
         lane < vm::kLookupLanesV1; ++lane) {
        const uint256 gamma_digest =
            aq::AirChallengeDigest(
                proof_seed,
                "stage3.v14_tape_root.source_gamma",
                {plan.source_inventory_root},
                {lane});
        const uint256 alpha_digest =
            aq::AirChallengeDigest(
                proof_seed,
                "stage3.v14_tape_root.source_alpha",
                {plan.source_inventory_root},
                {lane});
        BOOST_CHECK(gf::Eq(
            final.challenges.gamma[lane],
            gf::FromChallengeBytes3(
                gamma_digest.data())));
        BOOST_CHECK(gf::Eq(
            final.challenges.alpha[lane],
            gf::FromChallengeBytes3(
                alpha_digest.data())));
    }
    BOOST_CHECK_EQUAL(
        vm::CountViolationsV1(cs, columns), 0U);

    const auto proved =
        aq::AirQuotientProveRows(
            cs, columns, proof_seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRows(
            cs, proved.proof,
            proof_seed, &why),
        why);
    matmul::v4::rc::AirQuotientProofAlg
        canonical_proof;
    canonical_proof.batch = proved.proof.batch;
    canonical_proof.next_openings =
        proved.proof.next_openings;
    canonical_proof.trace_commit =
        proved.proof.trace_commit;
    std::vector<unsigned char> proof_bytes;
    BOOST_REQUIRE_MESSAGE(
        matmul::v4::rc::
            SerializeAirQuotientProofAlg(
                canonical_proof,
                proof_bytes, &why),
        why);
    BOOST_REQUIRE(!proof_bytes.empty());
    const auto decoded =
        matmul::v4::rc::
            DeserializeAirQuotientProofAlg(
                proof_bytes, &why);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_REQUIRE_MESSAGE(
        (aq::AirQuotientVerify<
            Fp3,
            aq::AirFriBackendAlg<Fp3>>(
                cs, *decoded, proof_seed,
                &why)),
        why);
    BOOST_TEST_MESSAGE(
        "descriptor proof shape W=" << cs.n_columns
        << " N=" << cs.n_rows
        << " n_coeffs=" << proved.proof.batch.n_coeffs
        << " bytes=" << proof_bytes.size());

    auto proof_tamper = proved.proof;
    BOOST_REQUIRE(!proof_tamper.batch.queries.empty());
    BOOST_REQUIRE(
        !proof_tamper.batch.queries[0]
             .row.values.empty());
    proof_tamper.batch.queries[0]
        .row.values[0] =
        gf::Add(
            proof_tamper.batch.queries[0]
                .row.values[0],
            Fp3::One());
    BOOST_CHECK(
        !aq::AirQuotientVerifyRows(
            cs, proof_tamper,
            proof_seed, &why));

    // Named proof-owned cells are authenticated in the exact ordered row
    // groups.  These are proof-level opening forgeries, not witness-count
    // diagnostics.
    const auto rejects_opening_cell =
        [&](uint32_t offset) {
            auto forged = proved.proof;
            BOOST_REQUIRE_LT(
                offset,
                forged.batch.queries[0]
                    .row
                    .values.size());
            forged.batch.queries[0]
                .row.values[offset] =
                    gf::Add(
                        forged.batch.queries[0]
                            .row
                            .values[offset],
                        Fp3::One());
            return
                !aq::AirQuotientVerifyRows(
                    cs, forged, proof_seed,
                    &why);
        };
    BOOST_CHECK(rejects_opening_cell(
        deterministic.layout.SourceValue(0)));
    BOOST_CHECK(rejects_opening_cell(
        deterministic.layout
            .HashSourceSelectorBit(0)));
    BOOST_CHECK(rejects_opening_cell(
        deterministic.layout
            .HashExpectedInput(0)));
    BOOST_CHECK(rejects_opening_cell(
        deterministic.layout.SourceValue(
            vm::kHashOutputSlotBaseV1)));
    BOOST_CHECK(rejects_opening_cell(
        final.tape_terminal_column[0]));

    // Exact order/coverage and address+shard tags are verifier-owned.
    auto wrong_coverage_cs = cs;
    const uint32_t coverage =
        deterministic.layout.CoverageRoot(0);
    const auto coverage_it = std::find_if(
        wrong_coverage_cs.preprocessed.begin(),
        wrong_coverage_cs.preprocessed.end(),
        [coverage](const auto& item) {
            return item.first == coverage;
        });
    BOOST_REQUIRE(
        coverage_it !=
        wrong_coverage_cs.preprocessed.end());
    coverage_it->second[0] =
        gf::Add(coverage_it->second[0], Fp3::One());
    BOOST_CHECK(
        !aq::AirQuotientVerifyRows(
            wrong_coverage_cs, proved.proof,
            proof_seed, &why));

    // Wrong producer time/lane changes the prior-memory tuple.
    auto wrong_prior_cs = cs;
    const uint32_t prior_task =
        deterministic.layout.HashPriorTask(0);
    const auto prior_it = std::find_if(
        wrong_prior_cs.preprocessed.begin(),
        wrong_prior_cs.preprocessed.end(),
        [prior_task](const auto& item) {
            return item.first == prior_task;
        });
    BOOST_REQUIRE(
        prior_it != wrong_prior_cs.preprocessed.end());
    prior_it->second[1] =
        gf::Add(prior_it->second[1], Fp3::One());
    BOOST_CHECK(
        !aq::AirQuotientVerifyRows(
            wrong_prior_cs, proved.proof,
            proof_seed, &why));

    // A cross-shard relabel changes address + 2^32*shard.
    auto wrong_shard_cs = cs;
    const uint32_t address_tag =
        deterministic.layout.SourceAddressTag(0);
    const auto shard_it = std::find_if(
        wrong_shard_cs.preprocessed.begin(),
        wrong_shard_cs.preprocessed.end(),
        [address_tag](const auto& item) {
            return item.first == address_tag;
        });
    BOOST_REQUIRE(
        shard_it != wrong_shard_cs.preprocessed.end());
    shard_it->second[0] =
        gf::Add(
            shard_it->second[0],
            gf::FromU64_3(uint64_t{1} << 32));
    BOOST_CHECK(
        !aq::AirQuotientVerifyRows(
            wrong_shard_cs, proved.proof,
            proof_seed, &why));

    // A different hidden capacity lane changes the verifier-owned schedule
    // root even when the four public tape-root lanes remain byte-for-byte
    // equal.
    auto capacity_shards = fixture.shards;
    capacity_shards[2].state_out[9] =
        gf::Add(
            capacity_shards[2].state_out[9],
            gf::FromU64(1));
    capacity_shards[3].state_in[9] =
        capacity_shards[2].state_out[9];
    vm::PlanV1 capacity_plan;
    BOOST_REQUIRE(
        vm::BuildHashPlanV1(
            capacity_shards, Seed(0x55),
            UINT64_C(0x53484152445f5631),
            16, 64, 8, fixture.hash_plan,
            capacity_plan, &why));
    vm::DeterministicAttachmentV1 capacity_det;
    aq::AirConstraintSystem<Fp3> capacity_cs;
    capacity_cs.n_rows = 16;
    BOOST_REQUIRE(
        vm::AppendDeterministicConstraintSystemV1(
            capacity_plan, capacity_cs,
            capacity_det, &why));
    vm::FinalizationV1 capacity_final;
    BOOST_REQUIRE(
        vm::AppendFinalConstraintSystemV1(
            capacity_det, capacity_cs,
            capacity_final, &why));
    BOOST_CHECK(
        !aq::AirQuotientVerifyRows(
            capacity_cs, proved.proof,
            proof_seed, &why));

    // A valid alternate public tape root derives a different challenge seed;
    // the original proof cannot be transplanted to that statement.
    auto alternate_root_shards = fixture.shards;
    alternate_root_shards.back().state_out[0] =
        gf::Add(
            alternate_root_shards.back()
                .state_out[0],
            gf::FromU64(1));
    vm::PlanV1 alternate_root_plan;
    BOOST_REQUIRE(
        vm::BuildHashPlanV1(
            alternate_root_shards, Seed(0x55),
            UINT64_C(0x53484152445f5631),
            16, 64, 8, fixture.hash_plan,
            alternate_root_plan, &why));
    aq::AirConstraintSystem<Fp3>
        alternate_root_cs;
    alternate_root_cs.n_rows = 16;
    vm::DeterministicAttachmentV1
        alternate_root_det;
    BOOST_REQUIRE(
        vm::AppendDeterministicConstraintSystemV1(
            alternate_root_plan,
            alternate_root_cs,
            alternate_root_det, &why));
    vm::FinalizationV1 alternate_root_final;
    BOOST_REQUIRE(
        vm::AppendFinalConstraintSystemV1(
            alternate_root_det,
            alternate_root_cs,
            alternate_root_final, &why));
    const uint256 alternate_seed =
        vm::ComputePublicTapeChallengeSeedV1(
            alternate_root_plan.proof_tape_root,
            alternate_root_plan
                .source_inventory_root);
    BOOST_CHECK(alternate_seed != proof_seed);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRows(
            alternate_root_cs, proved.proof,
            alternate_seed, &why));

    // A value in an inactive source slot violates the canonical-zero
    // constraint; there is no free witness padding channel.
    auto unused = columns;
    unused[
        deterministic.layout.SourceValue(63)][15] =
        Fp3::One();
    BOOST_CHECK_GT(
        vm::CountViolationsV1(cs, unused), 0U);

    // A source value cannot be changed while retaining the public tape root:
    // all descriptor auxiliaries are deterministic ordinary columns, and the
    // rebuilt relation is nonzero.
    auto source_mutated = deterministic_columns;
    source_mutated[
        deterministic.layout.SourceValue(0)][0] =
        gf::Add(
            source_mutated[
                deterministic.layout.SourceValue(0)][0],
            Fp3::One());
    auto source_cs = deterministic_cs;
    vm::FinalizationV1 source_final;
    BOOST_REQUIRE(
        vm::AppendFinalWitnessV1(
            deterministic, source_cs,
            source_mutated, source_final,
            &why));
    BOOST_CHECK_GT(
        vm::CountViolationsV1(
            source_cs, source_mutated),
        0U);
}

BOOST_AUTO_TEST_SUITE_END()
