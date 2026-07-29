// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_v13_v14_abi_logup_join.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace join =
    matmul::v4::rc::stage3_v13_v14_abi_logup_join;
namespace aq = matmul::v4::rc::air_quotient;
namespace bridge =
    matmul::v4::rc::stage3_safe_v12_recursive_bridge;
namespace gf = matmul::v4::rc::gkr_field;
namespace occurrence =
    matmul::v4::rc::stage3_v13_occurrence_manifest;
namespace tape =
    matmul::v4::rc::stage3_multirow_v13_proof_tape_air;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_v13_v14_abi_logup_join_tests)

namespace {

uint256 Root(uint8_t tag)
{
    uint256 out;
    for (uint32_t index = 0;
         index < out.size(); ++index) {
        out.begin()[index] =
            static_cast<unsigned char>(
                tag + 17 * index);
    }
    return out;
}

tape::PublicShapeV1 ToyShape()
{
    tape::PublicShapeV1 out;
    out.trace_rows = 2;
    out.trace_columns = 2;
    out.quotient_len = 2;
    out.n_coeffs = 2;
    out.base_column_indices = {0};
    return out;
}

tape::PublicBindingV1 ToyBinding()
{
    tape::PublicBindingV1 out;
    out.program_root = Root(0x11);
    out.statement_root = Root(0x22);
    out.public_fs_seed = Root(0x33);
    out.proof_wire_root = Root(0x44);
    out.tape_root = {
        gf::FromU64(1),
        gf::FromU64(2),
        gf::FromU64(3),
        gf::FromU64(4),
    };
    return out;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) out <<= 1;
    return out;
}

uint32_t SourceWord(uint32_t address)
{
    return UINT32_C(0x13579bdf) ^
        (address * UINT32_C(0x9e3779b9));
}

struct Fixture {
    tape::PublicShapeV1 shape{ToyShape()};
    tape::PublicBindingV1 binding{ToyBinding()};
    std::vector<bridge::TypedSafeEventProgramV13>
        program;
    occurrence::ManifestV1 manifest;
    tape::ScheduleV1 tape_schedule;
    join::PlanV1 plan;
    aq::AirConstraintSystem<gf::Fp3> resident_cs;
    std::vector<std::vector<gf::Fp3>>
        resident_columns;
    std::vector<uint32_t> base_indices;
    uint256 proof_seed{Root(0x91)};

    Fixture()
    {
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            occurrence::BuildCanonicalTypedProgramV1(
                shape, program, &why),
            why);
        BOOST_REQUIRE_MESSAGE(
            occurrence::
                BuildCanonicalOccurrenceManifestV1(
                    shape, program, manifest,
                    &why),
            why);
        tape_schedule =
            tape::BuildScheduleV1(shape, binding);
        BOOST_REQUIRE_MESSAGE(
            tape_schedule.valid,
            tape_schedule.note);

        uint32_t required_rows =
            tape_schedule.trace_rows;
        for (const auto& item :
             manifest.byte_occurrences) {
            if (item.canonical_abi_source) {
                required_rows = std::max(
                    required_rows,
                    item.consumer_row + 1);
            }
        }
        const uint32_t parent_rows =
            NextPowerOfTwo(required_rows);
        const uint32_t tape_offset = 0;
        const uint32_t v14_offset =
            tape::CanonicalLayoutV1().End();
        BOOST_REQUIRE_MESSAGE(
            join::BuildCanonicalPlanV1(
                shape, binding, program,
                manifest, parent_rows,
                tape_offset, v14_offset,
                plan, &why),
            why);

        resident_cs.n_rows = parent_rows;
        resident_cs.n_columns =
            v14_offset +
            bridge::
                TypedSafeDirectParentLayoutV14{}
                    .end;
        resident_columns.assign(
            resident_cs.n_columns,
            std::vector<gf::Fp3>(
                parent_rows, gf::Fp3::Zero()));

        std::set<uint32_t> base;
        for (const auto& source : plan.sources) {
            const uint32_t value =
                SourceWord(source.abi_address);
            resident_columns[
                source.address.column]
                [source.address.row] =
                    gf::FromU64_3(
                        source.abi_address);
            resident_columns[
                source.value.column]
                [source.value.row] =
                    gf::FromU64_3(value);
            base.insert(source.address.column);
            base.insert(source.value.column);
            for (uint32_t bit = 0;
                 bit < 8; ++bit) {
                resident_columns[
                    source.byte_bits[bit].column]
                    [source.byte_bits[bit].row] =
                        gf::FromU64_3(
                            (value >>
                             (8 *
                                  source.byte_in_word +
                              bit)) &
                            1U);
                base.insert(
                    source.byte_bits[bit].column);
            }
        }

        using Position =
            std::pair<uint32_t, uint32_t>;
        std::map<Position, uint32_t> message_words;
        std::map<
            std::pair<Position, uint8_t>,
            uint8_t> assigned_bytes;
        for (const auto& consumer :
             plan.consumers) {
            const uint8_t source_byte =
                static_cast<uint8_t>(
                    SourceWord(
                        consumer.abi_address) >>
                    (8 *
                     consumer.byte_in_abi_word));
            const Position position{
                consumer.message.row,
                consumer.message.column};
            const auto byte_position =
                std::make_pair(
                    position,
                    consumer.byte_in_message_word);
            const auto [it, inserted] =
                assigned_bytes.emplace(
                    byte_position, source_byte);
            BOOST_REQUIRE_MESSAGE(
                inserted ||
                    it->second == source_byte,
                "canonical manifest aliases one "
                "message byte to unequal ABI bytes");
            uint32_t& word =
                message_words[position];
            const uint32_t shift =
                8 *
                consumer.byte_in_message_word;
            word &= ~(UINT32_C(0xff) << shift);
            word |=
                uint32_t{source_byte} << shift;
            base.insert(consumer.message.column);
        }
        for (const auto& [position, value] :
             message_words) {
            resident_columns[position.second]
                [position.first] =
                    gf::FromU64_3(value);
        }
        base_indices.assign(
            base.begin(), base.end());
        BOOST_REQUIRE(!base_indices.empty());
    }
};

Fixture& Honest()
{
    static Fixture out;
    return out;
}

bool Verify(
    const Fixture& fixture,
    const join::PlanV1& plan,
    const join::ProofV1& proof,
    std::string* why)
{
    return join::VerifyV1(
        fixture.shape, fixture.binding,
        fixture.program, fixture.manifest,
        plan, fixture.proof_seed,
        fixture.resident_cs,
        fixture.base_indices,
        proof, why);
}

size_t BaseOpeningPosition(
    const std::vector<uint32_t>& base_indices,
    uint32_t column)
{
    const auto it = std::lower_bound(
        base_indices.begin(),
        base_indices.end(), column);
    BOOST_REQUIRE(
        it != base_indices.end() &&
        *it == column);
    return static_cast<size_t>(
        it - base_indices.begin());
}

} // namespace

BOOST_AUTO_TEST_CASE(
    canonical_plan_pins_every_address_multiplicity_and_cell)
{
    const auto& fixture = Honest();
    const auto& plan = fixture.plan;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        join::ValidateCanonicalPlanV1(
            fixture.shape, fixture.binding,
            fixture.program, fixture.manifest,
            plan, &why),
        why);
    BOOST_CHECK(plan.valid);
    BOOST_CHECK(plan.exact_manifest_rebuild);
    BOOST_CHECK(plan.exact_physical_cell_map);
    BOOST_CHECK(
        plan.exact_multiplicity_accounting);
    BOOST_CHECK_EQUAL(
        plan.unique_source_bytes,
        plan.sources.size());
    BOOST_CHECK_EQUAL(
        plan.consumer_occurrences,
        plan.consumers.size());
    BOOST_CHECK_EQUAL(
        plan.source_multiplicity_sum,
        plan.consumer_occurrences);
    BOOST_CHECK_LT(
        plan.unique_source_bytes,
        plan.consumer_occurrences);
    BOOST_TEST_MESSAGE(
        "ABI LogUp shape: rows=" <<
        plan.parent_rows <<
        " unique_source_bytes=" <<
        plan.unique_source_bytes <<
        " consumer_occurrences=" <<
        plan.consumer_occurrences <<
        " resident_columns=" <<
        fixture.resident_cs.n_columns <<
        " committed_parent_columns=" <<
        fixture.base_indices.size());

    {
        auto changed = plan;
        ++changed.sources[0].multiplicity;
        ++changed.source_multiplicity_sum;
        BOOST_CHECK(
            !join::ValidateCanonicalPlanV1(
                fixture.shape, fixture.binding,
                fixture.program,
                fixture.manifest,
                changed, &why));
    }
    {
        auto changed = plan;
        ++changed.sources[0].address.column;
        BOOST_CHECK(
            !join::ValidateCanonicalPlanV1(
                fixture.shape, fixture.binding,
                fixture.program,
                fixture.manifest,
                changed, &why));
    }
    {
        auto changed = plan;
        changed.consumers[0].abi_address ^= 1U;
        BOOST_CHECK(
            !join::ValidateCanonicalPlanV1(
                fixture.shape, fixture.binding,
                fixture.program,
                fixture.manifest,
                changed, &why));
    }
    {
        auto changed = plan;
        ++changed.consumers[0].message.column;
        BOOST_CHECK(
            !join::ValidateCanonicalPlanV1(
                fixture.shape, fixture.binding,
                fixture.program,
                fixture.manifest,
                changed, &why));
    }

    join::ChallengesV1 first;
    join::ChallengesV1 second;
    BOOST_REQUIRE(
        join::DeriveChallengesV1(
            plan, fixture.proof_seed,
            Root(0xa1), first, &why));
    BOOST_REQUIRE(
        join::DeriveChallengesV1(
            plan, fixture.proof_seed,
            Root(0xa2), second, &why));
    BOOST_CHECK(!(first == second));
}

BOOST_AUTO_TEST_CASE(
    rational_identity_rejects_address_and_value_transplants)
{
    const auto& fixture = Honest();
    std::string why;
    join::ProductV1 honest;
    BOOST_REQUIRE_MESSAGE(
        join::BuildProductV1(
            fixture.plan, fixture.proof_seed,
            fixture.resident_cs,
            fixture.resident_columns,
            fixture.base_indices,
            honest, &why),
        why);
    BOOST_CHECK(honest.valid);
    BOOST_CHECK_EQUAL(honest.violations, 0U);
    BOOST_CHECK(
        honest.actual_tape_cells_referenced);
    BOOST_CHECK(
        honest.actual_v14_message_cells_referenced);
    BOOST_CHECK(
        honest.consumer_u32_decomposition_constrained);
    BOOST_CHECK(
        honest.exact_schedule_multiplicities_preprocessed);
    BOOST_CHECK(honest.challenges_after_complete_r0);
    BOOST_CHECK(honest.cs.preprocessed_pin_ood);
    BOOST_CHECK(
        honest.dual_fp3_rational_identity_constrained);
    BOOST_CHECK(
        honest.terminal_cancellation_constrained);
    BOOST_CHECK(
        !honest.source_and_consumer_verifiers_resident);
    BOOST_CHECK(!honest.recursively_consumed);
    BOOST_CHECK(!honest.recursive_authority_ready);

    // The reusable composition API produces the same relation while delaying
    // every challenge-dependent column until the wider parent commits R0.
    {
        auto split_cs = fixture.resident_cs;
        auto split_columns =
            fixture.resident_columns;
        join::EmbeddedBaseV1 base;
        BOOST_REQUIRE_MESSAGE(
            join::AppendEmbeddedBaseProductV1(
                fixture.plan,
                fixture.base_indices,
                split_cs, split_columns,
                base, &why),
            why);
        BOOST_CHECK(base.valid);
        BOOST_CHECK(base.challenge_columns_absent);
        BOOST_CHECK_EQUAL(
            split_cs.n_columns,
            base.layout.dependent_base);
        const auto global_r0 =
            aq::AirQuotientBuildTwoEpochBaseRowSession(
                split_cs, split_columns,
                base.complete_r0_base_column_indices);
        BOOST_REQUIRE_MESSAGE(
            global_r0.valid, global_r0.note);

        join::EmbeddedFinalizationV1 final;
        BOOST_REQUIRE_MESSAGE(
            join::AppendEmbeddedFinalProductV1(
                fixture.plan, base,
                fixture.proof_seed,
                global_r0,
                split_cs, split_columns,
                final, &why),
            why);
        BOOST_CHECK(final.valid);
        BOOST_CHECK(final.exact_global_r0_indices);
        BOOST_CHECK(
            final.challenges_derived_after_global_r0);
        BOOST_CHECK(
            final.dual_fp3_rational_identity_constrained);
        BOOST_CHECK_EQUAL(
            split_cs.n_columns,
            honest.cs.n_columns);
        BOOST_CHECK_EQUAL(
            split_cs.constraints.size(),
            honest.cs.constraints.size());
        BOOST_CHECK(
            final.challenges == honest.challenges);
        BOOST_CHECK_EQUAL(
            join::CountViolationsV1(
                split_cs, split_columns),
            0U);

        // Verifier reconstruction follows the same two epochs and contains
        // no witness or prover-selected physical cell map.
        auto verifier_cs = fixture.resident_cs;
        join::EmbeddedBaseV1 verifier_base;
        BOOST_REQUIRE_MESSAGE(
            join::AppendEmbeddedBaseConstraintSystemV1(
                fixture.plan,
                fixture.base_indices,
                verifier_cs,
                verifier_base, &why),
            why);
        join::EmbeddedFinalizationV1 verifier_final;
        BOOST_REQUIRE_MESSAGE(
            join::AppendEmbeddedFinalConstraintSystemV1(
                fixture.plan, verifier_base,
                fixture.proof_seed,
                global_r0.base_row_commitment,
                global_r0.base_column_indices,
                verifier_cs,
                verifier_final, &why),
            why);
        BOOST_CHECK(
            verifier_final.challenges ==
            final.challenges);
        BOOST_CHECK_EQUAL(
            verifier_cs.n_columns,
            split_cs.n_columns);
        BOOST_CHECK_EQUAL(
            verifier_cs.constraints.size(),
            split_cs.constraints.size());

        // A child-local R0 that omits the ABI base schedule cannot finalize
        // the embedded relation.
        const auto private_r0 =
            aq::AirQuotientBuildTwoEpochBaseRowSession(
                fixture.resident_cs,
                fixture.resident_columns,
                fixture.base_indices);
        BOOST_REQUIRE(private_r0.valid);
        auto rejected_cs = fixture.resident_cs;
        auto rejected_columns =
            fixture.resident_columns;
        join::EmbeddedBaseV1 rejected_base;
        BOOST_REQUIRE(
            join::AppendEmbeddedBaseProductV1(
                fixture.plan,
                fixture.base_indices,
                rejected_cs,
                rejected_columns,
                rejected_base, &why));
        join::EmbeddedFinalizationV1 rejected;
        BOOST_CHECK(
            !join::AppendEmbeddedFinalProductV1(
                fixture.plan, rejected_base,
                fixture.proof_seed,
                private_r0,
                rejected_cs,
                rejected_columns,
                rejected, &why));
        BOOST_CHECK_MESSAGE(
            why.find(
                "embedded_final_product_parent") !=
                std::string::npos,
            why);

        // A sibling/base column may follow this ABI base inside the same R0.
        // The dependent suffix relocates after it while retaining the exact
        // physical references of this component.
        auto sibling_cs = fixture.resident_cs;
        auto sibling_columns =
            fixture.resident_columns;
        join::EmbeddedBaseV1 sibling_base;
        BOOST_REQUIRE(
            join::AppendEmbeddedBaseProductV1(
                fixture.plan,
                fixture.base_indices,
                sibling_cs,
                sibling_columns,
                sibling_base, &why));
        const uint32_t sibling_column =
            sibling_cs.n_columns++;
        sibling_columns.push_back(
            std::vector<gf::Fp3>(
                sibling_cs.n_rows,
                gf::Fp3::Zero()));
        auto sibling_r0_indices =
            sibling_base
                .complete_r0_base_column_indices;
        sibling_r0_indices.push_back(
            sibling_column);
        const auto sibling_r0 =
            aq::AirQuotientBuildTwoEpochBaseRowSession(
                sibling_cs, sibling_columns,
                sibling_r0_indices);
        BOOST_REQUIRE(sibling_r0.valid);
        join::EmbeddedFinalizationV1
            sibling_final;
        BOOST_REQUIRE_MESSAGE(
            join::AppendEmbeddedFinalProductV1(
                fixture.plan, sibling_base,
                fixture.proof_seed,
                sibling_r0,
                sibling_cs,
                sibling_columns,
                sibling_final, &why),
            why);
        BOOST_CHECK_EQUAL(
            sibling_final.dependent_column_base,
            sibling_column + 1);
        BOOST_CHECK_EQUAL(
            join::CountViolationsV1(
                sibling_cs, sibling_columns),
            0U);
    }

    {
        auto changed = fixture.resident_columns;
        const auto& source =
            fixture.plan.sources.front();
        changed[source.address.column]
            [source.address.row] =
                gf::Add(
                    changed[source.address.column]
                        [source.address.row],
                    gf::Fp3::One());
        join::ProductV1 rejected;
        BOOST_CHECK(
            !join::BuildProductV1(
                fixture.plan,
                fixture.proof_seed,
                fixture.resident_cs,
                changed,
                fixture.base_indices,
                rejected, &why));
    }
    {
        auto changed = fixture.resident_columns;
        const auto& source =
            fixture.plan.sources.front();
        const uint32_t old_word =
            SourceWord(source.abi_address);
        const uint32_t changed_word =
            old_word ^
            (UINT32_C(1) <<
             (8 * source.byte_in_word));
        changed[source.value.column]
            [source.value.row] =
                gf::FromU64_3(changed_word);
        const auto tape_layout =
            tape::CanonicalLayoutV1();
        const uint32_t record_slot =
            source.lookup_slot / 4;
        for (uint32_t bit = 0;
             bit < 32; ++bit) {
            changed[
                fixture.plan.tape_column_offset +
                tape_layout.Bit(
                    record_slot, bit)]
                [source.value.row] =
                    gf::FromU64_3(
                        (changed_word >> bit) & 1U);
        }
        join::ProductV1 rejected;
        BOOST_CHECK(
            !join::BuildProductV1(
                fixture.plan,
                fixture.proof_seed,
                fixture.resident_cs,
                changed,
                fixture.base_indices,
                rejected, &why));
    }
    {
        auto changed = fixture.resident_columns;
        const auto& consumer =
            fixture.plan.consumers.front();
        changed[consumer.message.column]
            [consumer.message.row] =
                gf::Add(
                    changed[consumer.message.column]
                        [consumer.message.row],
                    gf::FromU64_3(
                        UINT64_C(1) <<
                        (8 *
                         consumer
                             .byte_in_message_word)));
        join::ProductV1 rejected;
        BOOST_CHECK(
            !join::BuildProductV1(
                fixture.plan,
                fixture.proof_seed,
                fixture.resident_cs,
                changed,
                fixture.base_indices,
                rejected, &why));
    }
}

BOOST_AUTO_TEST_CASE(
    proof_level_opening_and_schedule_transplants_reject)
{
    if (std::getenv(
            "BTX_RUN_V13_V14_ABI_LOGUP_PROOF") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_V13_V14_ABI_LOGUP_PROOF=1 "
            "for the focused Q192 proof-level canary");
        return;
    }
    const auto& fixture = Honest();
    std::string why;
    join::ProductV1 product;
    BOOST_REQUIRE_MESSAGE(
        join::BuildProductV1(
            fixture.plan, fixture.proof_seed,
            fixture.resident_cs,
            fixture.resident_columns,
            fixture.base_indices,
            product, &why),
        why);
    join::ProofV1 proof;
    BOOST_REQUIRE_MESSAGE(
        join::ProveV1(
            product, fixture.proof_seed,
            proof, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        Verify(
            fixture, fixture.plan,
            proof, &why),
        why);

    // Proof-level actual tape Value-column opening transplant:
    // rejected by the unmodified row-Merkle/FRI verifier.
    {
        auto changed = proof;
        BOOST_REQUIRE(
            !changed.proof.batch.queries.empty());
        BOOST_REQUIRE(
            !changed.proof.batch.queries[0]
                 .group_rows.empty());
        auto& values =
            changed.proof.batch.queries[0]
                .group_rows[0].values;
        const size_t position =
            BaseOpeningPosition(
                product.r0_base_column_indices,
                fixture.plan.sources.front()
                    .value.column);
        BOOST_REQUIRE_LT(position, values.size());
        values[position] =
            gf::Add(
                values[position],
                gf::Fp3::One());
        BOOST_CHECK(
            !Verify(
                fixture, fixture.plan,
                changed, &why));
        BOOST_CHECK_MESSAGE(
            why.find("verify_air:") !=
                std::string::npos,
            why);
    }

    // Proof-level actual V14 Message-column opening transplant.
    {
        auto changed = proof;
        auto& values =
            changed.proof.batch.queries[0]
                .group_rows[0].values;
        const size_t position =
            BaseOpeningPosition(
                product.r0_base_column_indices,
                fixture.plan.consumers.front()
                    .message.column);
        BOOST_REQUIRE_LT(position, values.size());
        values[position] =
            gf::Add(
                values[position],
                gf::Fp3::One());
        BOOST_CHECK(
            !Verify(
                fixture, fixture.plan,
                changed, &why));
        BOOST_CHECK_MESSAGE(
            why.find("verify_air:") !=
                std::string::npos,
            why);
    }

    // A self-consistent proof cannot select a different public
    // multiplicity schedule: the verifier first rebuilds the exact plan.
    {
        auto changed_plan = fixture.plan;
        ++changed_plan.sources[0].multiplicity;
        ++changed_plan.source_multiplicity_sum;
        BOOST_CHECK(
            !Verify(
                fixture, changed_plan,
                proof, &why));
        BOOST_CHECK_MESSAGE(
            why.find("verify_plan:") !=
                std::string::npos,
            why);
    }
}

BOOST_AUTO_TEST_SUITE_END()
