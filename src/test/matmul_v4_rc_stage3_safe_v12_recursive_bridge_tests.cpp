// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>
#include <matmul/matmul_v4_rc_stage3_safe_v12_recursive_bridge.h>

#include <algorithm>
#include <chrono>
#include <stdexcept>

namespace bridge =
    matmul::v4::rc::stage3_safe_v12_recursive_bridge;
namespace cb =
    matmul::v4::rc::constraint_bytecode;
namespace domains =
    matmul::v4::rc::stage3_safe_v12_domain_registry;
namespace fsair =
    matmul::v4::rc::stage3_safe_v12_fs_air;
namespace gf = matmul::v4::rc::gkr_field;
namespace nirop =
    matmul::v4::rc::stage3_safe_v12_nirop_reduction;
namespace aq = matmul::v4::rc::air_quotient;
namespace aht = matmul::v4::rc::alg_hash_typed;
namespace fixedpoint =
    matmul::v4::rc::recursive_fixedpoint;
namespace p2source =
    matmul::v4::rc::stage3_p2_prefix_source_air;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_safe_v12_recursive_bridge_tests)

namespace {

matmul::v4::rc::alg_hash::Digest TestDigest(uint64_t first)
{
    return {
        gf::FromU64(first),
        gf::FromU64(first + 1),
        gf::FromU64(first + 2),
        gf::FromU64(first + 3),
    };
}

uint256 TestSeed(uint32_t value)
{
    uint256 out;
    for (uint32_t index = 0; index < out.size(); ++index) {
        out.begin()[index] =
            static_cast<unsigned char>(
                (value + 31U * index) & 0xffU);
    }
    if (out.IsNull()) out.begin()[0] = 1;
    return out;
}

uint32_t TestSeedWord(
    const uint256& seed, uint32_t word)
{
    uint32_t out = 0;
    for (uint32_t byte = 0; byte < 4; ++byte) {
        out |=
            uint32_t{
                seed.data()[4 * word + byte]}
            << (8 * byte);
    }
    return out;
}

struct FixtureV12 {
    fsair::ManifestV12 manifest;
    nirop::HybridInputsV12 inputs;
    nirop::HybridReceiptV12 receipt;
    domains::TranscriptDomainRegistryV12 registry;
    bridge::RecursiveBridgeV12 bridge;
};

FixtureV12 BuildFixture()
{
    FixtureV12 out;
    std::string why;
    const fsair::ShapeV12 shape{
        /*child_w=*/3,
        /*child_n_rows=*/8,
        /*child_quotient_len=*/16,
        /*n_coeffs=*/64,
        /*n_lde=*/1024,
        /*n_folds=*/6,
    };
    if (!fsair::BuildManifestV12(
            shape, out.manifest, &why)) {
        throw std::runtime_error(why);
    }
    out.inputs.common.statement = TestDigest(1'000);
    out.inputs.common.program = TestDigest(1'100);
    const auto shared_root = TestDigest(2'020);
    out.inputs.common.trace = shared_root;
    out.inputs.transcript.proof_witness.trace_commit =
        shared_root;

    matmul::v4::rc::alg_hash::Digest shape_commit{};
    if (!nirop::DeriveCanonicalShapeCommitV12(
            out.manifest,
            aht::RoleV12::TranscriptShapeCommit,
            shape_commit, &why)) {
        throw std::runtime_error(why);
    }
    const auto metadata =
        nirop::CanonicalTraceMetadataV12(out.manifest);
    for (uint32_t lane = 0; lane < 2; ++lane) {
        out.inputs.lane_claim[lane] = {
            out.inputs.common.statement,
            out.inputs.common.program,
            out.inputs.common.trace,
        };
        out.inputs.lane_trace_metadata[lane] = metadata;
        auto& proof =
            out.inputs.transcript.proof_witness.fri_lane[lane];
        const uint64_t base = 2'000 + 100 * lane;
        proof.shape_commit = shape_commit;
        proof.row_root = shared_root;
        proof.ood_evaluation_commit =
            TestDigest(base + 30);
        for (uint32_t fold = 0; fold <= 6; ++fold) {
            proof.fold_roots.push_back(
                TestDigest(base + 40 + 10 * fold));
        }
    }

    if (!nirop::DeriveParentFsSeedV12(
            out.manifest, out.inputs.common,
            out.inputs.transcript.proof_witness,
            aht::RoleV12::ApplicationStatementCommitment,
            out.inputs.transcript.parent_statement.
                parent_fs_seed,
            &why)) {
        throw std::runtime_error(why);
    }
    std::array<matmul::v4::rc::alg_hash::Digest, 2>
        terminal{};
    if (!fsair::DeriveFriTerminalReceiptsV12(
            out.manifest, out.inputs.transcript,
            terminal, &why)) {
        throw std::runtime_error(why);
    }
    std::vector<gf::Fp> sigma_core;
    if (!nirop::BuildTaxSigmaCoreV12(
            out.manifest, out.inputs.common,
            out.inputs.transcript.parent_statement.
                parent_fs_seed,
            terminal, sigma_core, &why)) {
        throw std::runtime_error(why);
    }
    out.inputs.shared_grind_nonce = UINT64_C(831039);
    out.inputs.transcript.parent_statement.
        shared_query_tax_nonce =
            out.inputs.shared_grind_nonce;
    if (!nirop::CheckSharedGrindNonceV12(
            sigma_core, out.inputs.shared_grind_nonce,
            &out.inputs.transcript.parent_statement.
                shared_query_tax_sigma) ||
        !nirop::BuildHybridReceiptV12(
            out.manifest, out.inputs,
            out.receipt, &why) ||
        !domains::BuildTranscriptDomainRegistryV12(
            out.manifest, out.registry, &why) ||
        !bridge::BuildRecursiveBridgeV12(
            out.manifest, out.inputs, out.receipt,
            out.registry.root, out.bridge, &why)) {
        throw std::runtime_error(why);
    }
    return out;
}

const FixtureV12& Fixture()
{
    static const FixtureV12 fixture = BuildFixture();
    return fixture;
}

void Renumber(cb::ProgramTable& table)
{
    for (uint32_t ordinal = 0;
         ordinal < table.programs.size(); ++ordinal) {
        table.programs[ordinal].constraint_ordinal = ordinal;
    }
}

void InstallRawEncoding(
    bridge::RecursiveBridgeV12& product,
    uint32_t row, gf::Fp raw)
{
    product.columns[product.layout.source][row] =
        gf::Fp3{raw, 0, 0};
    product.columns[product.layout.consumer][row] =
        gf::Fp3{raw, 0, 0};
    for (uint32_t bit = 0; bit < 64; ++bit) {
        product.columns[product.layout.Bit(bit)][row] =
            gf::Fp3::FromFp((raw >> bit) & 1U);
    }
    gf::Fp cumulative = 1;
    for (uint32_t step = 0; step < 6; ++step) {
        const uint32_t first = 32 + 6 * step;
        const uint32_t last =
            std::min<uint32_t>(64, first + 6);
        for (uint32_t bit = first; bit < last; ++bit) {
            cumulative = gf::Mul(
                cumulative, (raw >> bit) & 1U);
        }
        product.columns[
            product.layout.HighAnd(step)][row] =
                gf::Fp3::FromFp(cumulative);
    }
}

std::vector<bridge::TypedSafeEventProgramV13>
TypedEventProgramV13()
{
    using Binding = bridge::TypedSafeMessageBindingV13;
    using Cell = bridge::TypedSafeMessageCellProgramV13;
    using Kind = bridge::TypedSafeChallengeKindV13;
    const auto proof = [] {
        Cell cell;
        cell.binding = Binding::ProofOwned;
        return cell;
    };
    const auto constant = [](uint64_t value) {
        Cell cell;
        cell.binding = Binding::Constant;
        cell.constant = gf::FromU64(value);
        return cell;
    };
    const auto seed_lane = [](uint32_t lane) {
        Cell cell;
        cell.binding = Binding::QuerySeedLane;
        cell.query_seed_lane = lane;
        return cell;
    };
    const auto event = [&](Kind kind, aht::RoleV12 role,
                           uint32_t ordinal) {
        bridge::TypedSafeEventProgramV13 out;
        out.kind = kind;
        out.role = role;
        const std::string domain =
            "BTX_TEST_TYPED_SAFE_EVENT_V13_" +
            std::to_string(ordinal);
        out.application_domain.assign(
            domain.begin(), domain.end());
        out.message = {
            constant(UINT32_C(0x53414645)),
            constant(13),
            constant(ordinal),
            proof(),
            proof(),
        };
        return out;
    };

    std::vector<bridge::TypedSafeEventProgramV13> out;
    out.push_back(event(
        Kind::AirLambda,
        aht::RoleV12::TranscriptAirLambda, 0));
    out.push_back(event(
        Kind::BatchCoefficient,
        aht::RoleV12::TranscriptBatchCoefficient, 1));
    out.push_back(event(
        Kind::OodZ1,
        aht::RoleV12::TranscriptOodZ1, 2));
    out.push_back(event(
        Kind::OodZ2,
        aht::RoleV12::TranscriptOodZ2, 3));
    out.push_back(event(
        Kind::DeepWeight1,
        aht::RoleV12::TranscriptDeepWeight, 4));
    out.push_back(event(
        Kind::DeepWeight2,
        aht::RoleV12::TranscriptDeepWeight, 5));
    out.push_back(event(
        Kind::FoldBeta,
        aht::RoleV12::TranscriptFoldBeta, 6));
    out.push_back(event(
        Kind::QuerySeed,
        aht::RoleV12::TranscriptQuerySeed, 7));

    bridge::TypedSafeEventProgramV13 query;
    query.kind = Kind::QueryCandidate;
    query.role = aht::RoleV12::TranscriptQueryCandidate;
    const std::string query_domain =
        "BTX_TEST_TYPED_SAFE_EVENT_V13_QUERY";
    query.application_domain.assign(
        query_domain.begin(), query_domain.end());
    query.message = {
        constant(UINT32_C(0x53414645)),
        constant(13),
        seed_lane(0), seed_lane(1),
        seed_lane(2), seed_lane(3),
        constant(0),
    };
    out.push_back(std::move(query));
    return out;
}

std::vector<bridge::TypedSafeEventWitnessV13>
TypedEventWitnessV13(
    const std::vector<bridge::TypedSafeEventProgramV13>& program)
{
    std::vector<bridge::TypedSafeEventWitnessV13> out(
        program.size());
    for (uint32_t event = 0; event < program.size(); ++event) {
        out[event].message.resize(program[event].message.size());
        for (uint32_t ordinal = 0;
             ordinal < program[event].message.size(); ++ordinal) {
            if (program[event].message[ordinal].binding ==
                bridge::TypedSafeMessageBindingV13::ProofOwned) {
                out[event].message[ordinal] =
                    gf::FromU64(
                        1000 + 100 * event + ordinal);
            }
        }
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    exact_980_cell_inventory_and_128_fp3_to_384_limb_projection)
{
    const auto& fixture = Fixture();
    const auto& product = fixture.bridge;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        bridge::ValidateRecursiveBridgeV12(
            fixture.manifest, fixture.inputs,
            fixture.receipt, fixture.registry.root,
            product, &why),
        why);
    BOOST_CHECK(product.valid);
    BOOST_CHECK_EQUAL(
        product.cs.n_rows, bridge::kTraceRowsV12);
    BOOST_CHECK_EQUAL(
        product.cs.n_columns, bridge::kAirColumnsV12);
    BOOST_CHECK_EQUAL(
        product.cell_map.size(), bridge::kTraceRowsV12);
    BOOST_CHECK_EQUAL(
        bridge::kActiveMapRowsV12, 980U);
    uint32_t candidate_rows = 0;
    for (const auto& entry : product.cell_map) {
        candidate_rows +=
            entry.kind == bridge::CellKindV12::QueryCandidate
                ? 1U
                : 0U;
    }
    BOOST_CHECK_EQUAL(candidate_rows, 2U * 384U);
    for (uint32_t lane = 0; lane < 2; ++lane) {
        // Regression for the 384-vs-128 indexing defect: SAFE emits 384
        // base limbs, while the sampler stores exactly 128 packed Fp3 cells.
        BOOST_CHECK_EQUAL(
            fixture.receipt.transcript_air.query_lane[lane].
                query_sampler_air.source_candidates.size(),
            128U);
    }
    BOOST_CHECK_EQUAL(
        product.cs.preprocessed.size(), 4U);
    BOOST_CHECK_EQUAL(
        product.verifier_owned_preprocessed_columns, 4U);
    BOOST_CHECK_EQUAL(
        product.proof_owned_preprocessed_columns, 0U);
    for (uint32_t limb = 0; limb < 4; ++limb) {
        BOOST_CHECK_EQUAL(
            product.cs.preprocessed[limb].first,
            product.layout.ExpectedRegistryRoot(limb));
        BOOST_CHECK_NE(
            product.cs.preprocessed[limb].first,
            product.layout.ProofRegistryRoot(limb));
    }
    BOOST_CHECK(product.exact_cell_map_rebuilt);
    BOOST_CHECK(product.domain_registry_root_pinned);
    BOOST_CHECK(product.typed_terminal_receipts_mapped);
    BOOST_CHECK(product.shared_tax_and_nonce_mapped);
    BOOST_CHECK(
        product.both_query_candidate_vectors_mapped);
    BOOST_CHECK(product.both_q96_outputs_mapped);
    BOOST_CHECK(product.proof_cells_are_ordinary_columns);
    BOOST_CHECK(
        product.canonical_bytecode_is_relation_source);
    BOOST_CHECK(!product.normalized_parent_consumed);
    BOOST_CHECK(!product.recursive_authority_ready);
    BOOST_CHECK_EQUAL(
        bridge::CountViolationsV12(
            product.cs, product.columns),
        0U);
}

BOOST_AUTO_TEST_CASE(
    omission_duplication_reorder_and_source_offset_change_program_root)
{
    const auto& fixture = Fixture();
    const auto honest_root = fixture.bridge.program_root;
    const size_t marker_base =
        fixture.bridge.program_table.programs.size() -
        bridge::kTraceRowsV12;
    std::string why;

    {
        auto omitted = fixture.bridge.program_table;
        omitted.programs.erase(
            omitted.programs.begin() + marker_base + 17);
        Renumber(omitted);
        BOOST_REQUIRE_MESSAGE(
            cb::ValidateProgramTable(omitted, &why), why);
        BOOST_CHECK(
            cb::CommitProgramTableAlgHash(omitted) !=
            honest_root);
    }
    {
        auto duplicated = fixture.bridge.program_table;
        duplicated.programs[marker_base + 18] =
            duplicated.programs[marker_base + 17];
        Renumber(duplicated);
        BOOST_REQUIRE_MESSAGE(
            cb::ValidateProgramTable(duplicated, &why), why);
        BOOST_CHECK(
            cb::CommitProgramTableAlgHash(duplicated) !=
            honest_root);
    }
    {
        auto reordered = fixture.bridge.program_table;
        std::swap(
            reordered.programs[marker_base + 17],
            reordered.programs[marker_base + 18]);
        Renumber(reordered);
        BOOST_REQUIRE_MESSAGE(
            cb::ValidateProgramTable(reordered, &why), why);
        BOOST_CHECK(
            cb::CommitProgramTableAlgHash(reordered) !=
            honest_root);
    }
    {
        auto offset = fixture.bridge.program_table;
        auto& marker =
            offset.programs[marker_base + 20];
        // Marker instruction 16 is the source_offset Constant.
        BOOST_REQUIRE_GT(marker.instructions.size(), 16U);
        BOOST_REQUIRE(
            marker.instructions[16].opcode ==
            cb::Opcode::Constant);
        marker.instructions[16].constant.c0 =
            gf::Add(
                marker.instructions[16].constant.c0, 1);
        BOOST_REQUIRE_MESSAGE(
            cb::ValidateProgramTable(offset, &why), why);
        BOOST_CHECK(
            cb::CommitProgramTableAlgHash(offset) !=
            honest_root);
    }

    // The host-side reconstruction rejects the same attacks even before a
    // quotient proof is attempted.
    for (uint32_t attack = 0; attack < 4; ++attack) {
        auto changed = fixture.bridge;
        if (attack == 0) {
            changed.cell_map.pop_back();
        } else if (attack == 1) {
            changed.cell_map[18] = changed.cell_map[17];
        } else if (attack == 2) {
            std::swap(
                changed.cell_map[17],
                changed.cell_map[18]);
        } else {
            ++changed.cell_map[20].source_offset;
        }
        BOOST_CHECK(
            !bridge::ValidateRecursiveBridgeV12(
                fixture.manifest, fixture.inputs,
                fixture.receipt, fixture.registry.root,
                changed, &why));
    }
}

BOOST_AUTO_TEST_CASE(
    goldilocks_boundary_p_minus_one_accepts_p_and_x_plus_p_reject)
{
    const auto& fixture = Fixture();
    constexpr uint32_t row = bridge::kActiveMapRowsV12;
    {
        auto boundary = fixture.bridge;
        InstallRawEncoding(boundary, row, gf::kP - 1);
        BOOST_CHECK_EQUAL(
            bridge::CountViolationsV12(
                boundary.cs, boundary.columns),
            0U);
    }
    {
        auto modulus = fixture.bridge;
        InstallRawEncoding(modulus, row, gf::kP);
        BOOST_CHECK_GT(
            bridge::CountViolationsV12(
                modulus.cs, modulus.columns),
            0U);
    }
    {
        auto alias = fixture.bridge;
        InstallRawEncoding(alias, row, gf::kP + 5);
        BOOST_CHECK_GT(
            bridge::CountViolationsV12(
                alias.cs, alias.columns),
            0U);
    }
}

BOOST_AUTO_TEST_CASE(
    real_airquotient_roundtrip_and_proof_level_substitution_rejects)
{
    const auto& fixture = Fixture();
    const uint256 seed = TestSeed(0x512);
    bridge::RecursiveBridgeProofV12 receipt;
    std::string why;
    const auto prove_begin =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        bridge::ProveRecursiveBridgeV12(
            fixture.bridge, seed, receipt, &why),
        why);
    const auto prove_end =
        std::chrono::steady_clock::now();
    const auto verify_begin =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        bridge::VerifyRecursiveBridgeProofV12(
            fixture.manifest, receipt, seed, &why),
        why);
    const auto verify_end =
        std::chrono::steady_clock::now();

    matmul::v4::rc::AirQuotientProofAlg canonical;
    canonical.batch = receipt.proof.batch;
    canonical.next_openings =
        receipt.proof.next_openings;
    canonical.trace_commit =
        receipt.proof.trace_commit;
    std::vector<unsigned char> bytes;
    const size_t serialized =
        matmul::v4::rc::SerializeAirQuotientProofAlg(
            canonical, bytes, &why);
    BOOST_REQUIRE_MESSAGE(serialized != 0, why);
    BOOST_TEST_MESSAGE(
        "SAFE_V12_RECURSIVE_BRIDGE measured_bytes="
        << bytes.size()
        << " prove_ms="
        << std::chrono::duration_cast<
               std::chrono::milliseconds>(
               prove_end - prove_begin).count()
        << " verify_ms="
        << std::chrono::duration_cast<
               std::chrono::milliseconds>(
               verify_end - verify_begin).count()
        << " rows=" << fixture.bridge.cs.n_rows
        << " cols=" << fixture.bridge.cs.n_columns
        << " map=" << bridge::kActiveMapRowsV12);

    // Registry and ProgramTable substitution are rejected by verifier rebuild.
    {
        auto changed = receipt;
        changed.registry_root[0] =
            gf::Add(changed.registry_root[0], 1);
        BOOST_CHECK(
            !bridge::VerifyRecursiveBridgeProofV12(
                fixture.manifest, changed, seed, &why));
    }
    {
        auto changed = receipt;
        changed.program_root[0] =
            gf::Add(changed.program_root[0], 1);
        BOOST_CHECK(
            !bridge::VerifyRecursiveBridgeProofV12(
                fixture.manifest, changed, seed, &why));
    }
    {
        const uint256 wrong_seed = TestSeed(0x513);
        BOOST_CHECK_MESSAGE(
            !bridge::VerifyRecursiveBridgeProofV12(
                fixture.manifest, receipt,
                wrong_seed, &why),
            "proof accepted under a different external fs_seed");
    }

    BOOST_REQUIRE(!receipt.proof.batch.queries.empty());
    BOOST_REQUIRE_GT(
        receipt.proof.batch.queries[0].row.values.size(),
        fixture.bridge.layout.consumer);

    // Receipt/source, query/consumer and offset-pair proof openings are each
    // protected at proof level by the committed row and AIR relation.
    for (uint32_t column : {
             fixture.bridge.layout.FriTerminal(0, 0),
             fixture.bridge.layout.source,
             fixture.bridge.layout.consumer}) {
        auto changed = receipt;
        changed.proof.batch.queries[0].
            row.values[column] =
                gf::Add(
                    changed.proof.batch.queries[0].
                        row.values[column],
                    gf::Fp3::One());
        BOOST_CHECK_MESSAGE(
            !bridge::VerifyRecursiveBridgeProofV12(
                fixture.manifest, changed, seed, &why),
            "proof-level bridge cell substitution accepted");
    }

    // In-memory x+p is algebraically equal in Goldilocks and the legacy
    // row hasher canonicalizes it. The bridge verifier therefore performs an
    // explicit unique-representation audit before invoking AirQuotient.
    {
        auto changed = receipt;
        auto& value =
            changed.proof.batch.queries[0].
                row.values[fixture.bridge.layout.source];
        value.c0 = gf::kP;
        BOOST_CHECK_MESSAGE(
            !bridge::VerifyRecursiveBridgeProofV12(
                fixture.manifest, changed, seed, &why),
            "proof-level x+p substitution accepted");
    }
}

BOOST_AUTO_TEST_CASE(
    v13_typed_safe_parent_owns_all_challenge_kinds_and_query_seed)
{
    const auto program = TypedEventProgramV13();
    const auto witness = TypedEventWitnessV13(program);
    const uint256 seed = TestSeed(0x713);
    bridge::TypedSafeEventParentProductV13 product;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        bridge::BuildTypedSafeEventParentV13(
            program, witness, seed, product, &why),
        why);
    BOOST_CHECK(product.valid);
    BOOST_CHECK(product.unique_query_seed_event);
    BOOST_CHECK(product.every_query_uses_seed_output);
    BOOST_CHECK(product.complete_challenge_kind_coverage);
    BOOST_CHECK_EQUAL(
        product.challenge_kinds_covered,
        bridge::kTypedSafeEventRequiredKindsV13);
    BOOST_CHECK(product.poseidon_relations_executable);
    BOOST_CHECK(product.dual_fp3_receipt_ctl_terminal);
    BOOST_CHECK(product.receipt_ctl_challenges_after_r0);
    BOOST_CHECK(!product.r0_row_group_root.IsNull());
    BOOST_CHECK(product.r0_session.valid);
    BOOST_CHECK(product.proof_cells_are_ordinary_columns);
    BOOST_CHECK(!product.parent_owns_real_fri_relation);
    BOOST_CHECK(!product.normalized_child_cells_bound);
    BOOST_CHECK(!product.recursive_authority_ready);
    BOOST_CHECK_EQUAL(
        product.proof_owned_preprocessed_columns, 0U);
    BOOST_CHECK_EQUAL(
        product.semantic_receipt_cells,
        product.proof_owned_message_cells +
            4U * program.size());
    BOOST_CHECK_EQUAL(
        bridge::CountViolationsV12(
            product.cs, product.columns),
        0U);
    BOOST_CHECK(
        product.program_root !=
        matmul::v4::rc::alg_hash::Digest{});
    BOOST_CHECK(
        product.transcript_commitment !=
        matmul::v4::rc::alg_hash::Digest{});
    BOOST_CHECK_EQUAL(
        product.output_locations.size(),
        4U * program.size());

    // A candidate cannot substitute its own "seed": all four query message
    // lanes are constrained to the unique QuerySeed event output registers.
    auto seed_substitution = product;
    const auto query_it = std::find_if(
        seed_substitution.output_locations.begin(),
        seed_substitution.output_locations.end(),
        [](const auto& location) {
            return location.kind ==
                bridge::TypedSafeChallengeKindV13::QueryCandidate;
        });
    BOOST_REQUIRE(
        query_it != seed_substitution.output_locations.end());
    const uint32_t query_first_row =
        query_it->row;
    seed_substitution.columns[
        seed_substitution.layout.Message(2)][query_first_row] =
            gf::Add(
                seed_substitution.columns[
                    seed_substitution.layout.Message(2)]
                    [query_first_row],
                gf::Fp3::One());
    BOOST_CHECK_GT(
        bridge::CountViolationsV12(
            seed_substitution.cs,
            seed_substitution.columns),
        0U);

    // Ordinary proof transcript cells are covered by both the Poseidon state
    // relation and the dual-Fp3 receipt rational identity.
    BOOST_REQUIRE(
        !product.proof_owned_message_locations.empty());
    auto transcript_tamper = product;
    const auto location =
        transcript_tamper.proof_owned_message_locations.front();
    transcript_tamper.columns[location.column][location.row] =
        gf::Add(
            transcript_tamper.columns[location.column][location.row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        bridge::CountViolationsV12(
            transcript_tamper.cs,
            transcript_tamper.columns),
        0U);

    // Goldilocks x+p is not accepted as an alternate transcript encoding.
    auto alias = product;
    const auto alias_location =
        alias.proof_owned_message_locations.front();
    alias.columns[alias_location.column][alias_location.row] =
        gf::Fp3{gf::kP + 5, 0, 0};
    BOOST_CHECK_GT(
        bridge::CountViolationsV12(alias.cs, alias.columns),
        0U);

    // The rational-identity challenges are sampled only after committing R0.
    // Changing one proof-owned transcript cell changes both the authenticated
    // R0 group and its derived alpha/gamma tuple.
    auto changed_witness = witness;
    bool changed_one = false;
    for (uint32_t event = 0;
         event < program.size() && !changed_one; ++event) {
        for (uint32_t ordinal = 0;
             ordinal < program[event].message.size(); ++ordinal) {
            if (program[event].message[ordinal].binding !=
                bridge::TypedSafeMessageBindingV13::ProofOwned) {
                continue;
            }
            changed_witness[event].message[ordinal] =
                gf::Add(
                    changed_witness[event].message[ordinal], 1);
            changed_one = true;
            break;
        }
    }
    BOOST_REQUIRE(changed_one);
    bridge::TypedSafeEventParentProductV13 changed_product;
    BOOST_REQUIRE_MESSAGE(
        bridge::BuildTypedSafeEventParentV13(
            program, changed_witness, seed,
            changed_product, &why),
        why);
    BOOST_CHECK(
        changed_product.r0_row_group_root !=
        product.r0_row_group_root);
    bool challenge_changed = false;
    for (uint32_t lane = 0;
         lane < product.receipt_ctl_challenges.size(); ++lane) {
        challenge_changed =
            challenge_changed ||
            !gf::Eq(
                changed_product.receipt_ctl_challenges[lane],
                product.receipt_ctl_challenges[lane]);
    }
    BOOST_CHECK(challenge_changed);
}

BOOST_AUTO_TEST_CASE(
    v13_native_fri_schedule_materializes_exact_typed_messages)
{
    const std::vector<unsigned char> transcript{
        0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0x42,
    };
    struct Draw {
        const char* label;
        uint32_t index;
        bridge::TypedSafeChallengeKindV13 kind;
    };
    const std::array<Draw, 9> draws{{
        {"fra3_lambda", 0,
         bridge::TypedSafeChallengeKindV13::BatchCoefficient},
        {"fra3_z", 0,
         bridge::TypedSafeChallengeKindV13::OodZ1},
        {"fra3_z", 1,
         bridge::TypedSafeChallengeKindV13::OodZ1},
        {"fra3_z", 2,
         bridge::TypedSafeChallengeKindV13::OodZ2},
        {"fra3_z", 3,
         bridge::TypedSafeChallengeKindV13::OodZ2},
        {"fra3_w", 0,
         bridge::TypedSafeChallengeKindV13::DeepWeight1},
        {"fra3_w", 1,
         bridge::TypedSafeChallengeKindV13::DeepWeight2},
        {"fra3_fold", 0,
         bridge::TypedSafeChallengeKindV13::FoldBeta},
        {"fra3_query", 0,
         bridge::TypedSafeChallengeKindV13::QuerySeed},
    }};

    std::vector<bridge::TypedSafeEventProgramV13> native_program;
    std::vector<bridge::TypedSafeEventWitnessV13> native_witness;
    matmul::v4::rc::alg_hash::Digest query_seed{};
    std::string why;
    for (const auto& draw : draws) {
        bridge::NativeTypedSafeEventAuditV13 audit;
        BOOST_REQUIRE_MESSAGE(
            bridge::BuildNativeFri3AlgSafeEventV13(
                transcript, draw.label, draw.index,
                audit, &why),
            why);
        BOOST_CHECK(audit.exact_message_materialized);
        BOOST_CHECK(audit.native_air_output_parity);
        BOOST_CHECK(audit.program.kind == draw.kind);
        BOOST_CHECK_EQUAL(
            std::count_if(
                audit.program.message.begin(),
                audit.program.message.end(),
                [](const auto& cell) {
                    return cell.binding ==
                        bridge::TypedSafeMessageBindingV13::
                            ProofOwned;
                }),
            (transcript.size() + 3) / 4);
        if (draw.kind ==
            bridge::TypedSafeChallengeKindV13::QuerySeed) {
            BOOST_CHECK(audit.query_seed_source);
            query_seed = audit.safe_digest;
        }
        native_program.push_back(std::move(audit.program));
        native_witness.push_back(std::move(audit.witness));
    }
    BOOST_REQUIRE(
        query_seed != matmul::v4::rc::alg_hash::Digest{});

    bridge::NativeTypedSafeEventAuditV13 query0;
    bridge::NativeTypedSafeEventAuditV13 query191;
    BOOST_REQUIRE_MESSAGE(
        bridge::BuildNativeFri3AlgSafeQueryCandidateEventV13(
            query_seed, 0, query0, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        bridge::BuildNativeFri3AlgSafeQueryCandidateEventV13(
            query_seed,
            matmul::v4::rc::kRCFri3AlgNumQueries - 1,
            query191, &why),
        why);
    BOOST_CHECK(query0.query_candidate_consumes_seed);
    BOOST_CHECK(query0.native_air_output_parity);
    BOOST_CHECK(query191.native_air_output_parity);
    BOOST_CHECK(
        !gf::Eq(query0.native_output, query191.native_output));
    native_program.push_back(std::move(query0.program));
    native_witness.push_back(std::move(query0.witness));

    // The eighth verifier challenge kind is the outer AirQuotient lambda.
    // Its V13 native SAFE producer is intentionally not invented here: the
    // shipping outer backend still has a separate P2/SHA selector. The exact
    // FRI schedule above therefore cannot be promoted into a complete parent
    // until that producer exposes its own typed event.
    BOOST_CHECK_EQUAL(native_program.size(), 10U);
    BOOST_CHECK_EQUAL(native_witness.size(), native_program.size());

    auto changed = transcript;
    changed.back() ^= 1;
    bridge::NativeTypedSafeEventAuditV13 changed_seed;
    BOOST_REQUIRE(
        bridge::BuildNativeFri3AlgSafeEventV13(
            changed, "fra3_query", 0,
            changed_seed, &why));
    BOOST_CHECK(
        changed_seed.safe_digest != query_seed);

    auto noncanonical_seed = query_seed;
    noncanonical_seed[0] = gf::kP;
    bridge::NativeTypedSafeEventAuditV13 rejected;
    BOOST_CHECK(
        !bridge::BuildNativeFri3AlgSafeQueryCandidateEventV13(
            noncanonical_seed, 0, rejected, &why));
    BOOST_CHECK(
        !bridge::BuildNativeFri3AlgSafeEventV13(
            transcript, "unknown", 0, rejected, &why));
}

BOOST_AUTO_TEST_CASE(
    v13_typed_safe_parent_real_fri_rejects_tamper_transplant_and_seed)
{
    const auto program = TypedEventProgramV13();
    const auto witness = TypedEventWitnessV13(program);
    const uint256 seed = TestSeed(0x714);
    bridge::TypedSafeEventParentProductV13 product;
    bridge::TypedSafeEventParentProofV13 proof;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        bridge::BuildTypedSafeEventParentV13(
            program, witness, seed, product, &why),
        why);
    const auto begin = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        bridge::ProveTypedSafeEventParentV13(
            product, seed, proof, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        bridge::VerifyTypedSafeEventParentProofV13(
            program, proof, seed, &why),
        why);
    const auto end = std::chrono::steady_clock::now();
    BOOST_TEST_MESSAGE(
        "SAFE_EVENT_PARENT_V13 rows="
        << product.trace_rows
        << " cols=" << product.cs.n_columns
        << " active=" << product.active_permutation_rows
        << " semantic=" << product.semantic_receipt_cells
        << " roundtrip_ms="
        << std::chrono::duration_cast<
               std::chrono::milliseconds>(end - begin).count());

    BOOST_REQUIRE(!proof.proof.batch.queries.empty());
    BOOST_REQUIRE(
        !proof.proof.batch.queries[0].group_rows.empty());
    BOOST_REQUIRE(
        !proof.proof.batch.queries[0]
             .group_rows[0].values.empty());
    {
        auto tampered = proof;
        tampered.proof.batch.queries[0]
            .group_rows[0].values[0] =
            gf::Add(
                tampered.proof.batch.queries[0]
                    .group_rows[0].values[0],
                gf::Fp3::One());
        BOOST_CHECK(
            !bridge::VerifyTypedSafeEventParentProofV13(
                program, tampered, seed, &why));
    }
    {
        auto transplanted_program = program;
        transplanted_program[0].message[0].constant =
            gf::Add(
                transplanted_program[0].message[0].constant, 1);
        BOOST_CHECK(
            !bridge::VerifyTypedSafeEventParentProofV13(
                transplanted_program, proof, seed, &why));
    }
    {
        const uint256 wrong_seed = TestSeed(0x715);
        BOOST_CHECK(
            !bridge::VerifyTypedSafeEventParentProofV13(
                program, proof, wrong_seed, &why));
    }
    {
        auto commitment = proof;
        commitment.transcript_commitment[0] =
            gf::Add(commitment.transcript_commitment[0], 1);
        BOOST_CHECK(
            !bridge::VerifyTypedSafeEventParentProofV13(
                program, commitment, seed, &why));
    }
    {
        auto r0_substitution = proof;
        r0_substitution.r0_row_group_root.begin()[0] ^= 1U;
        BOOST_CHECK(
            !bridge::VerifyTypedSafeEventParentProofV13(
                program, r0_substitution, seed, &why));
    }
    BOOST_CHECK(
        bridge::kTypedSafeEventParentExecutableV13);
    BOOST_CHECK(
        !bridge::kTypedSafeEventNormalizedChildCellsBoundV13);
    BOOST_CHECK(
        !bridge::kTypedSafeEventRecursiveAuthorityReadyV13);
}

BOOST_AUTO_TEST_CASE(
    v13_native_verified_child_proof_drives_exact_typed_event_schedule)
{
    namespace rc = matmul::v4::rc;
    std::vector<std::vector<gf::Fp3>> columns(2);
    for (uint32_t column = 0; column < columns.size(); ++column) {
        columns[column].resize(8);
        for (uint32_t row = 0;
             row < columns[column].size(); ++row) {
            columns[column][row] = {
                gf::FromU64(1 + 19 * column + 7 * row),
                gf::FromU64(3 + 11 * column + 5 * row),
                gf::FromU64(9 + 13 * column + 17 * row),
            };
        }
    }
    const uint256 child_seed = TestSeed(0x731);
    const auto proved =
        rc::Fri3AlgSafeQ192K2V13BatchCommit(
            columns, child_seed, 17);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);

    bridge::NativeFri3AlgTypedSafeScheduleV13 schedule;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        bridge::BuildNativeFri3AlgTypedSafeScheduleV13(
            proved.proof, child_seed, schedule, &why),
        why);
    BOOST_CHECK(schedule.valid);
    BOOST_CHECK(schedule.native_proof_verified);
    BOOST_CHECK(schedule.exact_event_order);
    BOOST_CHECK(schedule.every_snapshot_exactly_materialized);
    BOOST_CHECK(
        schedule.every_safe_output_matches_native_consumer);
    BOOST_CHECK(schedule.unique_query_seed_then_q192);
    BOOST_CHECK(schedule.every_transcript_byte_typed);
    BOOST_CHECK(
        !schedule.transcript_word_bindings.empty());
    BOOST_CHECK_EQUAL(
        schedule.transcript_word_bindings.size(),
        schedule.proof_owned_message_cells);
    BOOST_CHECK_GT(
        schedule.transcript_byte_occurrences, 0U);
    BOOST_CHECK_EQUAL(
        schedule.transcript_byte_occurrences,
        schedule.transcript_bytes_with_normalized_source +
            schedule.transcript_bytes_missing_normalized_source);
    BOOST_CHECK_GT(
        schedule.transcript_bytes_requiring_hash_relation,
        0U);
    BOOST_CHECK_GT(
        schedule.transcript_bytes_missing_normalized_source,
        0U);
    for (const auto& binding :
         schedule.transcript_word_bindings) {
        for (uint32_t byte = 0;
             byte < binding.bytes_present; ++byte) {
            const auto& source =
                binding.source_bytes[byte];
            if (!source.normalized_source_available) {
                BOOST_CHECK(
                    source.kind ==
                    bridge::
                        NativeFri3AlgTypedSafeScheduleV13::
                            TranscriptSourceKind::
                                ProofPowGrindNonce);
            }
            if (source.hash_relation_required) {
                BOOST_CHECK(
                    source.kind ==
                        bridge::
                            NativeFri3AlgTypedSafeScheduleV13::
                                TranscriptSourceKind::
                                    ShapeCommitDigest ||
                    source.kind ==
                        bridge::
                            NativeFri3AlgTypedSafeScheduleV13::
                                TranscriptSourceKind::
                                    OodEvaluationCommitDigest);
            }
        }
    }
    BOOST_CHECK(
        !schedule
             .pow_grind_nonce_exported_by_normalized_parent);
    BOOST_CHECK(
        !schedule
             .shape_and_ood_commit_hashes_bound_in_parent);
    BOOST_TEST_MESSAGE(
        "SAFE_V13_NATIVE_SOURCE_MAP events="
        << schedule.events_materialized
        << " words="
        << schedule.transcript_word_bindings.size()
        << " byte_occurrences="
        << schedule.transcript_byte_occurrences
        << " missing_normalized="
        << schedule.transcript_bytes_missing_normalized_source
        << " hash_relation="
        << schedule.transcript_bytes_requiring_hash_relation);
    BOOST_CHECK_EQUAL(
        schedule.query_candidate_events,
        rc::kRCFri3AlgNumQueries);
    BOOST_CHECK_EQUAL(
        schedule.events_materialized,
        1U + 4U + 2U +
            proved.proof.fold_challenges.size() +
            1U + rc::kRCFri3AlgNumQueries);
    BOOST_CHECK_EQUAL(
        schedule.program.size(),
        schedule.witness.size());
    BOOST_CHECK(!schedule.outer_air_lambda_present);
    BOOST_CHECK(!schedule.normalized_child_cells_bound);

    // Proof-derived schedules cannot be forged by changing a shipped
    // challenge, query consumer, or parent-owned seed.
    {
        auto bad = proved.proof;
        bad.w1.c0 = gf::Add(bad.w1.c0, 1);
        bridge::NativeFri3AlgTypedSafeScheduleV13 rejected;
        BOOST_CHECK(
            !bridge::BuildNativeFri3AlgTypedSafeScheduleV13(
                bad, child_seed, rejected, &why));
        BOOST_CHECK(!rejected.valid);
    }
    {
        auto bad = proved.proof;
        BOOST_REQUIRE(!bad.queries.empty());
        bad.queries.front().index ^= 1U;
        bridge::NativeFri3AlgTypedSafeScheduleV13 rejected;
        BOOST_CHECK(
            !bridge::BuildNativeFri3AlgTypedSafeScheduleV13(
                bad, child_seed, rejected, &why));
        BOOST_CHECK(!rejected.valid);
    }
    {
        bridge::NativeFri3AlgTypedSafeScheduleV13 rejected;
        BOOST_CHECK(
            !bridge::BuildNativeFri3AlgTypedSafeScheduleV13(
                proved.proof, TestSeed(0x732),
                rejected, &why));
        BOOST_CHECK(!rejected.valid);
    }
}

BOOST_AUTO_TEST_CASE(
    v13_nonce_shape_and_ood_prefix_sources_are_same_parent_air_owned)
{
    namespace rc = matmul::v4::rc;
    const uint256 seed = TestSeed(0x741);
    const std::vector<std::vector<gf::Fp3>> columns{{
        gf::FromSigned3(3),
        gf::FromSigned3(5),
    }};
    const auto proved =
        rc::Fri3AlgSafeQ192K2V13BatchCommit(
            columns, seed, 23);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    bridge::NativeFri3AlgTypedSafeScheduleV13 schedule;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        bridge::BuildNativeFri3AlgTypedSafeScheduleV13(
            proved.proof, seed, schedule, &why),
        why);

    fixedpoint::NormalizedAlgAirBatchCodecMapV1 map;
    BOOST_REQUIRE_MESSAGE(
        fixedpoint::BuildNormalizedAlgAirBatchCodecMapV1(
            proved.proof, map, &why),
        why);
    const uint32_t needed_rows =
        std::max<uint32_t>(
            64,
            (5 + map.codec_words +
             fixedpoint::
                 kNormalizedAlgAirProofFieldBusRate -
             1) /
                fixedpoint::
                    kNormalizedAlgAirProofFieldBusRate);
    uint32_t rows = 2;
    while (rows < needed_rows) rows <<= 1;

    fixedpoint::FoldBusComposition parent;
    fixedpoint::
        NormalizedAlgAirProofFieldBusAttachmentV1
            proof_bus;
    proof_bus.layout =
        fixedpoint::NormalizedAlgAirProofFieldBusLayout(
            p2source::kSeedWordsV1);
    proof_bus.parent_rows = rows;
    proof_bus.batch_codec_bytes = map.codec_bytes;
    proof_bus.batch_codec_words = map.codec_words;
    proof_bus.active_sponge_rows =
        (5 + map.codec_words +
         fixedpoint::
             kNormalizedAlgAirProofFieldBusRate -
         1) /
            fixedpoint::
                kNormalizedAlgAirProofFieldBusRate;
    proof_bus.proof_commitment = TestSeed(0x742);
    proof_bus.valid = true;

    fixedpoint::
        NormalizedAlgAirCodecDecoderAttachmentV1
            decoder;
    decoder.layout =
        fixedpoint::NormalizedAlgAirCodecDecoderLayout(
            proof_bus.layout.End());
    decoder.map = map;
    decoder.parent_rows = rows;
    decoder.active_word_slots = map.codec_words;
    decoder.valid_byte_slots = map.codec_bytes;
    decoder.canonical_fp_elements = map.fp_elements;
    decoder.added_columns =
        decoder.layout.End() - decoder.layout.base;
    decoder.exact_length_constrained = true;
    decoder.every_word_decomposed = true;
    decoder.every_byte_range_checked = true;
    decoder.little_endian_recomposition_constrained =
        true;
    decoder.final_word_padding_zero = true;
    decoder.every_fp_encoding_canonical = true;
    decoder.no_unconsumed_codec_bytes = true;
    decoder.valid = true;

    p2source::ReceiptSeedSourceRefsV1 seed_source;
    for (uint32_t word = 0;
         word < p2source::kSeedWordsV1;
         ++word) {
        seed_source.u32_word[word] = {word, 0};
    }
    seed_source.canonical_receipt_statement = true;
    seed_source.verifier_recomputed_seed = true;
    seed_source.cells_bound_before_first_commitment = true;
    seed_source.complete_child_verifier_same_parent =
        false;

    parent.combined.n_rows = rows;
    parent.combined.n_columns = decoder.layout.End();
    parent.columns.assign(
        parent.combined.n_columns,
        std::vector<gf::Fp3>(
            rows, gf::Fp3::Zero()));
    for (uint32_t word = 0;
         word < p2source::kSeedWordsV1;
         ++word) {
        parent.columns[word][0] =
            gf::Fp3::FromFp(
                gf::FromU64(
                    TestSeedWord(seed, word)));
    }
    for (uint32_t word = 0;
         word < map.codec_words; ++word) {
        const uint32_t position = 5 + word;
        const uint32_t row =
            position /
            fixedpoint::
                kNormalizedAlgAirProofFieldBusRate;
        const uint32_t lane =
            position %
            fixedpoint::
                kNormalizedAlgAirProofFieldBusRate;
        parent.columns[
            proof_bus.layout.Field(lane)][row] =
            gf::Fp3::FromFp(
                gf::FromU64(
                    map.entries[word].value));
        for (uint32_t byte = 0;
             byte < 4; ++byte) {
            parent.columns[
                decoder.layout.Byte(
                    lane, byte)][row] =
                gf::Fp3::FromFp(
                    gf::FromU64(
                        (map.entries[word].value >>
                         (8 * byte)) &
                        0xff));
        }
    }

    bridge::NativeV13NormalizedPrefixAttachment
        attachment;
    BOOST_REQUIRE_MESSAGE(
        bridge::AttachNativeV13NormalizedPrefixSources(
            parent, proved.proof, seed,
            proof_bus, decoder, seed_source,
            schedule, attachment, &why),
        why);
    BOOST_CHECK(attachment.valid);
    BOOST_CHECK(attachment.exact_schedule_rebuilt);
    BOOST_CHECK(
        attachment.nonce_from_canonical_proof_decoder);
    BOOST_CHECK(
        attachment.shape_hash_from_proof_decoder_air);
    BOOST_CHECK(
        attachment.ood_hash_from_proof_decoder_air);
    BOOST_CHECK_EQUAL(
        attachment.nonce_source_occurrences,
        schedule
            .transcript_bytes_missing_normalized_source);
    BOOST_CHECK_EQUAL(
        attachment.shape_hash_source_occurrences +
            attachment.ood_hash_source_occurrences,
        schedule
            .transcript_bytes_requiring_hash_relation);
    BOOST_CHECK(!attachment.source_values_preprocessed);
    BOOST_CHECK(
        !attachment.complete_child_verifier_same_parent);
    BOOST_CHECK(!attachment.recursively_consumed);
    BOOST_CHECK(!attachment.recursive_authority_ready);
    BOOST_CHECK_EQUAL(
        p2source::CountViolations(parent), 0U);
    BOOST_TEST_MESSAGE(
        "SAFE_V13_PREFIX_SOURCE_AIR rows="
        << rows
        << " added_cols="
        << attachment.hash_sources.added_columns
        << " constraints="
        << attachment.hash_sources.added_constraints
        << " nonce_occurrences="
        << attachment.nonce_source_occurrences
        << " shape_hash_occurrences="
        << attachment.shape_hash_source_occurrences
        << " ood_hash_occurrences="
        << attachment.ood_hash_source_occurrences);

    // Version routing is explicit: neither wrapper accepts the other's lane.
    {
        p2source::AttachmentV1 rejected;
        BOOST_CHECK(
            !p2source::AttachV10PrefixSourceAirV1(
                parent, proved.proof, seed,
                proof_bus, decoder, seed_source,
                rejected, &why));
    }

    // The nonce source is an alias to the canonical decoder, rather than a
    // copied host value. Corrupting that decoder byte is rejected before a
    // second source chip can be attached.
    {
        const auto cell =
            attachment.pow_grind_nonce_bytes.front();
        const gf::Fp3 saved =
            parent.columns[cell.column][cell.row];
        parent.columns[cell.column][cell.row] =
            gf::Add(saved, gf::Fp3::One());
        bridge::NativeV13NormalizedPrefixAttachment
            rejected;
        BOOST_CHECK(
            !bridge::AttachNativeV13NormalizedPrefixSources(
                parent, proved.proof, seed,
                proof_bus, decoder, seed_source,
                schedule, rejected, &why));
        parent.columns[cell.column][cell.row] = saved;
    }

    // A caller cannot relabel the decoder metadata while leaving the witness
    // cells unchanged. The source chip independently rebuilds and compares
    // the complete canonical codec map.
    {
        const uint32_t saved =
            decoder.map.entries.front().value;
        decoder.map.entries.front().value ^= 1U;
        BOOST_CHECK(
            !p2source::ValidateV13PrefixSourceAirV1(
                parent, proved.proof, seed,
                proof_bus, decoder, seed_source,
                attachment.hash_sources, &why));
        decoder.map.entries.front().value = saved;
    }

    // Digest export bytes are constrained outputs of the Poseidon2 source
    // AIR. A forged export is rejected by both the polynomial constraints
    // and the structural validator.
    {
        const auto cell =
            attachment.hash_sources.exports
                .shape_commit.byte.front();
        const gf::Fp3 saved =
            parent.columns[cell.column][cell.row];
        parent.columns[cell.column][cell.row] =
            gf::Add(saved, gf::Fp3::One());
        BOOST_CHECK_GT(
            p2source::CountViolations(parent), 0U);
        BOOST_CHECK(
            !p2source::ValidateV13PrefixSourceAirV1(
                parent, proved.proof, seed,
                proof_bus, decoder, seed_source,
                attachment.hash_sources, &why));
        parent.columns[cell.column][cell.row] = saved;
        BOOST_CHECK_EQUAL(
            p2source::CountViolations(parent), 0U);
    }
}

BOOST_AUTO_TEST_CASE(
    native_multi_row_v13_replay_has_distinct_typed_parent_schedule)
{
    namespace rc = matmul::v4::rc;
    const uint256 seed = TestSeed(0x751);
    const auto fp3 =
        [](uint64_t value) {
            return gf::Fp3{
                gf::FromU64(value),
                gf::FromU64(value + 1),
                gf::FromU64(value + 2)};
        };
    const std::vector<
        std::vector<std::vector<gf::Fp3>>>
        groups{
            {{fp3(1), fp3(2), fp3(3), fp3(4)}},
            {{fp3(5), fp3(6), fp3(7), fp3(8)}},
            {{fp3(9), fp3(10), fp3(11), fp3(12)}},
        };
    const std::vector<
        rc::Fri3AlgMultiRowGroupRole>
        roles{
            rc::Fri3AlgMultiRowGroupRole::MainTrace,
            rc::Fri3AlgMultiRowGroupRole::
                AuxiliaryTrace,
            rc::Fri3AlgMultiRowGroupRole::Quotient,
        };
    const auto proved =
        rc::Fri3AlgMultiRowSafeQ192K2V13BatchCommitStreaming(
            groups, roles, seed, 29);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);

    bridge::NativeFri3AlgMultiRowTypedSafeScheduleV13
        schedule;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        bridge::
            BuildNativeFri3AlgMultiRowTypedSafeScheduleV13(
                proved.proof, seed, schedule, &why),
        why);
    BOOST_CHECK(schedule.valid);
    BOOST_CHECK(schedule.native_proof_verified);
    BOOST_CHECK(
        schedule.canonical_multi_row_event_order);
    BOOST_CHECK(
        schedule.every_snapshot_exactly_materialized);
    BOOST_CHECK(
        schedule.every_safe_output_matches_native_consumer);
    BOOST_CHECK(
        schedule.unique_query_seed_then_q192);
    BOOST_CHECK_EQUAL(
        schedule.query_candidate_events,
        rc::kRCFri3AlgNumQueries);
    BOOST_CHECK_EQUAL(
        schedule.events_materialized,
        schedule.replay.events.size());
    BOOST_REQUIRE_GT(schedule.program.size(), 4U);
    BOOST_CHECK(
        schedule.program.front().kind ==
        bridge::TypedSafeChallengeKindV13::OodZ1);
    BOOST_CHECK(
        schedule.program[4].kind ==
        bridge::TypedSafeChallengeKindV13::
            BatchCoefficient);
    BOOST_CHECK_GT(
        schedule.proof_owned_message_cells, 0U);
    BOOST_CHECK(!schedule.normalized_child_cells_bound);
    BOOST_CHECK(!schedule.outer_split_rap_events_bound);
    BOOST_CHECK(!schedule.recursively_consumed);

    // The adapter accepts only the output of a completely verified native
    // multi-row proof. Proof mutation, seed transplant and V2 relabel all
    // clear the schedule instead of exporting caller-supplied events.
    {
        auto bad = proved.proof;
        bad.evals_z1.front() =
            gf::Add(
                bad.evals_z1.front(),
                gf::Fp3::One());
        bridge::
            NativeFri3AlgMultiRowTypedSafeScheduleV13
                rejected;
        BOOST_CHECK(
            !bridge::
                BuildNativeFri3AlgMultiRowTypedSafeScheduleV13(
                    bad, seed, rejected, &why));
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(rejected.program.empty());
    }
    {
        bridge::
            NativeFri3AlgMultiRowTypedSafeScheduleV13
                rejected;
        BOOST_CHECK(
            !bridge::
                BuildNativeFri3AlgMultiRowTypedSafeScheduleV13(
                    proved.proof, TestSeed(0x752),
                    rejected, &why));
        BOOST_CHECK(!rejected.valid);
    }
    {
        auto bad = proved.proof;
        bad.version =
            rc::kRCFri3AlgMultiRowBatchProofVersion;
        bridge::
            NativeFri3AlgMultiRowTypedSafeScheduleV13
                rejected;
        BOOST_CHECK(
            !bridge::
                BuildNativeFri3AlgMultiRowTypedSafeScheduleV13(
                    bad, seed, rejected, &why));
        BOOST_CHECK(!rejected.valid);
    }
}

BOOST_AUTO_TEST_CASE(
    outer_safe_v2_and_multi_row_v13_form_one_typed_parent_program)
{
    namespace rc = matmul::v4::rc;
    constexpr uint32_t N = 8;
    const uint256 seed = TestSeed(0x761);
    std::vector<std::vector<gf::Fp3>> columns(
        4, std::vector<gf::Fp3>(
               N, gf::Fp3::Zero()));
    for (uint32_t row = 0; row < N; ++row) {
        columns[0][row] =
            gf::Fp3::FromFp(
                gf::FromU64(
                    3 + 2 * row + row * row));
        columns[1][row] =
            gf::Fp3::FromFp(
                gf::FromU64(7 + 5 * row));
    }
    const auto make_cs =
        [](const gf::Fp3& relation_challenge) {
            aq::AirConstraintSystem<gf::Fp3> cs;
            cs.n_rows = N;
            cs.n_columns = 4;
            aq::AirConstraint<gf::Fp3> relation;
            relation.name =
                "test.safe_v2_parent_relation";
            relation.kind =
                aq::AirKind::kEverywhere;
            relation.alg_degree = 1;
            relation.eval =
                [relation_challenge](
                    const auto& cur,
                    const auto&) {
                    return gf::Sub(
                        cur[2],
                        gf::Add(
                            cur[0],
                            gf::Mul(
                                relation_challenge,
                                cur[1])));
                };
            cs.constraints.push_back(
                std::move(relation));
            aq::AirConstraint<gf::Fp3> transition;
            transition.name =
                "test.safe_v2_parent_next";
            transition.kind =
                aq::AirKind::kTransition;
            transition.alg_degree = 1;
            transition.eval =
                [](const auto& cur,
                   const auto& next) {
                    return gf::Sub(
                        next[3],
                        gf::Add(cur[3], cur[2]));
                };
            cs.constraints.push_back(
                std::move(transition));
            return cs;
        };
    const std::vector<uint32_t> base_indices{0, 1};
    const auto shape_cs =
        make_cs(gf::Fp3::Zero());
    const auto r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            shape_cs, columns, base_indices);
    BOOST_REQUIRE_MESSAGE(r0.valid, r0.note);
    const uint256 relation_digest =
        aq::AirChallengeDigest(
            seed,
            "test_safe_v2_parent_relation",
            {r0.base_row_commitment},
            {N, 4});
    const gf::Fp3 relation_challenge =
        gf::FromChallengeBytes3(
            relation_digest.data());
    auto cs = make_cs(relation_challenge);
    for (uint32_t row = 0; row < N; ++row) {
        columns[2][row] =
            gf::Add(
                columns[0][row],
                gf::Mul(
                    relation_challenge,
                    columns[1][row]));
        if (row + 1 < N) {
            columns[3][row + 1] =
                gf::Add(
                    columns[3][row],
                    columns[2][row]);
        }
    }
    cs.preprocessed.emplace_back(
        1, columns[1]);
    cs.preprocessed_pin_ood = true;
    cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role =
            aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns = base_indices,
        .root = r0.base_row_commitment,
    });

    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeV2(
            cs, columns, base_indices,
            seed, {}, &r0);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    bridge::
        NativeSplitRapMultiRowTypedSafeScheduleV2
            schedule;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        bridge::
            BuildNativeSplitRapMultiRowTypedSafeScheduleV2(
                cs, proved.proof, base_indices,
                seed, schedule, &why),
        why);
    BOOST_CHECK(schedule.valid);
    BOOST_CHECK(schedule.outer.valid);
    BOOST_CHECK(schedule.child.valid);
    BOOST_CHECK(
        schedule.child_seed_derived_from_outer_replay);
    BOOST_CHECK(
        schedule.complete_challenge_kind_coverage);
    BOOST_CHECK(
        schedule.child.every_transcript_byte_typed);
    BOOST_CHECK(
        schedule.child.canonical_v13_source_keys_complete);
    BOOST_CHECK(
        schedule.canonical_v13_proof_decoded);
    BOOST_CHECK(
        schedule.every_child_transcript_abi_source_resolved);
    BOOST_CHECK_GT(
        schedule.canonical_v13_sources.size(), 0U);
    BOOST_CHECK_EQUAL(
        schedule.canonical_v13_abi_words.size(),
        matmul::v4::rc::
            stage3_multirow_v11_proof_abi::
                kFieldAbiHeaderWordsV1 +
            2 *
                schedule.canonical_v13_sources.size());
    BOOST_CHECK_EQUAL(
        schedule
            .canonical_v13_source_byte_occurrences,
        schedule
            .canonical_v13_source_byte_occurrences_resolved);
    BOOST_CHECK_GT(
        schedule.child
            .prior_event_output_byte_occurrences,
        0U);
    BOOST_CHECK_GT(
        schedule.child
            .derived_hash_byte_occurrences,
        0U);
    BOOST_REQUIRE_GT(schedule.program.size(), 2U);
    BOOST_CHECK(
        schedule.program[0].kind ==
        bridge::TypedSafeChallengeKindV13::AirLambda);
    BOOST_CHECK(
        schedule.program[1].kind ==
        bridge::TypedSafeChallengeKindV13::FriSeed);
    BOOST_CHECK(
        schedule.program[2].kind ==
        bridge::TypedSafeChallengeKindV13::OodZ1);
    BOOST_CHECK(!schedule.normalized_child_cells_bound);
    BOOST_CHECK(!schedule.same_parent_child_seed_feedback);
    BOOST_CHECK(!schedule.recursively_consumed);

    bridge::TypedSafeEventParentProductV13 parent;
    BOOST_REQUIRE_MESSAGE(
        bridge::BuildTypedSafeEventParentV13(
            schedule.program, schedule.witness,
            TestSeed(0x762), parent, &why),
        why);
    BOOST_CHECK(parent.valid);
    BOOST_CHECK(
        parent.complete_challenge_kind_coverage);
    BOOST_CHECK_EQUAL(
        parent.challenge_kinds_covered,
        bridge::kTypedSafeEventRequiredKindsV13);
    BOOST_CHECK_EQUAL(parent.violations, 0U);
    BOOST_CHECK(!parent.normalized_child_cells_bound);
    BOOST_CHECK(!parent.recursive_authority_ready);
    BOOST_TEST_MESSAGE(
        "SAFE_V2_MULTI_ROW_TYPED_PARENT events="
        << schedule.program.size()
        << " rows=" << parent.trace_rows
        << " cols=" << parent.cs.n_columns
        << " constraints="
        << parent.cs.constraints.size()
        << " proof_cells="
        << parent.proof_owned_message_cells
        << " max_degree="
        << parent.max_algebraic_degree);

    bridge::TypedSafeDirectParentProductV14 direct;
    BOOST_REQUIRE_MESSAGE(
        bridge::BuildTypedSafeDirectParentV14(
            schedule.program, schedule.witness,
            direct, &why),
        why);
    BOOST_CHECK(direct.valid);
    BOOST_CHECK(direct.ordinary_air);
    BOOST_CHECK(direct.no_post_commit_challenges);
    BOOST_CHECK(direct.physical_alias_inventory_complete);
    BOOST_CHECK(direct.ordered_receipt_hash_in_trace);
    BOOST_CHECK(direct.query_seed_feedback_exact);
    BOOST_CHECK(direct.proof_cells_are_ordinary_columns);
    BOOST_CHECK_EQUAL(
        direct.cs.n_columns,
        bridge::kTypedSafeDirectParentColumnsV14);
    BOOST_CHECK_EQUAL(direct.violations, 0U);
    BOOST_CHECK_EQUAL(
        direct.aliased_proof_owned_message_cells,
        direct.proof_owned_message_cells);
    BOOST_CHECK(!direct.canonical_child_proof_decoder_bound);
    BOOST_CHECK(!direct.normalized_child_cells_bound);
    BOOST_CHECK(!direct.recursive_authority_ready);
    BOOST_REQUIRE(!direct.proof_cell_aliases.empty());
    uint64_t child_snapshot_aliases = 0;
    for (const auto& binding :
         schedule.child.transcript_word_bindings) {
        const auto found = std::find_if(
            direct.proof_cell_aliases.begin(),
            direct.proof_cell_aliases.end(),
            [&](const auto& alias) {
                return alias.event ==
                        binding.event +
                            schedule.outer.program.size() &&
                    alias.message_ordinal ==
                        binding.message_ordinal;
            });
        BOOST_REQUIRE_MESSAGE(
            found != direct.proof_cell_aliases.end(),
            "canonical V13 transcript word has no physical "
            "V14 Event.message -> receipt alias");
        ++child_snapshot_aliases;
        for (uint32_t byte = 0;
             byte < binding.bytes_present; ++byte) {
            const auto& source =
                binding.source_bytes[byte];
            if (!source.canonical_abi_source) continue;
            BOOST_REQUIRE_LT(
                source.abi_source_address,
                schedule.canonical_v13_sources.size());
            const auto& canonical =
                schedule.canonical_v13_sources[
                    source.abi_source_address];
            BOOST_CHECK(
                canonical.key == source.abi_key);
        }
    }
    BOOST_CHECK_EQUAL(
        child_snapshot_aliases,
        schedule.child
            .transcript_word_bindings.size());
    BOOST_TEST_MESSAGE(
        "SAFE_V14_DIRECT_PARENT events="
        << schedule.program.size()
        << " rows=" << direct.trace_rows
        << " cols=" << direct.cs.n_columns
        << " constraints="
        << direct.cs.constraints.size()
        << " direct_aliases="
        << direct.proof_cell_aliases.size()
        << " child_snapshot_aliases="
        << child_snapshot_aliases
        << " canonical_abi_cells="
        << schedule.canonical_v13_sources.size()
        << " max_degree="
        << direct.max_algebraic_degree);

    {
        auto bad = direct.columns;
        const auto& alias =
            direct.proof_cell_aliases.front();
        bad[alias.receipt_column][alias.receipt_row] =
            gf::Add(
                bad[alias.receipt_column][alias.receipt_row],
                gf::Fp3::One());
        BOOST_CHECK_GT(
            bridge::CountViolationsV12(
                direct.cs, bad),
            0U);
    }
    {
        auto bad = direct.columns;
        const auto& alias =
            direct.proof_cell_aliases.front();
        bad[alias.event_column][alias.event_row] =
            gf::Add(
                bad[alias.event_column][alias.event_row],
                gf::Fp3::One());
        bad[alias.receipt_column][alias.receipt_row] =
            bad[alias.event_column][alias.event_row];
        BOOST_CHECK_GT(
            bridge::CountViolationsV12(
                direct.cs, bad),
            0U);
    }
    {
        auto bad = direct.columns;
        const auto& layout = direct.layout;
        bad[layout.Carry(0)][1] =
            gf::Add(
                bad[layout.Carry(0)][1],
                gf::Fp3::One());
        BOOST_CHECK_GT(
            bridge::CountViolationsV12(
                direct.cs, bad),
            0U);
    }

    bridge::TypedSafeDirectParentProofV14 direct_proof;
    const uint256 direct_seed = TestSeed(0x764);
    const auto direct_begin =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        bridge::ProveTypedSafeDirectParentV14(
            direct, direct_seed,
            direct_proof, &why),
        why);
    const auto direct_prove_end =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        bridge::VerifyTypedSafeDirectParentProofV14(
            schedule.program, direct_proof,
            direct_seed,
            direct.transcript_commitment,
            &why),
        why);
    const auto direct_verify_end =
        std::chrono::steady_clock::now();
    BOOST_TEST_MESSAGE(
        "SAFE_V14_DIRECT_PROOF rows="
        << direct.trace_rows
        << " cols=" << direct.cs.n_columns
        << " prove_ms="
        << std::chrono::duration_cast<
               std::chrono::milliseconds>(
               direct_prove_end -
               direct_begin).count()
        << " verify_ms="
        << std::chrono::duration_cast<
               std::chrono::milliseconds>(
               direct_verify_end -
               direct_prove_end).count());

    BOOST_REQUIRE(
        !direct_proof.proof.batch.queries.empty());
    BOOST_REQUIRE_GT(
        direct_proof.proof.batch.queries[0]
            .row.values.size(),
        direct.proof_cell_aliases.front()
            .event_column);
    {
        // Proof-owned SAFE message cell: the opening no longer matches its
        // committed row and the real FRI/AIR verifier rejects.
        auto bad = direct_proof;
        const uint32_t column =
            direct.proof_cell_aliases.front()
                .event_column;
        bad.proof.batch.queries[0]
            .row.values[column] =
            gf::Add(
                bad.proof.batch.queries[0]
                    .row.values[column],
                gf::Fp3::One());
        BOOST_CHECK_MESSAGE(
            !bridge::VerifyTypedSafeDirectParentProofV14(
                schedule.program, bad,
                direct_seed,
                direct.transcript_commitment,
                &why),
            "proof-cell opening substitution accepted");
    }
    {
        // Ordered-event binding: a proof cannot be transplanted to a
        // different canonical event schedule.
        auto reordered = schedule.program;
        std::swap(reordered[0], reordered[1]);
        BOOST_CHECK_MESSAGE(
            !bridge::VerifyTypedSafeDirectParentProofV14(
                reordered, direct_proof,
                direct_seed,
                direct.transcript_commitment,
                &why),
            "ordered-event program transplant accepted");
    }
    {
        // The receipt boundary is public input to the rebuilt AIR.
        auto wrong_receipt =
            direct.transcript_commitment;
        wrong_receipt[0] =
            gf::Add(wrong_receipt[0], 1);
        BOOST_CHECK_MESSAGE(
            !bridge::VerifyTypedSafeDirectParentProofV14(
                schedule.program, direct_proof,
                direct_seed, wrong_receipt,
                &why),
            "wrong receipt boundary accepted");
    }
    {
        BOOST_CHECK_MESSAGE(
            !bridge::VerifyTypedSafeDirectParentProofV14(
                schedule.program, direct_proof,
                TestSeed(0x765),
                direct.transcript_commitment,
                &why),
            "proof accepted under a different external seed");
    }
    {
        // Query/opening integrity is enforced by the native FRI proof, not a
        // host witness-violation count.
        auto bad = direct_proof;
        bad.proof.batch.queries[0].index ^= 1U;
        BOOST_CHECK_MESSAGE(
            !bridge::VerifyTypedSafeDirectParentProofV14(
                schedule.program, bad,
                direct_seed,
                direct.transcript_commitment,
                &why),
            "query-index opening substitution accepted");
    }

    {
        auto bad = proved.proof;
        bad.air_constraint_lambda =
            gf::Add(
                bad.air_constraint_lambda,
                gf::Fp3::One());
        bridge::
            NativeSplitRapMultiRowTypedSafeScheduleV2
                rejected;
        BOOST_CHECK(
            !bridge::
                BuildNativeSplitRapMultiRowTypedSafeScheduleV2(
                    cs, bad, base_indices,
                    seed, rejected, &why));
        BOOST_CHECK(!rejected.valid);
    }
    {
        auto bad = proved.proof;
        bad.batch.queries.front().index ^= 1U;
        bridge::
            NativeSplitRapMultiRowTypedSafeScheduleV2
                rejected;
        BOOST_CHECK(
            !bridge::
                BuildNativeSplitRapMultiRowTypedSafeScheduleV2(
                    cs, bad, base_indices,
                    seed, rejected, &why));
        BOOST_CHECK(!rejected.valid);
    }
    {
        bridge::
            NativeSplitRapMultiRowTypedSafeScheduleV2
                rejected;
        BOOST_CHECK(
            !bridge::
                BuildNativeSplitRapMultiRowTypedSafeScheduleV2(
                    cs, proved.proof, base_indices,
                    TestSeed(0x763), rejected, &why));
        BOOST_CHECK(!rejected.valid);
    }
}

BOOST_AUTO_TEST_SUITE_END()
