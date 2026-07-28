// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>
#include <matmul/matmul_v4_rc_stage3_safe_v12_recursive_bridge.h>

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

BOOST_AUTO_TEST_SUITE_END()
