// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

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

BOOST_AUTO_TEST_SUITE_END()
