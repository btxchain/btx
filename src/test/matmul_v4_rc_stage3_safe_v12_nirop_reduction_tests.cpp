// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_safe_v12_nirop_reduction.h>

#include <boost/test/unit_test.hpp>

#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace matmul::v4::rc::stage3_safe_v12_nirop_reduction {
namespace {

ah::Digest TestDigest(uint64_t first)
{
    return {
        gf::FromU64(first),
        gf::FromU64(first + 1),
        gf::FromU64(first + 2),
        gf::FromU64(first + 3),
    };
}

fsair::ShapeV12 TestShape()
{
    return {
        /*child_w=*/3,
        /*child_n_rows=*/8,
        /*child_quotient_len=*/16,
        /*n_coeffs=*/64,
        /*n_lde=*/1024,
        /*n_folds=*/6,
    };
}

struct FixtureV12 {
    fsair::ManifestV12 manifest;
    HybridInputsV12 inputs;
    HybridReceiptV12 receipt;
};

FixtureV12 BuildFixture()
{
    FixtureV12 out;
    std::string why;
    if (!fsair::BuildManifestV12(
            TestShape(), out.manifest, &why)) {
        throw std::runtime_error(why);
    }

    out.inputs.common.statement = TestDigest(1'000);
    out.inputs.common.program = TestDigest(1'100);
    const ah::Digest shared_row_root = TestDigest(2'020);
    // V12 is a true shared-commitment construction: the AIR statement,
    // both lane claims and both FRI row roots name this exact digest.
    out.inputs.common.trace = shared_row_root;
    out.inputs.transcript.proof_witness.trace_commit =
        out.inputs.common.trace;
    ah::Digest canonical_shape{};
    if (!DeriveCanonicalShapeCommitV12(
            out.manifest,
            aht::RoleV12::TranscriptShapeCommit,
            canonical_shape, &why)) {
        throw std::runtime_error(why);
    }
    const TraceMetadataV12 canonical_metadata =
        CanonicalTraceMetadataV12(out.manifest);
    for (uint32_t lane = 0; lane < kLaneCountV12; ++lane) {
        out.inputs.lane_claim[lane] = {
            out.inputs.common.statement,
            out.inputs.common.program,
            out.inputs.common.trace,
        };
        out.inputs.lane_trace_metadata[lane] =
            canonical_metadata;
        auto& proof =
            out.inputs.transcript.proof_witness.fri_lane[lane];
        const uint64_t base = 2'000 + 100 * lane;
        proof.shape_commit = canonical_shape;
        proof.row_root = shared_row_root;
        proof.ood_evaluation_commit = TestDigest(base + 30);
        for (uint32_t fold = 0; fold <= 6; ++fold) {
            proof.fold_roots.push_back(
                TestDigest(base + 40 + 10 * fold));
        }
    }

    ah::Digest parent_seed{};
    if (!DeriveParentFsSeedV12(
            out.manifest, out.inputs.common,
            out.inputs.transcript.proof_witness,
            aht::RoleV12::ApplicationStatementCommitment,
            parent_seed, &why)) {
        throw std::runtime_error(why);
    }
    out.inputs.transcript.parent_statement.parent_fs_seed =
        parent_seed;

    std::array<ah::Digest, kLaneCountV12> terminal_receipts{};
    if (!fsair::DeriveFriTerminalReceiptsV12(
            out.manifest, out.inputs.transcript,
            terminal_receipts, &why)) {
        throw std::runtime_error(why);
    }
    std::vector<gf::Fp> sigma_core;
    if (!BuildTaxSigmaCoreV12(
            out.manifest, out.inputs.common, parent_seed,
            terminal_receipts,
            sigma_core, &why)) {
        throw std::runtime_error(why);
    }
    // Deterministic KAT for the acyclic transcript. The verifier recomputes
    // the full g20 predicate; pinning avoids a prover search in normal CI:
    // pre-FRI seed -> two terminal receipts -> one g20 tax -> queries.
    out.inputs.shared_grind_nonce = UINT64_C(831'039);
    out.inputs.transcript.parent_statement.
        shared_query_tax_nonce =
            out.inputs.shared_grind_nonce;
    if (!CheckSharedGrindNonceV12(
            sigma_core, out.inputs.shared_grind_nonce,
            &out.inputs.transcript.parent_statement.
                shared_query_tax_sigma)) {
        throw std::runtime_error(
            "stage3:safe_v12_nirop:shared g20 KAT mismatch");
    }
    if (!BuildHybridReceiptV12(
            out.manifest, out.inputs, out.receipt, &why) ||
        !ValidateHybridReceiptV12(
            out.manifest, out.inputs, out.receipt, &why)) {
        throw std::runtime_error(why);
    }
    return out;
}

const FixtureV12& Fixture()
{
    static const FixtureV12 fixture = BuildFixture();
    return fixture;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_safe_v12_nirop_reduction_tests)

BOOST_AUTO_TEST_CASE(
    dual_q96_common_join_tax_and_conditional_ledger_execute)
{
    const FixtureV12& fixture = Fixture();
    BOOST_TEST_MESSAGE(
        "deterministic shipped-g20 nonce="
        << fixture.inputs.shared_grind_nonce);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ValidateHybridReceiptV12(
            fixture.manifest, fixture.inputs,
            fixture.receipt, &why),
        why);
    BOOST_CHECK(fixture.receipt.valid);
    BOOST_CHECK(fixture.receipt.manifest_valid);
    BOOST_CHECK(fixture.receipt.common_binding_valid);
    BOOST_CHECK(
        fixture.receipt.trace_root_equality_air_valid);
    BOOST_CHECK(fixture.receipt.native_air_transcript_valid);
    BOOST_CHECK(
        fixture.receipt.typed_lane_domains_distinct);
    BOOST_CHECK(fixture.receipt.query_vectors_distinct);
    BOOST_CHECK(
        fixture.receipt.
            tax_sigma_and_nonce_bound_to_query_channels);
    BOOST_CHECK(
        fixture.receipt.query_channels_are_only_index_source);
    BOOST_CHECK(fixture.receipt.tax_satisfied);
    BOOST_CHECK(fixture.receipt.tax_air_constraints_zero);
    BOOST_TEST(
        fixture.receipt.common_binding.
            proof_dependent_preprocessed_columns == 0U);
    BOOST_CHECK(
        fixture.receipt.common_binding.
            both_lanes_equal_common_cells);
    BOOST_CHECK(
        fixture.receipt.common_binding.
            proof_bundle_bound_to_parent_seed);
    BOOST_CHECK(
        fixture.receipt.common_binding.
            fri_preamble_nonce_free);
    BOOST_CHECK(fixture.receipt.fri_terminal_receipts_bound);
    BOOST_CHECK(fixture.receipt.acyclic_prover_order_enforced);
    const auto& trace_air =
        fixture.receipt.trace_root_equality_air;
    BOOST_CHECK(trace_air.valid);
    BOOST_TEST(trace_air.cs.n_rows == 2U);
    BOOST_TEST(trace_air.cs.n_columns == 60U);
    BOOST_TEST(trace_air.equality_constraints == 48U);
    BOOST_TEST(trace_air.constraint_violations == 0U);
    BOOST_TEST(
        trace_air.verifier_owned_preprocessed_columns == 16U);
    BOOST_TEST(
        trace_air.proof_owned_preprocessed_columns == 0U);
    BOOST_CHECK(trace_air.common_trace_aliases_constrained);
    BOOST_CHECK(trace_air.metadata_aliases_constrained);
    BOOST_CHECK(
        trace_air.canonical_shape_aliases_constrained);
    BOOST_CHECK(trace_air.shared_row_root_constrained);
    BOOST_CHECK(
        trace_air.row_root_to_common_trace_constrained);
    BOOST_CHECK(
        trace_air.only_verifier_owned_values_preprocessed);
    BOOST_CHECK(
        fixture.inputs.transcript.proof_witness.
            fri_lane[0].shape_commit ==
        fixture.inputs.transcript.proof_witness.
            fri_lane[1].shape_commit);
    BOOST_CHECK(
        fixture.inputs.transcript.proof_witness.
            fri_lane[0].row_root ==
        fixture.inputs.transcript.proof_witness.
            fri_lane[1].row_root);
    BOOST_CHECK(
        fixture.inputs.transcript.proof_witness.
            fri_lane[0].row_root ==
        fixture.inputs.common.trace);
    BOOST_CHECK(
        fixture.inputs.transcript.proof_witness.
            fri_lane[0].ood_evaluation_commit !=
        fixture.inputs.transcript.proof_witness.
            fri_lane[1].ood_evaluation_commit);
    BOOST_CHECK(
        fixture.inputs.transcript.proof_witness.
            fri_lane[0].fold_roots !=
        fixture.inputs.transcript.proof_witness.
            fri_lane[1].fold_roots);

    const auto reduction = AssessShippedSoundnessReductionV12(
        fixture.manifest, fixture.inputs, fixture.receipt);
    const auto site_manifest =
        scenarios::BuildProductionProofSiteManifest(
            scenarios::SelectedProductionProofSitePolicy());
    BOOST_REQUIRE(
        ValidateProductionSiteManifestBindingV12(
            site_manifest));
    BOOST_TEST(reduction.lanes == 2U);
    BOOST_TEST(reduction.queries_per_lane == 96U);
    BOOST_TEST(reduction.total_queries == 192U);
    BOOST_TEST(reduction.grind_bits == 20U);
    BOOST_TEST(
        reduction.proof_sites ==
        site_manifest.total_proof_sites);
    BOOST_TEST(reduction.proof_sites > 37'488'397ULL);
    BOOST_CHECK(
        reduction.proof_site_manifest_commitment ==
        site_manifest.commitment);
    BOOST_CHECK(reduction.parameters_read_from_shipped_construction);
    BOOST_CHECK(reduction.proof_site_arithmetic_manifest_valid);
    BOOST_CHECK(
        reduction.executable_private_hash_site_capacity);
    BOOST_CHECK(reduction.common_transcript_join_executable);
    BOOST_CHECK(
        reduction.
            common_trace_root_equality_air_executable);
    BOOST_CHECK(
        !reduction.
            common_trace_root_equality_recursively_consumed);
    BOOST_CHECK(reduction.lane_domains_and_tags_distinct);
    BOOST_CHECK(reduction.lane_query_vectors_distinct);
    BOOST_CHECK(reduction.shared_nonce_tax_executable);
    BOOST_CHECK(
        reduction.
            multiplicative_then_additive_expression_machine_checked);
    // The corrected inventory no longer supports the stale ~101.9-bit
    // claim, but its ~91.2-bit conditional value still exceeds the explicit
    // 64-bit V1 consensus class.
    BOOST_CHECK(reduction.conditional_numeric_v1_target_met);
    BOOST_CHECK_CLOSE(
        reduction.lane_proximity_bits,
        87.60356724, 1.0e-6);
    BOOST_CHECK_CLOSE(
        reduction.multiplicative_pair_bits,
        175.20713448, 1.0e-6);
    BOOST_CHECK_CLOSE(
        reduction.pair_after_single_grind_bits,
        155.20713448, 1.0e-6);
    BOOST_CHECK(
        reduction.global_conditional_bits > 91.2);
    BOOST_CHECK(
        reduction.global_conditional_bits < 91.3);

    // Numeric margin is not a theorem. These are the exact premises that
    // still prevent certification and authority.
    BOOST_CHECK(
        !reduction.
            proof_site_upper_bound_recursively_enforced);
    BOOST_CHECK(
        reduction.
            shared_nonce_tax_is_sole_query_entropy_source);
    BOOST_CHECK(
        !reduction.lane_independence_reduction_complete);
    BOOST_CHECK(
        !reduction.
            common_commitment_binding_reduction_complete);
    BOOST_CHECK(
        !reduction.concrete_safe_nirop_reduction_complete);
    BOOST_CHECK(!reduction.nirop_reduction_certified);
    BOOST_TEST(reduction.residual_premises.size() >= 5U);
    BOOST_CHECK(kDualQ96CommonTranscriptJoinExecutableV12);
    BOOST_CHECK(kDualQ96SharedNonceTaxPredicateExecutableV12);
    BOOST_CHECK(
        kDualQ96SharedTraceRootEqualityAirExecutableV12);
    BOOST_CHECK(
        !kDualQ96CommonCommitmentHybridReductionCertifiedV12);
    BOOST_CHECK(!kDualQ96NiropReductionCertifiedV12);
    BOOST_CHECK(!kDualQ96GlobalReductionCertifiedV12);
    BOOST_CHECK(!kDualQ96AuthorityReadyV12);

    // The V12 reduction accepts only the exact selected site inventory.
    // Removing a family and recomputing neither its arithmetic nor its
    // commitment cannot lower the union term.
    auto omitted_site = site_manifest;
    omitted_site.entries.pop_back();
    BOOST_CHECK(
        !ValidateProductionSiteManifestBindingV12(
            omitted_site));

    // Likewise, changing the proof-owned private-boundary packing capacity
    // is a real site-count substitution, not a free theorem parameter.
    auto capacity_substitution = site_manifest;
    BOOST_REQUIRE(!capacity_substitution.entries.empty());
    capacity_substitution.entries[0].units_per_site = 4096;
    BOOST_CHECK(
        !ValidateProductionSiteManifestBindingV12(
            capacity_substitution));
}

BOOST_AUTO_TEST_CASE(
    lane_commitment_domain_query_and_role_substitutions_reject)
{
    const FixtureV12& fixture = Fixture();
    HybridReceiptV12 unused;
    std::string why;

    // A child may not substitute a lane-local claim for the common trace.
    HybridInputsV12 changed_claim = fixture.inputs;
    changed_claim.lane_claim[1].trace = TestDigest(9'000);
    BOOST_CHECK(!BuildHybridReceiptV12(
        fixture.manifest, changed_claim, unused, &why));

    // A two-root envelope is not the V12 construction. Both independently
    // typed Q96 FS lanes must consume one exact shared commitment.
    HybridInputsV12 changed_root = fixture.inputs;
    changed_root.transcript.proof_witness.
        fri_lane[1].row_root = TestDigest(9'100);
    BOOST_CHECK(!BuildHybridReceiptV12(
        fixture.manifest, changed_root, unused, &why));

    // Aggregate equality would miss +delta/-delta compensation. The direct
    // per-coordinate shared-root constraints reject it.
    HybridInputsV12 compensated = fixture.inputs;
    compensated.transcript.proof_witness.
        fri_lane[0].row_root[0] = gf::Add(
            compensated.transcript.proof_witness.
                fri_lane[0].row_root[0],
            1);
    compensated.transcript.proof_witness.
        fri_lane[1].row_root[0] = gf::Sub(
            compensated.transcript.proof_witness.
                fri_lane[1].row_root[0],
            1);
    TraceRootEqualityAirV12 bad_trace_air;
    BOOST_CHECK(!BuildTraceRootEqualityAirV12(
        fixture.manifest, compensated.common,
        compensated.lane_claim,
        compensated.lane_trace_metadata,
        compensated.transcript.proof_witness,
        bad_trace_air, &why));

    // Even changing both metadata copies together cannot move a
    // verifier-derived shape field.
    HybridInputsV12 metadata_swap = fixture.inputs;
    ++metadata_swap.lane_trace_metadata[0].trace_columns;
    ++metadata_swap.lane_trace_metadata[1].trace_columns;
    BOOST_CHECK(!BuildTraceRootEqualityAirV12(
        fixture.manifest, metadata_swap.common,
        metadata_swap.lane_claim,
        metadata_swap.lane_trace_metadata,
        metadata_swap.transcript.proof_witness,
        bad_trace_air, &why));

    // A real digest under an unrelated typed oracle role is not a canonical
    // V12 shape commitment, even when copied consistently into both lanes.
    ah::Digest wrong_shape{};
    BOOST_REQUIRE(DeriveCanonicalShapeCommitV12(
        fixture.manifest, aht::RoleV12::MerkleRowLeaf,
        wrong_shape, &why));
    BOOST_CHECK(
        wrong_shape !=
        fixture.receipt.trace_root_equality_air.
            canonical_shape_commit);
    HybridInputsV12 shape_role_swap = fixture.inputs;
    for (auto& lane :
         shape_role_swap.transcript.proof_witness.fri_lane) {
        lane.shape_commit = wrong_shape;
    }
    BOOST_CHECK(!BuildTraceRootEqualityAirV12(
        fixture.manifest, shape_role_swap.common,
        shape_role_swap.lane_claim,
        shape_role_swap.lane_trace_metadata,
        shape_role_swap.transcript.proof_witness,
        bad_trace_air, &why));

    // A simultaneous shared-root substitution cannot preserve the
    // verifier-owned common trace commitment. Direct per-lane aliases make
    // the local equality AIR reject without relying on the parent seed.
    HybridInputsV12 shared_root_swap = fixture.inputs;
    const ah::Digest substituted_root = TestDigest(9'200);
    for (auto& lane :
         shared_root_swap.transcript.proof_witness.fri_lane) {
        lane.row_root = substituted_root;
    }
    BOOST_CHECK(!BuildTraceRootEqualityAirV12(
        fixture.manifest, shared_root_swap.common,
        shared_root_swap.lane_claim,
        shared_root_swap.lane_trace_metadata,
        shared_root_swap.transcript.proof_witness,
        bad_trace_air, &why));
    BOOST_CHECK(!BuildHybridReceiptV12(
        fixture.manifest, shared_root_swap, unused, &why));

    // Replacing the common trace, AIR trace, both lane claims and both row
    // roots together satisfies only the local equality relation. The
    // unchanged parent seed remains bound to the original public trace and
    // causes the integrated join to reject.
    HybridInputsV12 whole_trace_swap = fixture.inputs;
    const ah::Digest substituted_trace = TestDigest(9'300);
    whole_trace_swap.common.trace = substituted_trace;
    whole_trace_swap.transcript.proof_witness.trace_commit =
        substituted_trace;
    for (uint32_t lane = 0; lane < kLaneCountV12; ++lane) {
        whole_trace_swap.lane_claim[lane].trace =
            substituted_trace;
        whole_trace_swap.transcript.proof_witness.
            fri_lane[lane].row_root = substituted_trace;
    }
    BOOST_REQUIRE(BuildTraceRootEqualityAirV12(
        fixture.manifest, whole_trace_swap.common,
        whole_trace_swap.lane_claim,
        whole_trace_swap.lane_trace_metadata,
        whole_trace_swap.transcript.proof_witness,
        bad_trace_air, &why));
    BOOST_CHECK(!BuildHybridReceiptV12(
        fixture.manifest, whole_trace_swap, unused, &why));

    // A copied lane manifest has a valid-looking width but merges the typed
    // oracle domains. Canonical reconstruction rejects it.
    fsair::ManifestV12 merged_domain = fixture.manifest;
    merged_domain.fri_lane[1] =
        merged_domain.fri_lane[0];
    BOOST_CHECK(
        !fsair::ValidateManifestV12(merged_domain, &why));
    BOOST_CHECK(!BuildHybridReceiptV12(
        merged_domain, fixture.inputs, unused, &why));

    // Copying one lane's query vector into the other is rejected from the
    // complete AIR transcript, not only by an advisory distinctness flag.
    HybridReceiptV12 shared_queries = fixture.receipt;
    shared_queries.transcript_air.fri_lane[1].
        projected_execution.query_indices =
        shared_queries.transcript_air.fri_lane[0].
            projected_execution.query_indices;
    shared_queries.query_indices[1] =
        shared_queries.query_indices[0];
    BOOST_CHECK(!ValidateHybridReceiptV12(
        fixture.manifest, fixture.inputs,
        shared_queries, &why));

    // Mutating a proof-owned equality carrier is detected by reconstruction
    // and by the linear constraints, not trusted as a receipt boolean.
    HybridReceiptV12 changed_equality_air = fixture.receipt;
    changed_equality_air.trace_root_equality_air.
        columns.back()[0] = gf::Add(
            changed_equality_air.trace_root_equality_air.
                columns.back()[0],
            gf::Fp3::One());
    BOOST_CHECK(!ValidateHybridReceiptV12(
        fixture.manifest, fixture.inputs,
        changed_equality_air, &why));

    // The final SAFE outputs are part of the child receipt and the post-FRI
    // tax preimage. They cannot be discarded or substituted.
    HybridReceiptV12 changed_terminal_receipt = fixture.receipt;
    changed_terminal_receipt.fri_terminal_receipts[0][0] =
        gf::Add(
            changed_terminal_receipt.
                fri_terminal_receipts[0][0],
            1);
    BOOST_CHECK(!ValidateHybridReceiptV12(
        fixture.manifest, fixture.inputs,
        changed_terminal_receipt, &why));

    // Re-tagging the common parent derivation with an unrelated oracle role
    // gives a real digest, but never the canonical parent FS seed.
    ah::Digest role_swapped_seed{};
    BOOST_REQUIRE(DeriveParentFsSeedV12(
        fixture.manifest, fixture.inputs.common,
        fixture.inputs.transcript.proof_witness,
        aht::RoleV12::MerkleRowLeaf,
        role_swapped_seed, &why));
    BOOST_CHECK(
        role_swapped_seed !=
        fixture.inputs.transcript.parent_statement.
            parent_fs_seed);
    HybridInputsV12 role_swap = fixture.inputs;
    role_swap.transcript.parent_statement.parent_fs_seed =
        role_swapped_seed;
    BOOST_CHECK(!BuildHybridReceiptV12(
        fixture.manifest, role_swap, unused, &why));
}

BOOST_AUTO_TEST_CASE(
    shared_nonce_and_goldilocks_alias_attacks_reject)
{
    const FixtureV12& fixture = Fixture();
    HybridReceiptV12 unused;
    std::string why;

    uint64_t cheap_nonce = 0;
    while (CheckSharedGrindNonceV12(
        fixture.receipt.tax_sigma_core, cheap_nonce, nullptr)) {
        ++cheap_nonce;
    }
    HybridInputsV12 untaxed = fixture.inputs;
    untaxed.shared_grind_nonce = cheap_nonce;
    untaxed.transcript.parent_statement.
        shared_query_tax_nonce = cheap_nonce;
    const bool cheap_nonce_satisfies_tax =
        CheckSharedGrindNonceV12(
        fixture.receipt.tax_sigma_core, cheap_nonce,
        &untaxed.transcript.parent_statement.
            shared_query_tax_sigma);
    BOOST_CHECK(!cheap_nonce_satisfies_tax);
    BOOST_CHECK(!BuildHybridReceiptV12(
        fixture.manifest, untaxed, unused, &why));

    // The nonce is a single post-terminal value. It cannot be injected into
    // a pre-tax lane or changed in only the query request.
    HybridInputsV12 split_nonce = fixture.inputs;
    ++split_nonce.transcript.parent_statement.
        shared_query_tax_nonce;
    BOOST_CHECK(!BuildHybridReceiptV12(
        fixture.manifest, split_nonce, unused, &why));

    // p == 1 (mod 2^20): B=x+p can fake twenty low zero bits. The actual
    // canonicity constraint rejects that witness.
    const gf::Fp nonconforming =
        gf::FromU64((UINT64_C(1) << 20) - 1);
    BOOST_CHECK(!Fri3AlgCheckAlgebraicGrind(
        nonconforming, kTaxedGrindBitsV12));
    const auto aliased = BuildFri3AlgGrindPredicateAirV1(
        nonconforming, kTaxedGrindBitsV12,
        /*use_aliased_witness=*/true);
    BOOST_REQUIRE_MESSAGE(aliased.valid, aliased.note);
    BOOST_CHECK(aliased.canonicity_constrained);
    BOOST_CHECK_GT(aliased.violations, 0U);
}

BOOST_AUTO_TEST_CASE(
    prover_order_is_acyclic_and_future_roots_change_taxed_queries)
{
    const FixtureV12& fixture = Fixture();
    std::string why;

    // Step 1 is pre-FRI. Future OOD/fold roots do not enter the parent seed.
    HybridInputsV12 changed = fixture.inputs;
    changed.transcript.proof_witness.
        fri_lane[1].fold_roots.back()[0] = gf::Add(
            changed.transcript.proof_witness.
                fri_lane[1].fold_roots.back()[0],
            1);
    ah::Digest unchanged_parent{};
    BOOST_REQUIRE(DeriveParentFsSeedV12(
        fixture.manifest, changed.common,
        changed.transcript.proof_witness,
        aht::RoleV12::ApplicationStatementCommitment,
        unchanged_parent, &why));
    BOOST_CHECK(
        unchanged_parent ==
        fixture.inputs.transcript.parent_statement.parent_fs_seed);

    // Step 2 executes the two sequential FRI transcripts without reading a
    // grind nonce or query-tax sigma.
    std::array<ah::Digest, kLaneCountV12> receipts{};
    BOOST_REQUIRE(fsair::DeriveFriTerminalReceiptsV12(
        fixture.manifest, changed.transcript, receipts, &why));
    BOOST_CHECK(
        receipts != fixture.receipt.fri_terminal_receipts);

    // Step 3 binds both terminal receipts, pays one g20 tax, and only then
    // executes the two independently typed query squeezes.
    std::vector<gf::Fp> sigma_core;
    BOOST_REQUIRE(BuildTaxSigmaCoreV12(
        fixture.manifest, changed.common, unchanged_parent,
        receipts, sigma_core, &why));
    BOOST_CHECK(sigma_core != fixture.receipt.tax_sigma_core);
    BOOST_REQUIRE(FindSharedGrindNonceV12(
        sigma_core, changed.shared_grind_nonce, 0, &why));
    changed.transcript.parent_statement.shared_query_tax_nonce =
        changed.shared_grind_nonce;
    BOOST_REQUIRE(CheckSharedGrindNonceV12(
        sigma_core, changed.shared_grind_nonce,
        &changed.transcript.parent_statement.
            shared_query_tax_sigma));
    HybridReceiptV12 changed_receipt;
    BOOST_REQUIRE(BuildHybridReceiptV12(
        fixture.manifest, changed, changed_receipt, &why));
    BOOST_CHECK(
        changed_receipt.query_indices !=
        fixture.receipt.query_indices);

    // Moving the nonce earlier cannot affect either FRI receipt; trying to
    // reuse the old taxed sigma with a changed nonce is rejected instead of
    // inducing a transcript fixed point.
    HybridInputsV12 early_nonce = fixture.inputs;
    ++early_nonce.transcript.parent_statement.
        shared_query_tax_nonce;
    std::array<ah::Digest, kLaneCountV12> same_receipts{};
    BOOST_REQUIRE(fsair::DeriveFriTerminalReceiptsV12(
        fixture.manifest, early_nonce.transcript,
        same_receipts, &why));
    BOOST_CHECK(
        same_receipts ==
        fixture.receipt.fri_terminal_receipts);
    HybridReceiptV12 unused;
    BOOST_CHECK(!BuildHybridReceiptV12(
        fixture.manifest, early_nonce, unused, &why));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_safe_v12_nirop_reduction
