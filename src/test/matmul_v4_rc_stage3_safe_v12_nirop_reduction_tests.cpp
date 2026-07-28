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
        /*n_coeffs=*/4,
        /*n_lde=*/64,
        /*n_folds=*/2,
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
        proof.fold_roots = {
            TestDigest(base + 40),
            TestDigest(base + 50),
            TestDigest(base + 60),
        };
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

    std::vector<gf::Fp> sigma_core;
    if (!BuildTaxSigmaCoreV12(
            out.manifest, out.inputs.common, parent_seed,
            sigma_core, &why)) {
        throw std::runtime_error(why);
    }
    // Deterministic KAT produced by FindSharedGrindNonceV12 for this exact
    // shared-commitment sigma core. The verifier recomputes the full g=20
    // predicate; pinning the answer avoids a prover search in normal CI.
    out.inputs.shared_grind_nonce = UINT64_C(181'070);
    if (!CheckSharedGrindNonceV12(
            sigma_core, out.inputs.shared_grind_nonce, nullptr)) {
        throw std::runtime_error(
            "stage3:safe_v12_nirop:shared g20 KAT mismatch");
    }
    for (auto& lane :
         out.inputs.transcript.proof_witness.fri_lane) {
        lane.pow_grind_nonce =
            out.inputs.shared_grind_nonce;
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
            both_lanes_use_shared_nonce);
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
    BOOST_TEST(reduction.lanes == 2U);
    BOOST_TEST(reduction.queries_per_lane == 96U);
    BOOST_TEST(reduction.total_queries == 192U);
    BOOST_TEST(reduction.grind_bits == 20U);
    BOOST_TEST(reduction.proof_sites == 37'488'397ULL);
    BOOST_CHECK(reduction.parameters_read_from_shipped_construction);
    BOOST_CHECK(reduction.proof_site_arithmetic_manifest_valid);
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
        reduction.global_conditional_bits > 101.8);
    BOOST_CHECK(
        reduction.global_conditional_bits < 101.9);

    // Numeric margin is not a theorem. These are the exact premises that
    // still prevent certification and authority.
    BOOST_CHECK(
        !reduction.
            proof_site_upper_bound_recursively_enforced);
    BOOST_CHECK(
        !reduction.
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
    for (auto& lane :
         untaxed.transcript.proof_witness.fri_lane) {
        lane.pow_grind_nonce = cheap_nonce;
    }
    BOOST_CHECK(!BuildHybridReceiptV12(
        fixture.manifest, untaxed, unused, &why));

    // Paying for lane 0 does not permit a second lane-specific nonce.
    HybridInputsV12 split_nonce = fixture.inputs;
    ++split_nonce.transcript.proof_witness.
        fri_lane[1].pow_grind_nonce;
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

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_safe_v12_nirop_reduction
