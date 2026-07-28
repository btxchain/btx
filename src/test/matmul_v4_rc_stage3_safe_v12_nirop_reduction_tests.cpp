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
    out.inputs.common.trace = TestDigest(1'200);
    out.inputs.transcript.proof_witness.trace_commit =
        out.inputs.common.trace;
    for (uint32_t lane = 0; lane < kLaneCountV12; ++lane) {
        out.inputs.lane_claim[lane] = {
            out.inputs.common.statement,
            out.inputs.common.program,
            out.inputs.common.trace,
        };
        auto& proof =
            out.inputs.transcript.proof_witness.fri_lane[lane];
        const uint64_t base = 2'000 + 100 * lane;
        proof.shape_commit = TestDigest(base + 10);
        proof.row_root = TestDigest(base + 20);
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
    // sigma core. Pinning it keeps the ordinary test suite fast while the
    // verifier still recomputes the shipped g=20 predicate from first
    // principles. The prover search remains an executable public helper.
    out.inputs.shared_grind_nonce = UINT64_C(6'992'314);
    if (!CheckSharedGrindNonceV12(
            sigma_core, out.inputs.shared_grind_nonce, nullptr)) {
        throw std::runtime_error(
            "stage3:safe_v12_nirop:g20 KAT mismatch");
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

    // Nor can it substitute only one committed row-root while retaining the
    // old common parent seed.
    HybridInputsV12 changed_root = fixture.inputs;
    changed_root.transcript.proof_witness.
        fri_lane[1].row_root = TestDigest(9'100);
    BOOST_CHECK(!BuildHybridReceiptV12(
        fixture.manifest, changed_root, unused, &why));

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
