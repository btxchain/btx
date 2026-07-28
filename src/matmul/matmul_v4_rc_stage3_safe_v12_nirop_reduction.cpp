// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_safe_v12_nirop_reduction.h>

#include <algorithm>
#include <cmath>
#include <limits>

namespace matmul::v4::rc::stage3_safe_v12_nirop_reduction {
namespace {

bool Fail(std::string* why, const std::string& text)
{
    if (why != nullptr) {
        *why = "stage3:safe_v12_nirop:" + text;
    }
    return false;
}

bool CanonicalDigest(const ah::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp lane) { return lane < gf::kP; });
}

void AppendDigest(
    std::vector<gf::Fp>& lanes, const ah::Digest& digest)
{
    lanes.insert(lanes.end(), digest.begin(), digest.end());
}

void AppendU32(std::vector<gf::Fp>& lanes, uint32_t value)
{
    lanes.push_back(gf::FromU64(value));
}

std::vector<uint8_t> CommonBindingDomain()
{
    static constexpr char kDomain[] =
        "BTX_STAGE3_V12_DUAL_Q96_COMMON_BINDING";
    return std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(kDomain),
        reinterpret_cast<const uint8_t*>(kDomain) +
            sizeof(kDomain) - 1);
}

bool CanonicalCommon(
    const CommonCommitmentsV12& common)
{
    return CanonicalDigest(common.statement) &&
        CanonicalDigest(common.program) &&
        CanonicalDigest(common.trace);
}

bool CanonicalProofBundle(
    const fsair::ProofWitnessInputsV12& proof)
{
    if (!CanonicalDigest(proof.trace_commit)) return false;
    for (const auto& lane : proof.fri_lane) {
        if (!CanonicalDigest(lane.shape_commit) ||
            !CanonicalDigest(lane.row_root) ||
            !CanonicalDigest(lane.ood_evaluation_commit)) {
            return false;
        }
        for (const ah::Digest& root : lane.fold_roots) {
            if (!CanonicalDigest(root)) return false;
        }
    }
    return true;
}

LaneCommonClaimV12 ClaimFor(
    const CommonCommitmentsV12& common)
{
    return {common.statement, common.program, common.trace};
}

bool ClaimsEqualCommon(
    const CommonCommitmentsV12& common,
    const std::array<LaneCommonClaimV12, kLaneCountV12>& claims)
{
    const LaneCommonClaimV12 expected = ClaimFor(common);
    return std::all_of(
        claims.begin(), claims.end(),
        [&](const LaneCommonClaimV12& claim) {
            return claim == expected;
        });
}

bool SameTaxAir(
    const Fri3AlgGrindPredicateAirV1& left,
    const Fri3AlgGrindPredicateAirV1& right)
{
    return left.n_rows == right.n_rows &&
        left.n_columns == right.n_columns &&
        left.n_constraints == right.n_constraints &&
        left.bit_columns == right.bit_columns &&
        left.tax_bits == right.tax_bits &&
        left.max_alg_degree == right.max_alg_degree &&
        left.violations == right.violations &&
        left.booleanity_constrained ==
            right.booleanity_constrained &&
        left.canonicity_constrained ==
            right.canonicity_constrained &&
        left.tax_constrained == right.tax_constrained &&
        left.valid == right.valid;
}

bool SameHybridReceipt(
    const HybridReceiptV12& left,
    const HybridReceiptV12& right)
{
    return left.common_binding == right.common_binding &&
        left.tax_sigma_core == right.tax_sigma_core &&
        left.tax_sigma == right.tax_sigma &&
        SameTaxAir(
            left.tax_predicate_air,
            right.tax_predicate_air) &&
        left.query_indices == right.query_indices &&
        left.manifest_valid == right.manifest_valid &&
        left.common_binding_valid ==
            right.common_binding_valid &&
        left.native_air_transcript_valid ==
            right.native_air_transcript_valid &&
        left.typed_lane_domains_distinct ==
            right.typed_lane_domains_distinct &&
        left.query_vectors_distinct ==
            right.query_vectors_distinct &&
        left.tax_satisfied == right.tax_satisfied &&
        left.tax_air_constraints_zero ==
            right.tax_air_constraints_zero &&
        left.valid == right.valid;
}

bool NearlyEqual(
    long double left, long double right,
    long double relative_tolerance = 1.0e-12L)
{
    const long double scale = std::max(
        {1.0e-300L, std::fabs(left), std::fabs(right)});
    return std::fabs(left - right) <=
        relative_tolerance * scale;
}

} // namespace

bool DeriveParentFsSeedV12(
    const fsair::ManifestV12& manifest,
    const CommonCommitmentsV12& common,
    const fsair::ProofWitnessInputsV12& proof_witness,
    aht::RoleV12 role, ah::Digest& seed,
    std::string* why)
{
    seed = {};
    if (!fsair::ValidateManifestV12(manifest, why) ||
        !CanonicalCommon(common) ||
        !CanonicalProofBundle(proof_witness) ||
        proof_witness.trace_commit != common.trace) {
        return Fail(why, "noncanonical or inconsistent common bundle");
    }
    for (const auto& lane : proof_witness.fri_lane) {
        if (lane.fold_roots.size() !=
            static_cast<uint64_t>(manifest.shape.n_folds) + 1) {
            return Fail(why, "fold-root count mismatch");
        }
    }

    std::vector<gf::Fp> message;
    message.reserve(
        16 + 12 +
        2 * (12 + 4 * (manifest.shape.n_folds + 1)));
    message.push_back(kCommonBindingMagicV12);
    AppendU32(message, kProtocolVersionV12);
    AppendU32(message, kQueriesPerLaneV12);
    AppendU32(message, kLaneCountV12);
    AppendU32(message, manifest.shape.child_w);
    AppendU32(message, manifest.shape.child_n_rows);
    AppendU32(message, manifest.shape.child_quotient_len);
    AppendU32(message, manifest.shape.n_coeffs);
    AppendU32(message, manifest.shape.n_lde);
    AppendU32(message, manifest.shape.n_folds);
    AppendDigest(message, common.statement);
    AppendDigest(message, common.program);
    AppendDigest(message, common.trace);
    for (uint32_t lane = 0; lane < kLaneCountV12; ++lane) {
        const auto& proof = proof_witness.fri_lane[lane];
        AppendU32(message, lane);
        AppendDigest(message, proof.shape_commit);
        AppendDigest(message, proof.row_root);
        AppendDigest(message, proof.ood_evaluation_commit);
        AppendU32(
            message,
            static_cast<uint32_t>(proof.fold_roots.size()));
        for (const ah::Digest& root : proof.fold_roots) {
            AppendDigest(message, root);
        }
    }
    safe::SafeCoreResultV12 audit;
    if (!safe::SafeCoreDigestV12(
            role, CommonBindingDomain(), message, seed,
            &audit, why) ||
        !CanonicalDigest(seed) ||
        audit.tag_stats.sha256d_calls == 0 ||
        audit.cost.published_algorithm_poseidon_calls == 0) {
        seed = {};
        return Fail(why, "SAFECore common binding derivation");
    }
    return true;
}

bool BuildTaxSigmaCoreV12(
    const fsair::ManifestV12& manifest,
    const CommonCommitmentsV12& common,
    const ah::Digest& parent_fs_seed,
    std::vector<gf::Fp>& sigma_core,
    std::string* why)
{
    sigma_core.clear();
    if (!fsair::ValidateManifestV12(manifest, why) ||
        !CanonicalCommon(common) ||
        !CanonicalDigest(parent_fs_seed)) {
        return Fail(why, "invalid tax sigma inputs");
    }
    sigma_core.reserve(40);
    sigma_core.push_back(kCommonBindingMagicV12);
    AppendU32(sigma_core, kProtocolVersionV12);
    AppendU32(sigma_core, kQueriesPerLaneV12);
    AppendU32(sigma_core, kTaxedGrindBitsV12);
    AppendDigest(sigma_core, parent_fs_seed);
    AppendDigest(sigma_core, common.statement);
    AppendDigest(sigma_core, common.program);
    AppendDigest(sigma_core, common.trace);
    for (const auto& tag : {
             manifest.air_quotient.safe_manifest.tag,
             manifest.fri_lane[0].safe_manifest.tag,
             manifest.fri_lane[1].safe_manifest.tag}) {
        sigma_core.insert(
            sigma_core.end(), tag.begin(), tag.end());
    }
    AppendU32(sigma_core, manifest.shape.child_w);
    AppendU32(sigma_core, manifest.shape.child_n_rows);
    AppendU32(sigma_core, manifest.shape.child_quotient_len);
    AppendU32(sigma_core, manifest.shape.n_coeffs);
    AppendU32(sigma_core, manifest.shape.n_lde);
    AppendU32(sigma_core, manifest.shape.n_folds);
    return true;
}

bool CheckSharedGrindNonceV12(
    const std::vector<gf::Fp>& sigma_core, uint64_t nonce,
    ah::Digest* sigma)
{
    if (sigma_core.empty() ||
        std::any_of(
            sigma_core.begin(), sigma_core.end(),
            [](gf::Fp lane) { return lane >= gf::kP; })) {
        if (sigma != nullptr) *sigma = {};
        return false;
    }
    const ah::Digest derived =
        Fri3AlgAlgebraicSqueeze(sigma_core, nonce);
    if (sigma != nullptr) *sigma = derived;
    return Fri3AlgCheckAlgebraicGrind(
        derived[0], kTaxedGrindBitsV12);
}

bool FindSharedGrindNonceV12(
    const std::vector<gf::Fp>& sigma_core, uint64_t& nonce,
    uint64_t max_iters, std::string* why)
{
    nonce = 0;
    if (sigma_core.empty() ||
        std::any_of(
            sigma_core.begin(), sigma_core.end(),
            [](gf::Fp lane) { return lane >= gf::kP; })) {
        return Fail(why, "invalid grind sigma core");
    }
    const auto found = Fri3AlgGrindAlgebraicSqueeze(
        sigma_core, kTaxedGrindBitsV12, max_iters);
    if (!found.has_value()) {
        return Fail(why, "shared taxed nonce search exhausted");
    }
    nonce = *found;
    return CheckSharedGrindNonceV12(
        sigma_core, nonce, nullptr);
}

bool BuildHybridReceiptV12(
    const fsair::ManifestV12& manifest,
    const HybridInputsV12& inputs,
    HybridReceiptV12& receipt,
    std::string* why)
{
    receipt = {};
    if (!fsair::ValidateManifestV12(manifest, why)) {
        return Fail(why, "manifest invalid");
    }
    receipt.manifest_valid = true;

    CommonBindingReceiptV12 binding;
    binding.binding_role =
        aht::RoleV12::ApplicationStatementCommitment;
    binding.common_statement = inputs.common.statement;
    binding.common_program = inputs.common.program;
    binding.common_trace = inputs.common.trace;
    binding.lane_claim = inputs.lane_claim;
    binding.proof_dependent_preprocessed_columns = 0;
    binding.common_cells_canonical =
        CanonicalCommon(inputs.common);
    binding.both_lanes_equal_common_cells =
        ClaimsEqualCommon(inputs.common, inputs.lane_claim);
    binding.transcript_trace_equals_common_trace =
        inputs.transcript.proof_witness.trace_commit ==
        inputs.common.trace;
    binding.both_lanes_use_shared_nonce =
        std::all_of(
            inputs.transcript.proof_witness.fri_lane.begin(),
            inputs.transcript.proof_witness.fri_lane.end(),
            [&](const auto& lane) {
                return lane.pow_grind_nonce ==
                    inputs.shared_grind_nonce;
            });
    if (!DeriveParentFsSeedV12(
            manifest, inputs.common,
            inputs.transcript.proof_witness,
            binding.binding_role,
            binding.parent_fs_seed, why)) {
        return false;
    }
    binding.proof_bundle_bound_to_parent_seed =
        binding.parent_fs_seed ==
        inputs.transcript.parent_statement.parent_fs_seed;
    binding.valid =
        binding.common_cells_canonical &&
        binding.both_lanes_equal_common_cells &&
        binding.proof_bundle_bound_to_parent_seed &&
        binding.transcript_trace_equals_common_trace &&
        binding.both_lanes_use_shared_nonce &&
        binding.proof_dependent_preprocessed_columns == 0;
    binding.note = binding.valid
        ? "stage3:safe_v12_nirop:common_transcript_join_ok"
        : "stage3:safe_v12_nirop:common_transcript_join_failure";
    if (!binding.valid) {
        return Fail(why, "common binding mismatch");
    }
    receipt.common_binding = binding;
    receipt.common_binding_valid = true;

    if (!BuildTaxSigmaCoreV12(
            manifest, inputs.common, binding.parent_fs_seed,
            receipt.tax_sigma_core, why)) {
        return false;
    }
    receipt.tax_satisfied = CheckSharedGrindNonceV12(
        receipt.tax_sigma_core, inputs.shared_grind_nonce,
        &receipt.tax_sigma);
    if (!receipt.tax_satisfied) {
        return Fail(why, "shared nonce does not satisfy g=20 tax");
    }
    receipt.tax_predicate_air =
        BuildFri3AlgGrindPredicateAirV1(
            receipt.tax_sigma[0],
            kTaxedGrindBitsV12,
            /*use_aliased_witness=*/false);
    receipt.tax_air_constraints_zero =
        receipt.tax_predicate_air.valid &&
        receipt.tax_predicate_air.booleanity_constrained &&
        receipt.tax_predicate_air.canonicity_constrained &&
        receipt.tax_predicate_air.tax_constrained &&
        receipt.tax_predicate_air.tax_bits ==
            kTaxedGrindBitsV12 &&
        receipt.tax_predicate_air.violations == 0;
    if (!receipt.tax_air_constraints_zero) {
        return Fail(why, "tax predicate AIR failed");
    }

    if (!fsair::BuildAirWitnessV12(
            manifest, inputs.transcript,
            receipt.transcript_air, why) ||
        !fsair::ValidateAirWitnessV12(
            manifest, inputs.transcript,
            receipt.transcript_air, why)) {
        return false;
    }
    receipt.native_air_transcript_valid = true;
    receipt.typed_lane_domains_distinct =
        manifest.fri_lane[0].typed_domain !=
            manifest.fri_lane[1].typed_domain &&
        manifest.fri_lane[0].safe_manifest.tag !=
            manifest.fri_lane[1].safe_manifest.tag;
    for (uint32_t lane = 0; lane < kLaneCountV12; ++lane) {
        receipt.query_indices[lane] =
            receipt.transcript_air.fri_lane[lane].
                projected_execution.query_indices;
        if (receipt.query_indices[lane].size() !=
            kQueriesPerLaneV12) {
            return Fail(why, "query count mismatch");
        }
    }
    receipt.query_vectors_distinct =
        receipt.query_indices[0] !=
        receipt.query_indices[1];
    receipt.valid =
        receipt.manifest_valid &&
        receipt.common_binding_valid &&
        receipt.native_air_transcript_valid &&
        receipt.typed_lane_domains_distinct &&
        receipt.query_vectors_distinct &&
        receipt.tax_satisfied &&
        receipt.tax_air_constraints_zero;
    receipt.note = receipt.valid
        ? "stage3:safe_v12_nirop:"
          "dual_q96_common_join_and_tax_executable"
        : "stage3:safe_v12_nirop:hybrid_receipt_failure";
    return receipt.valid;
}

bool ValidateHybridReceiptV12(
    const fsair::ManifestV12& manifest,
    const HybridInputsV12& inputs,
    const HybridReceiptV12& receipt,
    std::string* why)
{
    if (!receipt.valid ||
        !fsair::ValidateAirWitnessV12(
            manifest, inputs.transcript,
            receipt.transcript_air, why)) {
        return Fail(why, "supplied hybrid receipt invalid");
    }
    HybridReceiptV12 expected;
    if (!BuildHybridReceiptV12(
            manifest, inputs, expected, why)) {
        return false;
    }
    if (!SameHybridReceipt(receipt, expected)) {
        return Fail(why, "hybrid receipt mismatch");
    }
    return true;
}

ShippedSoundnessReductionV12
AssessShippedSoundnessReductionV12(
    const fsair::ManifestV12& manifest,
    const HybridInputsV12& inputs,
    const HybridReceiptV12& receipt)
{
    ShippedSoundnessReductionV12 out;
    out.lanes = kLaneCountV12;
    out.queries_per_lane = kQueriesPerLaneV12;
    out.total_queries =
        kLaneCountV12 * kQueriesPerLaneV12;
    out.grind_bits = kTaxedGrindBitsV12;
    out.proof_sites = kProductionProofSitesV12;
    out.site_union_bits =
        std::log2(static_cast<double>(out.proof_sites));
    out.proximity_ratio = 17.0 / 32.0;
    out.proximity_bits_per_query =
        std::log2(32.0 / 17.0);

    out.lane_failure_probability = std::pow(
        static_cast<long double>(17.0L / 32.0L),
        static_cast<long double>(out.queries_per_lane));
    out.multiplicative_pair_failure_probability =
        out.lane_failure_probability *
        out.lane_failure_probability;
    out.grind_amplified_pair_failure_probability =
        std::ldexp(
            out.multiplicative_pair_failure_probability,
            static_cast<int>(out.grind_bits));
    out.common_binding_failure_probability =
        std::ldexp(
            1.0L,
            -static_cast<int>(kCommonBindingBitsV12));
    out.conditional_safe_nirop_failure_probability =
        std::ldexp(
            1.0L,
            -static_cast<int>(
                kConditionalSafeNiropBitsV12));
    out.per_site_conditional_failure_probability =
        out.grind_amplified_pair_failure_probability +
        out.common_binding_failure_probability +
        out.conditional_safe_nirop_failure_probability;
    out.global_conditional_failure_probability =
        static_cast<long double>(out.proof_sites) *
        out.per_site_conditional_failure_probability;

    out.lane_proximity_bits =
        -std::log2(
            static_cast<double>(
                out.lane_failure_probability));
    out.multiplicative_pair_bits =
        -std::log2(
            static_cast<double>(
                out.multiplicative_pair_failure_probability));
    out.pair_after_single_grind_bits =
        -std::log2(
            static_cast<double>(
                out.grind_amplified_pair_failure_probability));
    out.common_binding_bits = kCommonBindingBitsV12;
    out.conditional_safe_nirop_bits =
        kConditionalSafeNiropBitsV12;
    out.per_site_conditional_bits =
        -std::log2(
            static_cast<double>(
                out.per_site_conditional_failure_probability));
    out.global_conditional_bits =
        -std::log2(
            static_cast<double>(
                out.global_conditional_failure_probability));

    std::string verify_why;
    out.common_transcript_join_executable =
        ValidateHybridReceiptV12(
            manifest, inputs, receipt, &verify_why);
    out.lane_domains_and_tags_distinct =
        receipt.typed_lane_domains_distinct;
    out.lane_query_vectors_distinct =
        receipt.query_vectors_distinct;
    out.shared_nonce_tax_executable =
        receipt.tax_satisfied &&
        receipt.tax_air_constraints_zero &&
        receipt.tax_predicate_air.tax_bits ==
            kTaxedGrindBitsV12;
    // The current V12 manifest squeezes lane queries before this outer joint
    // tax is checked. Every accepted nonce is taxed and shared, but sigma is
    // not yet the sole source of every query cell. Do not claim the stronger
    // Construction-2 premise.
    out.shared_nonce_tax_is_sole_query_entropy_source = false;

    const auto site_manifest =
        scenarios::BuildProductionProofSiteManifest(
            scenarios::SelectedProductionProofSitePolicy());
    out.proof_site_arithmetic_manifest_valid =
        site_manifest.arithmetic_exact &&
        site_manifest.total_proof_sites ==
            kProductionProofSitesV12 &&
        scenarios::ValidateProductionProofSiteManifest(
            site_manifest, nullptr);
    out.proof_site_upper_bound_recursively_enforced =
        site_manifest.complete_global_upper_bound_manifest_derived &&
        site_manifest.recursive_scheduler_consumes_manifest &&
        site_manifest.executable_backend_enforces_policy;

    out.parameters_read_from_shipped_construction =
        out.lanes == 2 &&
        out.queries_per_lane == 96 &&
        out.total_queries == 192 &&
        out.grind_bits ==
            kRCFri3AlgTaxedQGrindBits &&
        out.grind_bits == 20 &&
        out.proof_sites ==
            gsl::kCanonicalProductionSites &&
        manifest.shape.n_lde ==
            manifest.shape.n_coeffs *
                fsair::kFriBlowupV12;

    // Typed domains, transcript equality and distinct observed vectors are
    // executable evidence, not a proof that two calls to one concrete
    // permutation instantiate independent random oracles.
    out.lane_independence_reduction_complete = false;
    // The parent seed binds the root bundle, but the lane Merkle roots are not
    // yet equality-constrained to a proof that they commit to common.trace.
    out.common_commitment_binding_reduction_complete = false;
    out.concrete_safe_nirop_reduction_complete =
        safe::kConcreteTagHashReductionCertifiedV12 &&
        safe::kConcretePoseidonReductionCertifiedV12 &&
        safe::kExactGlobalSafeQueryManifestEnforcedV12 &&
        safe::kSafeDomainRegistryRootPinnedV12 &&
        safe::kActiveNativeSafeMigrationV12 &&
        safe::kRecursiveSafeAirExecutableV12 &&
        safe::kNativeRecursiveSafeParityCertifiedV12;

    const long double expected_lane =
        std::pow(
            static_cast<long double>(17.0L / 32.0L),
            static_cast<long double>(96));
    const long double expected_pair =
        expected_lane * expected_lane;
    const long double expected_per_site =
        std::ldexp(expected_pair, 20) +
        std::ldexp(1.0L, -128) +
        std::ldexp(1.0L, -128);
    const long double expected_global =
        static_cast<long double>(37'488'397ULL) *
        expected_per_site;
    out.multiplicative_then_additive_expression_machine_checked =
        NearlyEqual(
            out.lane_failure_probability,
            expected_lane) &&
        NearlyEqual(
            out.multiplicative_pair_failure_probability,
            expected_pair) &&
        NearlyEqual(
            out.per_site_conditional_failure_probability,
            expected_per_site) &&
        NearlyEqual(
            out.global_conditional_failure_probability,
            expected_global) &&
        std::fabs(
            out.pair_after_single_grind_bits -
            (out.multiplicative_pair_bits -
             static_cast<double>(out.grind_bits))) <
            1.0e-9;
    out.conditional_numeric_v1_target_met =
        std::isfinite(out.global_conditional_bits) &&
        out.global_conditional_bits >=
            static_cast<double>(kV1TargetBitsV12);
    out.nirop_reduction_certified =
        out.parameters_read_from_shipped_construction &&
        out.proof_site_arithmetic_manifest_valid &&
        out.proof_site_upper_bound_recursively_enforced &&
        out.common_transcript_join_executable &&
        out.lane_domains_and_tags_distinct &&
        out.lane_query_vectors_distinct &&
        out.shared_nonce_tax_executable &&
        out.shared_nonce_tax_is_sole_query_entropy_source &&
        out.lane_independence_reduction_complete &&
        out.common_commitment_binding_reduction_complete &&
        out.concrete_safe_nirop_reduction_complete &&
        out.multiplicative_then_additive_expression_machine_checked &&
        out.conditional_numeric_v1_target_met;
    out.exact_expression =
        "eps_global <= 37488397 * "
        "(2^20 * ((17/32)^96 * (17/32)^96) "
        "+ 2^-128 + eps_SAFE_NIROP), "
        "conditioned on eps_SAFE_NIROP <= 2^-128";
    out.residual_premises = {
        "Make the taxed sigma the sole source of all 192 query indices.",
        "Prove two typed SAFE lane domains instantiate the required "
        "independent-oracle hybrid under the shared concrete Poseidon2.",
        "Equality-constrain each lane row root to the common trace "
        "commitment inside the recursive verifier.",
        "Certify the concrete H(IO,D) and Poseidon SAFE reductions and pin "
        "the typed-domain registry root.",
        "Make the recursive scheduler consume and enforce the exact "
        "37,488,397-site production manifest."};
    out.note =
        "stage3:safe_v12_nirop:"
        "common_join_and_g20_tax_executable;"
        "dual_q96_conditional_global_bits=" +
        std::to_string(out.global_conditional_bits) +
        ";independence_binding_safe_and_site_reductions_false;"
        "authority_false";
    return out;
}

} // namespace matmul::v4::rc::stage3_safe_v12_nirop_reduction
