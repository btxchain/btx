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

std::vector<uint8_t> TraceShapeDomain()
{
    static constexpr char kDomain[] =
        "BTX_STAGE3_V12_SHARED_TRACE_SHAPE";
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

bool CanonicalClaim(const LaneCommonClaimV12& claim)
{
    return CanonicalDigest(claim.statement) &&
        CanonicalDigest(claim.program) &&
        CanonicalDigest(claim.trace);
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

bool SameTraceEqualityAir(
    const TraceRootEqualityAirV12& left,
    const TraceRootEqualityAirV12& right);

bool SameHybridReceipt(
    const HybridReceiptV12& left,
    const HybridReceiptV12& right)
{
    return left.common_binding == right.common_binding &&
        SameTraceEqualityAir(
            left.trace_root_equality_air,
            right.trace_root_equality_air) &&
        left.tax_sigma_core == right.tax_sigma_core &&
        left.tax_sigma == right.tax_sigma &&
        SameTaxAir(
            left.tax_predicate_air,
            right.tax_predicate_air) &&
        left.query_indices == right.query_indices &&
        left.fri_terminal_receipts ==
            right.fri_terminal_receipts &&
        left.manifest_valid == right.manifest_valid &&
        left.common_binding_valid ==
            right.common_binding_valid &&
        left.trace_root_equality_air_valid ==
            right.trace_root_equality_air_valid &&
        left.native_air_transcript_valid ==
            right.native_air_transcript_valid &&
        left.typed_lane_domains_distinct ==
            right.typed_lane_domains_distinct &&
        left.query_vectors_distinct ==
            right.query_vectors_distinct &&
        left.tax_sigma_and_nonce_bound_to_query_channels ==
            right.tax_sigma_and_nonce_bound_to_query_channels &&
        left.query_channels_are_only_index_source ==
            right.query_channels_are_only_index_source &&
        left.acyclic_prover_order_enforced ==
            right.acyclic_prover_order_enforced &&
        left.fri_terminal_receipts_bound ==
            right.fri_terminal_receipts_bound &&
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

constexpr uint32_t kEqualityRows = 2;
constexpr uint32_t kCommonTraceBase = 0;
constexpr uint32_t kMetadataBase = 4;
constexpr uint32_t kCanonicalShapeBase = 12;
constexpr uint32_t kProofTraceBase = 16;
constexpr uint32_t kLaneClaimTraceBase = 20;
constexpr uint32_t kLaneMetadataBase = 28;
constexpr uint32_t kLaneShapeBase = 44;
constexpr uint32_t kLaneRowRootBase = 52;
constexpr uint32_t kEqualityColumns = 60;
constexpr uint32_t kVerifierOwnedColumns = 16;
constexpr uint32_t kMetadataLanes = 8;

std::array<gf::Fp, kMetadataLanes> MetadataLanes(
    const TraceMetadataV12& metadata)
{
    return {{
        gf::FromU64(metadata.protocol_version),
        gf::FromU64(metadata.trace_rows),
        gf::FromU64(metadata.trace_columns),
        gf::FromU64(metadata.quotient_len),
        gf::FromU64(metadata.n_coeffs),
        gf::FromU64(metadata.n_lde),
        gf::FromU64(metadata.blowup),
        gf::FromU64(metadata.folds),
    }};
}

void FillConstantColumn(
    std::vector<std::vector<gf::Fp3>>& columns,
    uint32_t column, gf::Fp value)
{
    columns[column].assign(
        kEqualityRows, gf::Fp3::FromFp(value));
}

void FillDigestColumns(
    std::vector<std::vector<gf::Fp3>>& columns,
    uint32_t base, const ah::Digest& digest)
{
    for (uint32_t lane = 0; lane < digest.size(); ++lane) {
        FillConstantColumn(columns, base + lane, digest[lane]);
    }
}

void FillMetadataColumns(
    std::vector<std::vector<gf::Fp3>>& columns,
    uint32_t base, const TraceMetadataV12& metadata)
{
    const auto lanes = MetadataLanes(metadata);
    for (uint32_t lane = 0; lane < lanes.size(); ++lane) {
        FillConstantColumn(columns, base + lane, lanes[lane]);
    }
}

void AddEquality(
    aq::AirConstraintSystem<gf::Fp3>& cs,
    uint32_t source, uint32_t sink)
{
    aq::AirConstraint<gf::Fp3> equality;
    equality.name =
        "stage3.safe_v12.shared_trace_root_equality";
    equality.kind = aq::AirKind::kEverywhere;
    equality.alg_degree = 1;
    equality.eval = [source, sink](
                        const std::vector<gf::Fp3>& cur,
                        const std::vector<gf::Fp3>&) {
        return gf::Sub(cur[source], cur[sink]);
    };
    cs.constraints.push_back(std::move(equality));
}

uint32_t CountEqualityViolations(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns)
{
    if (columns.size() != cs.n_columns) {
        return std::numeric_limits<uint32_t>::max();
    }
    uint32_t violations = 0;
    std::vector<gf::Fp3> cur(cs.n_columns);
    std::vector<gf::Fp3> next(cs.n_columns);
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        const uint32_t next_row = (row + 1) % cs.n_rows;
        for (uint32_t column = 0;
             column < cs.n_columns; ++column) {
            if (columns[column].size() != cs.n_rows) {
                return std::numeric_limits<uint32_t>::max();
            }
            cur[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            if (!gf::IsZero(constraint.eval(cur, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

bool SameColumns(
    const std::vector<std::vector<gf::Fp3>>& left,
    const std::vector<std::vector<gf::Fp3>>& right)
{
    if (left.size() != right.size()) return false;
    for (size_t column = 0; column < left.size(); ++column) {
        if (left[column].size() != right[column].size()) {
            return false;
        }
        for (size_t row = 0; row < left[column].size(); ++row) {
            if (!gf::Eq(left[column][row], right[column][row])) {
                return false;
            }
        }
    }
    return true;
}

bool SamePreprocessed(
    const std::vector<
        std::pair<uint32_t, std::vector<gf::Fp3>>>& left,
    const std::vector<
        std::pair<uint32_t, std::vector<gf::Fp3>>>& right)
{
    if (left.size() != right.size()) return false;
    for (size_t item = 0; item < left.size(); ++item) {
        if (left[item].first != right[item].first ||
            left[item].second.size() !=
                right[item].second.size()) {
            return false;
        }
        for (size_t row = 0;
             row < left[item].second.size(); ++row) {
            if (!gf::Eq(
                    left[item].second[row],
                    right[item].second[row])) {
                return false;
            }
        }
    }
    return true;
}

bool SameTraceEqualityAir(
    const TraceRootEqualityAirV12& left,
    const TraceRootEqualityAirV12& right)
{
    return SameColumns(left.columns, right.columns) &&
        left.canonical_metadata == right.canonical_metadata &&
        left.canonical_shape_commit ==
            right.canonical_shape_commit &&
        left.shared_row_root == right.shared_row_root &&
        left.cs.n_rows == right.cs.n_rows &&
        left.cs.n_columns == right.cs.n_columns &&
        left.cs.constraints.size() ==
            right.cs.constraints.size() &&
        SamePreprocessed(
            left.cs.preprocessed,
            right.cs.preprocessed) &&
        left.cs.preprocessed_pin_ood ==
            right.cs.preprocessed_pin_ood &&
        left.verifier_owned_preprocessed_columns ==
            right.verifier_owned_preprocessed_columns &&
        left.proof_owned_preprocessed_columns ==
            right.proof_owned_preprocessed_columns &&
        left.equality_constraints ==
            right.equality_constraints &&
        left.constraint_violations ==
            right.constraint_violations &&
        left.common_trace_aliases_constrained ==
            right.common_trace_aliases_constrained &&
        left.metadata_aliases_constrained ==
            right.metadata_aliases_constrained &&
        left.canonical_shape_aliases_constrained ==
            right.canonical_shape_aliases_constrained &&
        left.shared_row_root_constrained ==
            right.shared_row_root_constrained &&
        left.row_root_to_common_trace_constrained ==
            right.row_root_to_common_trace_constrained &&
        left.only_verifier_owned_values_preprocessed ==
            right.only_verifier_owned_values_preprocessed &&
        left.valid == right.valid;
}

} // namespace

TraceMetadataV12 CanonicalTraceMetadataV12(
    const fsair::ManifestV12& manifest)
{
    return {
        kProtocolVersionV12,
        manifest.shape.child_n_rows,
        manifest.shape.child_w,
        manifest.shape.child_quotient_len,
        manifest.shape.n_coeffs,
        manifest.shape.n_lde,
        fsair::kFriBlowupV12,
        manifest.shape.n_folds,
    };
}

bool DeriveCanonicalShapeCommitV12(
    const fsair::ManifestV12& manifest,
    aht::RoleV12 role, ah::Digest& shape_commit,
    std::string* why)
{
    shape_commit = {};
    if (!fsair::ValidateManifestV12(manifest, why)) {
        return Fail(why, "shape manifest invalid");
    }
    const TraceMetadataV12 metadata =
        CanonicalTraceMetadataV12(manifest);
    std::vector<gf::Fp> message;
    message.reserve(2 + kMetadataLanes);
    message.push_back(kTraceEqualityMagicV12);
    const auto lanes = MetadataLanes(metadata);
    message.insert(message.end(), lanes.begin(), lanes.end());
    safe::SafeCoreResultV12 audit;
    if (!safe::SafeCoreDigestV12(
            role, TraceShapeDomain(), message,
            shape_commit, &audit, why) ||
        !CanonicalDigest(shape_commit) ||
        audit.tag_stats.sha256d_calls == 0 ||
        audit.cost.published_algorithm_poseidon_calls == 0) {
        shape_commit = {};
        return Fail(why, "canonical shape SAFE derivation");
    }
    return true;
}

bool BuildTraceRootEqualityAirV12(
    const fsair::ManifestV12& manifest,
    const CommonCommitmentsV12& common,
    const std::array<LaneCommonClaimV12, kLaneCountV12>&
        lane_claim,
    const std::array<TraceMetadataV12, kLaneCountV12>&
        lane_metadata,
    const fsair::ProofWitnessInputsV12& proof_witness,
    TraceRootEqualityAirV12& out,
    std::string* why)
{
    out = {};
    if (!fsair::ValidateManifestV12(manifest, why) ||
        !CanonicalCommon(common) ||
        !CanonicalProofBundle(proof_witness) ||
        !std::all_of(
            lane_claim.begin(), lane_claim.end(),
            CanonicalClaim)) {
        return Fail(why, "trace equality inputs invalid");
    }

    out.canonical_metadata =
        CanonicalTraceMetadataV12(manifest);
    if (!DeriveCanonicalShapeCommitV12(
            manifest, aht::RoleV12::TranscriptShapeCommit,
            out.canonical_shape_commit, why)) {
        return false;
    }
    out.shared_row_root =
        proof_witness.fri_lane[0].row_root;

    out.cs.n_rows = kEqualityRows;
    out.cs.n_columns = kEqualityColumns;
    out.cs.preprocessed_pin_ood = true;
    out.columns.assign(
        kEqualityColumns,
        std::vector<gf::Fp3>(
            kEqualityRows, gf::Fp3::Zero()));

    FillDigestColumns(
        out.columns, kCommonTraceBase, common.trace);
    FillMetadataColumns(
        out.columns, kMetadataBase,
        out.canonical_metadata);
    FillDigestColumns(
        out.columns, kCanonicalShapeBase,
        out.canonical_shape_commit);
    FillDigestColumns(
        out.columns, kProofTraceBase,
        proof_witness.trace_commit);
    for (uint32_t lane = 0; lane < kLaneCountV12; ++lane) {
        FillDigestColumns(
            out.columns,
            kLaneClaimTraceBase + 4 * lane,
            lane_claim[lane].trace);
        FillMetadataColumns(
            out.columns,
            kLaneMetadataBase + kMetadataLanes * lane,
            lane_metadata[lane]);
        FillDigestColumns(
            out.columns,
            kLaneShapeBase + 4 * lane,
            proof_witness.fri_lane[lane].shape_commit);
        FillDigestColumns(
            out.columns,
            kLaneRowRootBase + 4 * lane,
            proof_witness.fri_lane[lane].row_root);
    }

    for (uint32_t column = 0;
         column < kVerifierOwnedColumns; ++column) {
        out.cs.preprocessed.emplace_back(
            column, out.columns[column]);
    }
    out.verifier_owned_preprocessed_columns =
        kVerifierOwnedColumns;
    out.proof_owned_preprocessed_columns = 0;
    out.only_verifier_owned_values_preprocessed =
        out.cs.preprocessed.size() ==
            kVerifierOwnedColumns;

    for (uint32_t lane = 0; lane < 4; ++lane) {
        AddEquality(
            out.cs, kProofTraceBase + lane,
            kCommonTraceBase + lane);
        for (uint32_t proof_lane = 0;
             proof_lane < kLaneCountV12; ++proof_lane) {
            AddEquality(
                out.cs,
                kLaneClaimTraceBase +
                    4 * proof_lane + lane,
                kCommonTraceBase + lane);
            AddEquality(
                out.cs,
                kLaneShapeBase +
                    4 * proof_lane + lane,
                kCanonicalShapeBase + lane);
        }
        AddEquality(
            out.cs, kLaneRowRootBase + 4 + lane,
            kLaneRowRootBase + lane);
        for (uint32_t proof_lane = 0;
             proof_lane < kLaneCountV12; ++proof_lane) {
            AddEquality(
                out.cs,
                kLaneRowRootBase +
                    4 * proof_lane + lane,
                kCommonTraceBase + lane);
        }
    }
    for (uint32_t proof_lane = 0;
         proof_lane < kLaneCountV12; ++proof_lane) {
        for (uint32_t lane = 0;
             lane < kMetadataLanes; ++lane) {
            AddEquality(
                out.cs,
                kLaneMetadataBase +
                    kMetadataLanes * proof_lane + lane,
                kMetadataBase + lane);
        }
    }
    out.equality_constraints =
        static_cast<uint32_t>(out.cs.constraints.size());
    out.constraint_violations =
        CountEqualityViolations(out.cs, out.columns);
    out.common_trace_aliases_constrained = true;
    out.metadata_aliases_constrained = true;
    out.canonical_shape_aliases_constrained = true;
    out.shared_row_root_constrained = true;
    out.row_root_to_common_trace_constrained = true;
    out.valid =
        out.equality_constraints == 48 &&
        out.constraint_violations == 0 &&
        out.verifier_owned_preprocessed_columns == 16 &&
        out.proof_owned_preprocessed_columns == 0 &&
        out.only_verifier_owned_values_preprocessed;
    out.note = out.valid
        ? "stage3:safe_v12_nirop:"
          "shared_trace_shape_and_bound_row_root_air_ok"
        : "stage3:safe_v12_nirop:"
          "shared_trace_shape_or_bound_row_root_mismatch";
    if (!out.valid) {
        return Fail(why, "trace equality AIR violations");
    }
    return true;
}

bool ValidateTraceRootEqualityAirV12(
    const fsair::ManifestV12& manifest,
    const CommonCommitmentsV12& common,
    const std::array<LaneCommonClaimV12, kLaneCountV12>&
        lane_claim,
    const std::array<TraceMetadataV12, kLaneCountV12>&
        lane_metadata,
    const fsair::ProofWitnessInputsV12& proof_witness,
    const TraceRootEqualityAirV12& air,
    std::string* why)
{
    if (!air.valid ||
        CountEqualityViolations(air.cs, air.columns) != 0) {
        return Fail(why, "supplied trace equality AIR invalid");
    }
    TraceRootEqualityAirV12 expected;
    if (!BuildTraceRootEqualityAirV12(
            manifest, common, lane_claim, lane_metadata,
            proof_witness, expected, why)) {
        return false;
    }
    if (!SameTraceEqualityAir(air, expected)) {
        return Fail(why, "trace equality AIR mismatch");
    }
    return true;
}

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
    // This seed is deliberately pre-FRI.  It may bind only values known
    // before OOD and fold challenges are sampled; future fold roots enter
    // sequentially in each typed FRI channel and are joined by the post-FRI
    // tax sigma through the two terminal receipts.
    message.reserve(16 + 12 + 2 * 9);
    message.push_back(kCommonBindingMagicV12);
    AppendU32(message, kProtocolVersionV12);
    AppendU32(message, kQueriesPerLaneV12);
    AppendU32(
        message, fsair::kQueryCandidatesPerLaneV12);
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
    const std::array<ah::Digest, kLaneCountV12>&
        fri_terminal_receipts,
    std::vector<gf::Fp>& sigma_core,
    std::string* why)
{
    sigma_core.clear();
    if (!fsair::ValidateManifestV12(manifest, why) ||
        !CanonicalCommon(common) ||
        !CanonicalDigest(parent_fs_seed) ||
        !std::all_of(
            fri_terminal_receipts.begin(),
            fri_terminal_receipts.end(),
            [](const ah::Digest& receipt) {
                return CanonicalDigest(receipt) &&
                    receipt != ah::Digest{};
            })) {
        return Fail(why, "invalid tax sigma inputs");
    }
    sigma_core.reserve(48);
    sigma_core.push_back(kCommonBindingMagicV12);
    AppendU32(sigma_core, kProtocolVersionV12);
    AppendU32(sigma_core, kQueriesPerLaneV12);
    AppendU32(
        sigma_core, fsair::kQueryCandidatesPerLaneV12);
    AppendU32(sigma_core, kTaxedGrindBitsV12);
    AppendDigest(sigma_core, parent_fs_seed);
    AppendDigest(sigma_core, common.statement);
    AppendDigest(sigma_core, common.program);
    AppendDigest(sigma_core, common.trace);
    AppendDigest(sigma_core, fri_terminal_receipts[0]);
    AppendDigest(sigma_core, fri_terminal_receipts[1]);
    for (const auto& tag : {
             manifest.air_quotient.safe_manifest.tag,
             manifest.fri_lane[0].safe_manifest.tag,
             manifest.fri_lane[1].safe_manifest.tag,
             manifest.query_lane[0].safe_manifest.tag,
             manifest.query_lane[1].safe_manifest.tag}) {
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
    binding.fri_preamble_nonce_free =
        std::all_of(
            manifest.fri_lane.begin(),
            manifest.fri_lane.end(),
            [](const auto& lane) {
                return !lane.calls.empty() &&
                    lane.calls.front().role ==
                        fsair::CallRoleV12::AbsorbFriPreamble &&
                    lane.calls.front().payload_lanes == 16;
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
        binding.fri_preamble_nonce_free &&
        binding.proof_dependent_preprocessed_columns == 0;
    binding.note = binding.valid
        ? "stage3:safe_v12_nirop:common_transcript_join_ok"
        : "stage3:safe_v12_nirop:common_transcript_join_failure";
    if (!binding.valid) {
        return Fail(why, "common binding mismatch");
    }
    receipt.common_binding = binding;
    receipt.common_binding_valid = true;

    if (!BuildTraceRootEqualityAirV12(
            manifest, inputs.common, inputs.lane_claim,
            inputs.lane_trace_metadata,
            inputs.transcript.proof_witness,
            receipt.trace_root_equality_air, why) ||
        !ValidateTraceRootEqualityAirV12(
            manifest, inputs.common, inputs.lane_claim,
            inputs.lane_trace_metadata,
            inputs.transcript.proof_witness,
            receipt.trace_root_equality_air, why)) {
        return false;
    }
    receipt.trace_root_equality_air_valid = true;

    if (!fsair::DeriveFriTerminalReceiptsV12(
            manifest, inputs.transcript,
            receipt.fri_terminal_receipts, why)) {
        return false;
    }
    receipt.fri_terminal_receipts_bound =
        receipt.fri_terminal_receipts[0] != ah::Digest{} &&
        receipt.fri_terminal_receipts[1] != ah::Digest{};
    if (!receipt.fri_terminal_receipts_bound) {
        return Fail(why, "empty FRI terminal receipt");
    }

    if (!BuildTaxSigmaCoreV12(
            manifest, inputs.common, binding.parent_fs_seed,
            receipt.fri_terminal_receipts,
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
    receipt.tax_sigma_and_nonce_bound_to_query_channels =
        inputs.transcript.parent_statement.
            shared_query_tax_sigma == receipt.tax_sigma &&
        inputs.transcript.parent_statement.
            shared_query_tax_nonce == inputs.shared_grind_nonce;
    if (!receipt.tax_sigma_and_nonce_bound_to_query_channels) {
        return Fail(
            why, "query channel does not consume taxed sigma/nonce");
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
            manifest.fri_lane[1].safe_manifest.tag &&
        manifest.query_lane[0].typed_domain !=
            manifest.query_lane[1].typed_domain &&
        manifest.query_lane[0].safe_manifest.tag !=
            manifest.query_lane[1].safe_manifest.tag;
    for (uint32_t lane = 0; lane < kLaneCountV12; ++lane) {
        const auto& fri_execution =
            receipt.transcript_air.fri_lane[lane].
                projected_execution;
        if (!fri_execution.fri_terminal_receipt_emitted ||
            fri_execution.fri_terminal_receipt !=
                receipt.fri_terminal_receipts[lane]) {
            return Fail(
                why, "FRI terminal receipt AIR mismatch");
        }
        receipt.query_indices[lane] =
            receipt.transcript_air.query_lane[lane].
                projected_execution.query_indices;
        if (receipt.query_indices[lane].size() !=
            kQueriesPerLaneV12) {
            return Fail(why, "query count mismatch");
        }
    }
    receipt.query_vectors_distinct =
        receipt.query_indices[0] !=
        receipt.query_indices[1];
    const auto emits_queries = [](const auto& channel) {
        return !channel.projected_execution.query_indices.empty();
    };
    receipt.query_channels_are_only_index_source =
        !emits_queries(receipt.transcript_air.air_quotient) &&
        !emits_queries(receipt.transcript_air.fri_lane[0]) &&
        !emits_queries(receipt.transcript_air.fri_lane[1]) &&
        emits_queries(receipt.transcript_air.query_lane[0]) &&
        emits_queries(receipt.transcript_air.query_lane[1]) &&
        receipt.transcript_air.query_lane[0].
            query_sampler_air_valid &&
        receipt.transcript_air.query_lane[1].
            query_sampler_air_valid;
    receipt.acyclic_prover_order_enforced =
        binding.fri_preamble_nonce_free &&
        receipt.fri_terminal_receipts_bound &&
        receipt.tax_sigma_and_nonce_bound_to_query_channels;
    receipt.valid =
        receipt.manifest_valid &&
        receipt.common_binding_valid &&
        receipt.trace_root_equality_air_valid &&
        receipt.native_air_transcript_valid &&
        receipt.typed_lane_domains_distinct &&
        receipt.query_vectors_distinct &&
        receipt.tax_sigma_and_nonce_bound_to_query_channels &&
        receipt.query_channels_are_only_index_source &&
        receipt.acyclic_prover_order_enforced &&
        receipt.fri_terminal_receipts_bound &&
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
    out.common_trace_root_equality_air_executable =
        receipt.trace_root_equality_air_valid &&
        ValidateTraceRootEqualityAirV12(
            manifest, inputs.common, inputs.lane_claim,
            inputs.lane_trace_metadata,
            inputs.transcript.proof_witness,
            receipt.trace_root_equality_air, nullptr);
    // The AIR is executable and mutation-tested, but is not yet appended to
    // the normalized recursive parent proof. Keep reduction certification
    // separate from host/witness execution.
    out.common_trace_root_equality_recursively_consumed = false;
    out.lane_domains_and_tags_distinct =
        receipt.typed_lane_domains_distinct;
    out.lane_query_vectors_distinct =
        receipt.query_vectors_distinct;
    out.shared_nonce_tax_executable =
        receipt.tax_satisfied &&
        receipt.tax_air_constraints_zero &&
        receipt.tax_predicate_air.tax_bits ==
            kTaxedGrindBitsV12;
    // Query candidates now live in two dedicated typed channels. Their only
    // variable absorb is the verifier-recomputed taxed sigma and its shared
    // nonce; all other query-call cells are fixed descriptors/domain tags.
    // Recursive equality from those SAFE outputs into the sampler remains a
    // separate false premise below.
    out.shared_nonce_tax_is_sole_query_entropy_source =
        receipt.tax_sigma_and_nonce_bound_to_query_channels &&
        receipt.query_channels_are_only_index_source &&
        receipt.acyclic_prover_order_enforced &&
        receipt.fri_terminal_receipts_bound &&
        fsair::kQuerySamplerSoleProductionQuerySourceV12;

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
    // The exact equality AIR now exists, but the recursive parent does not
    // consume it yet.
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
        out.common_trace_root_equality_air_executable &&
        out.common_trace_root_equality_recursively_consumed &&
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
        "Recursively equality-bind both dedicated taxed-query SAFE outputs "
        "to the two without-replacement sampler candidate vectors.",
        "Prove two typed SAFE lane domains instantiate the required "
        "independent-oracle hybrid under the shared concrete Poseidon2.",
        "Append the executable shared trace/shape/row-root equality AIR "
        "to the normalized recursive parent proof.",
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
