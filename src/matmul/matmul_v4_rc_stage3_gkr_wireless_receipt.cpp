// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_gkr_wireless_receipt.h>

#include <matmul/matmul_v4_rc_stage3_safe_v12.h>

#include <algorithm>
#include <limits>

namespace matmul::v4::rc::stage3_gkr_wireless_receipt {

namespace safe = safe_v12;
namespace aht = alg_hash_typed;

namespace {

constexpr char DESCRIPTOR_DOMAIN_V1[] =
    "BTX_STAGE3_GKR_PUBLIC_DESCRIPTOR_V1";
constexpr char PROOF_DOMAIN_V1[] =
    "BTX_STAGE3_GKR_CANONICAL_FRI_PROOF_V1";
constexpr char CHUNK_FS_DOMAIN_V1[] =
    "BTX_STAGE3_GKR_V13_CHUNK_FS_SEED_V1";
constexpr char EVALUATION_DOMAIN_V1[] =
    "BTX_STAGE3_GKR_AUTHENTICATED_OOD_EVALUATIONS_V1";
constexpr char RECEIPT_DOMAIN_V1[] =
    "BTX_STAGE3_GKR_WIRELESS_RECEIPT_V1";
constexpr char RECEIPT_SET_DOMAIN_V1[] =
    "BTX_STAGE3_GKR_WIRELESS_RECEIPT_SET_V1";

bool Fail(std::string* why, const std::string& text)
{
    if (why != nullptr) {
        *why = "stage3:gkr_wireless_receipt:" + text;
    }
    return false;
}

bool DigestEq(const ah::Digest& left, const ah::Digest& right)
{
    for (uint32_t lane = 0; lane < ah::kAlgHashDigestLen; ++lane) {
        if (gf::Canonical(left[lane]) !=
            gf::Canonical(right[lane])) {
            return false;
        }
    }
    return true;
}

bool DigestCanonical(const ah::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp value) {
            return value < gf::kP;
        });
}

bool DigestZero(const ah::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp value) {
            return gf::Canonical(value) == 0;
        });
}

bool Fp3Canonical(const gf::Fp3& value)
{
    return value.c0 < gf::kP &&
        value.c1 < gf::kP &&
        value.c2 < gf::kP;
}

void AppendU32(std::vector<gf::Fp>& out, uint32_t value)
{
    out.push_back(gf::FromU64(value));
}

void AppendU64(std::vector<gf::Fp>& out, uint64_t value)
{
    AppendU32(out, static_cast<uint32_t>(value));
    AppendU32(out, static_cast<uint32_t>(value >> 32));
}

void AppendUint256(
    std::vector<gf::Fp>& out,
    const uint256& value)
{
    for (uint32_t word = 0; word < 8; ++word) {
        uint32_t limb = 0;
        for (uint32_t byte = 0; byte < 4; ++byte) {
            limb |=
                static_cast<uint32_t>(
                    value.data()[4 * word + byte])
                << (8 * byte);
        }
        AppendU32(out, limb);
    }
}

void AppendDigest(
    std::vector<gf::Fp>& out,
    const ah::Digest& digest)
{
    for (const gf::Fp lane : digest) {
        out.push_back(gf::Canonical(lane));
    }
}

void AppendFp3(
    std::vector<gf::Fp>& out,
    const gf::Fp3& value)
{
    out.push_back(gf::Canonical(value.c0));
    out.push_back(gf::Canonical(value.c1));
    out.push_back(gf::Canonical(value.c2));
}

std::vector<uint8_t> Domain(const char* text)
{
    const auto* begin =
        reinterpret_cast<const uint8_t*>(text);
    return std::vector<uint8_t>(
        begin, begin + std::char_traits<char>::length(text));
}

ah::Digest SafeHash(
    const char* domain,
    const std::vector<gf::Fp>& message)
{
    ah::Digest out{};
    if (!safe::SafeCoreDigestV12(
            aht::RoleV12::ReceiptCommitment,
            Domain(domain), message, out)) {
        return {};
    }
    return out;
}

ColumnDescriptorV1 ConvertColumn(
    const RCGkrColumnInfo& column)
{
    ColumnDescriptorV1 out;
    out.id = column.id;
    out.tensor = column.tensor;
    out.round = column.round;
    out.layer = column.layer;
    out.rows = column.rows;
    out.cols = column.cols;
    out.chunk = column.chunk;
    out.n_chunks = column.n_chunks;
    out.chunk_offset = column.chunk_offset;
    out.logical_len = column.len;
    out.int64_cells = column.int64_cells;
    return out;
}

bool DescriptorCoreValid(
    const PublicDescriptorV1& descriptor,
    std::string* why)
{
    if (descriptor.version != kDescriptorVersionV1 ||
        !ValidateRCEpisodeParams(descriptor.params) ||
        descriptor.height < 0 ||
        descriptor.claimed_digest.IsNull() ||
        descriptor.pow_bind.IsNull() ||
        descriptor.episode_sigma.IsNull() ||
        descriptor.fri_fs_seed.IsNull() ||
        descriptor.round_roots.size() !=
            descriptor.params.rounds ||
        std::any_of(
            descriptor.round_roots.begin(),
            descriptor.round_roots.end(),
            [](const uint256& root) {
                return root.IsNull();
            })) {
        return Fail(why, "descriptor_public_shape");
    }
    if (RCGkrEpisodeDigestFromRoots(
            descriptor.round_roots) !=
            descriptor.claimed_digest ||
        RCGkrDerivePowBind(descriptor.claimed_digest) !=
            descriptor.pow_bind) {
        return Fail(why, "descriptor_episode_binding");
    }
    const RCGkrLayout layout =
        RCGkrTraceLayout(descriptor.params);
    if (layout.columns.empty() ||
        layout.columns.size() >
            kRCFri3AlgBatchMaxColumns ||
        descriptor.trace_cells != layout.trace_cells ||
        descriptor.operand_cells != layout.operand_cells ||
        descriptor.total_cells != layout.total_cells ||
        descriptor.columns.size() != layout.columns.size()) {
        return Fail(why, "descriptor_layout_shape");
    }
    for (uint32_t index = 0;
         index < layout.columns.size(); ++index) {
        if (!(descriptor.columns[index] ==
              ConvertColumn(layout.columns[index])) ||
            descriptor.columns[index].id != index ||
            descriptor.columns[index].logical_len == 0 ||
            descriptor.columns[index].logical_len >
                kRCGkrColumnMaxCoeffs) {
            return Fail(why, "descriptor_column_order");
        }
    }
    return true;
}

bool RangeValid(
    const PublicDescriptorV1& descriptor,
    const ChunkRangeV1& range)
{
    if (!(range.column_count > 0 &&
        range.column_count <=
            kMaxOracleColumnsPerReceiptV1 &&
        range.first_column < descriptor.columns.size() &&
        range.column_count <=
            descriptor.columns.size() -
                range.first_column)) {
        return false;
    }
    uint32_t n_coeffs = 1;
    for (uint32_t local = 0;
         local < range.column_count; ++local) {
        const uint64_t len =
            descriptor.columns[
                range.first_column + local]
                .logical_len;
        if (len == 0 ||
            len > kRCGkrColumnMaxCoeffs) {
            return false;
        }
        while (n_coeffs < len) {
            if (n_coeffs >
                kRCGkrColumnMaxCoeffs / 2U) {
                return false;
            }
            n_coeffs *= 2U;
        }
    }
    const auto estimated =
        EstimateQ192V13ProofBytesV1(
            range.column_count, n_coeffs);
    return estimated.has_value() &&
        *estimated <= kRCFriMaxProofBytesHard;
}

bool ProofCanonical(
    const Fri3AlgBatchProof& proof)
{
    if (!DigestCanonical(proof.row_commit.root) ||
        !Fp3Canonical(proof.lambda) ||
        !Fp3Canonical(proof.z1) ||
        !Fp3Canonical(proof.z2) ||
        !Fp3Canonical(proof.w1) ||
        !Fp3Canonical(proof.w2) ||
        !Fp3Canonical(proof.final_value)) {
        return false;
    }
    for (const auto& value : proof.evals_z1) {
        if (!Fp3Canonical(value)) return false;
    }
    for (const auto& value : proof.evals_z2) {
        if (!Fp3Canonical(value)) return false;
    }
    for (const auto& layer : proof.fold_layers) {
        if (!DigestCanonical(layer.root)) return false;
    }
    for (const auto& value : proof.fold_challenges) {
        if (!Fp3Canonical(value)) return false;
    }
    for (const auto& query : proof.queries) {
        for (const auto& value : query.row.values) {
            if (!Fp3Canonical(value)) return false;
        }
        for (const auto& sibling : query.row.siblings) {
            if (!DigestCanonical(sibling)) return false;
        }
        for (const auto& step : query.steps) {
            if (!Fp3Canonical(step.even) ||
                !Fp3Canonical(step.odd)) {
                return false;
            }
            for (const auto& sibling : step.even_siblings) {
                if (!DigestCanonical(sibling)) return false;
            }
            for (const auto& sibling : step.odd_siblings) {
                if (!DigestCanonical(sibling)) return false;
            }
        }
    }
    return true;
}

bool CanonicalCodec(
    const Fri3AlgBatchProof& proof,
    std::vector<unsigned char>& bytes)
{
    bytes.clear();
    if (!ProofCanonical(proof) ||
        SerializeFri3AlgBatchProof(proof, bytes) == 0 ||
        bytes.empty() ||
        bytes.size() >
            kRCFriMaxProofBytesHard) {
        bytes.clear();
        return false;
    }
    const auto decoded =
        DeserializeFri3AlgSafeQ192K2V13BatchProof(
            bytes);
    if (!decoded.has_value()) {
        bytes.clear();
        return false;
    }
    std::vector<unsigned char> round_trip;
    if (SerializeFri3AlgBatchProof(
            *decoded, round_trip) == 0 ||
        round_trip != bytes) {
        bytes.clear();
        return false;
    }
    return true;
}

bool CanonicalizeProverProof(
    const Fri3AlgBatchProof& proof,
    Fri3AlgBatchProof& canonical)
{
    std::vector<unsigned char> bytes;
    if (SerializeFri3AlgBatchProof(
            proof, bytes) == 0 ||
        bytes.empty() ||
        bytes.size() >
            kRCFriMaxProofBytesHard) {
        return false;
    }
    const auto decoded =
        DeserializeFri3AlgSafeQ192K2V13BatchProof(
            bytes);
    if (!decoded.has_value() ||
        !ProofCanonical(*decoded)) {
        return false;
    }
    std::vector<unsigned char> round_trip;
    if (SerializeFri3AlgBatchProof(
            *decoded, round_trip) == 0 ||
        round_trip != bytes) {
        return false;
    }
    canonical = *decoded;
    return true;
}

std::vector<AuthenticatedOodEvaluationV1>
EvaluationsFromProof(
    const PublicDescriptorV1& descriptor,
    const ChunkRangeV1& range,
    const Fri3AlgBatchProof& proof)
{
    std::vector<AuthenticatedOodEvaluationV1> out;
    if (proof.evals_z1.size() != range.column_count ||
        proof.evals_z2.size() != range.column_count) {
        return out;
    }
    out.reserve(range.column_count);
    for (uint32_t local = 0;
         local < range.column_count; ++local) {
        const uint32_t global =
            range.first_column + local;
        out.push_back({
            global,
            static_cast<uint32_t>(
                descriptor.columns[global].logical_len),
            proof.evals_z1[local],
            proof.evals_z2[local],
        });
    }
    return out;
}

void FillNormalized(
    const ReceiptV1& receipt,
    NormalizedPublicInputV1& out)
{
    out = {};
    out.version = receipt.version;
    out.descriptor_root = receipt.descriptor_root;
    out.proof_statement_root =
        receipt.proof_statement_root;
    out.evaluation_root = receipt.evaluation_root;
    out.receipt_root = receipt.receipt_root;
    out.row_root = receipt.fri_proof.row_commit.root;
    out.chunk_fs_seed = receipt.chunk_fs_seed;
    out.first_column = receipt.range.first_column;
    out.column_count = receipt.range.column_count;
    out.n_coeffs = receipt.fri_proof.n_coeffs;
    out.blowup = receipt.fri_proof.blowup;
}

} // namespace

bool BuildPublicDescriptorV1(
    const RCEpisodeParams& params,
    int32_t height,
    const uint256& claimed_digest,
    const uint256& pow_bind,
    const uint256& episode_sigma,
    const std::vector<uint256>& round_roots,
    const uint256& fri_fs_seed,
    PublicDescriptorV1& out,
    std::string* why)
{
    out = {};
    if (!ValidateRCEpisodeParams(params)) {
        return Fail(why, "params");
    }
    const RCGkrLayout layout = RCGkrTraceLayout(params);
    out.version = kDescriptorVersionV1;
    out.params = params;
    out.height = height;
    out.claimed_digest = claimed_digest;
    out.pow_bind = pow_bind;
    out.episode_sigma = episode_sigma;
    out.round_roots = round_roots;
    out.fri_fs_seed = fri_fs_seed;
    out.trace_cells = layout.trace_cells;
    out.operand_cells = layout.operand_cells;
    out.total_cells = layout.total_cells;
    out.columns.reserve(layout.columns.size());
    for (const auto& column : layout.columns) {
        out.columns.push_back(ConvertColumn(column));
    }
    if (!DescriptorCoreValid(out, why)) {
        out = {};
        return false;
    }
    out.descriptor_root =
        ComputePublicDescriptorRootV1(out);
    if (DigestZero(out.descriptor_root)) {
        out = {};
        return Fail(why, "descriptor_root");
    }
    return true;
}

bool ValidatePublicDescriptorV1(
    const PublicDescriptorV1& descriptor,
    std::string* why)
{
    if (!DescriptorCoreValid(descriptor, why) ||
        !DigestCanonical(descriptor.descriptor_root) ||
        DigestZero(descriptor.descriptor_root) ||
        !DigestEq(
            descriptor.descriptor_root,
            ComputePublicDescriptorRootV1(descriptor))) {
        return Fail(why, "descriptor_root_mismatch");
    }
    return true;
}

ah::Digest ComputePublicDescriptorRootV1(
    const PublicDescriptorV1& descriptor)
{
    std::vector<gf::Fp> message;
    AppendU32(message, descriptor.version);
    AppendU32(message, descriptor.params.rounds);
    AppendU32(message, descriptor.params.d_head);
    AppendU32(message, descriptor.params.n_q);
    AppendU32(message, descriptor.params.n_ctx);
    AppendU32(message, descriptor.params.L_lyr);
    AppendU32(message, descriptor.params.d_model);
    AppendU32(message, descriptor.params.d_ff);
    AppendU32(message, descriptor.params.b_seq);
    AppendU32(message, descriptor.params.T_leaf);
    AppendU32(
        message,
        static_cast<uint32_t>(descriptor.height));
    AppendUint256(message, descriptor.claimed_digest);
    AppendUint256(message, descriptor.pow_bind);
    AppendUint256(message, descriptor.episode_sigma);
    AppendU32(
        message,
        static_cast<uint32_t>(
            descriptor.round_roots.size()));
    for (const auto& root : descriptor.round_roots) {
        AppendUint256(message, root);
    }
    AppendUint256(message, descriptor.fri_fs_seed);
    AppendU64(message, descriptor.trace_cells);
    AppendU64(message, descriptor.operand_cells);
    AppendU64(message, descriptor.total_cells);
    AppendU32(
        message,
        static_cast<uint32_t>(
            descriptor.columns.size()));
    for (const auto& column : descriptor.columns) {
        AppendU32(message, column.id);
        AppendU32(
            message,
            static_cast<uint32_t>(column.tensor));
        AppendU32(message, column.round);
        AppendU32(message, column.layer);
        AppendU32(message, column.rows);
        AppendU32(message, column.cols);
        AppendU32(message, column.chunk);
        AppendU32(message, column.n_chunks);
        AppendU64(message, column.chunk_offset);
        AppendU64(message, column.logical_len);
        AppendU32(message, column.int64_cells ? 1U : 0U);
    }
    return SafeHash(DESCRIPTOR_DOMAIN_V1, message);
}

std::vector<ChunkRangeV1> BuildChunkPlanV1(
    const PublicDescriptorV1& descriptor,
    uint32_t max_columns_per_receipt)
{
    std::vector<ChunkRangeV1> out;
    if (!ValidatePublicDescriptorV1(
            descriptor, nullptr) ||
        max_columns_per_receipt == 0 ||
        max_columns_per_receipt >
            kMaxOracleColumnsPerReceiptV1) {
        return out;
    }
    uint32_t first = 0;
    while (first < descriptor.columns.size()) {
        uint32_t count = 0;
        while (count < max_columns_per_receipt &&
               first + count <
                   descriptor.columns.size()) {
            const ChunkRangeV1 candidate{
                first, count + 1};
            if (!RangeValid(descriptor, candidate)) {
                break;
            }
            ++count;
        }
        if (count == 0) {
            out.clear();
            return out;
        }
        out.push_back({first, count});
        first += count;
    }
    return out;
}

std::optional<size_t>
EstimateQ192V13ProofBytesV1(
    uint32_t batch_columns,
    uint32_t n_coeffs)
{
    if (batch_columns == 0 ||
        batch_columns >
            kRCFri3AlgBatchMaxColumns ||
        n_coeffs == 0 ||
        (n_coeffs & (n_coeffs - 1U)) != 0 ||
        n_coeffs >
            kRCGkrColumnMaxCoeffs) {
        return std::nullopt;
    }
    uint64_t folds = 0;
    for (uint32_t value = n_coeffs;
         value > 1; value >>= 1) {
        ++folds;
    }
    const uint64_t row_path_depth = folds + 4U;
    constexpr uint64_t FP3_BYTES = 24U;
    constexpr uint64_t DIGEST_BYTES = 32U;
    const uint64_t width = batch_columns;
    const unsigned __int128 fixed =
        64U +
        4U * static_cast<unsigned __int128>(width) +
        3U * FP3_BYTES +
        2U * (4U +
              FP3_BYTES *
                  static_cast<unsigned __int128>(width)) +
        2U * FP3_BYTES +
        4U +
        36U *
            static_cast<unsigned __int128>(folds + 1U) +
        FP3_BYTES +
        4U +
        FP3_BYTES *
            static_cast<unsigned __int128>(folds) +
        4U;
    const unsigned __int128 fold_path_depth_sum =
        static_cast<unsigned __int128>(folds) *
            row_path_depth -
        static_cast<unsigned __int128>(folds) *
            (folds - 1U) / 2U;
    const unsigned __int128 query_bytes =
        16U +
        FP3_BYTES *
            static_cast<unsigned __int128>(width) +
        DIGEST_BYTES * row_path_depth +
        64U * static_cast<unsigned __int128>(folds) +
        64U * fold_path_depth_sum;
    const unsigned __int128 total =
        fixed +
        kRCFri3AlgNumQueries * query_bytes;
    if (total >
        std::numeric_limits<size_t>::max()) {
        return std::nullopt;
    }
    return static_cast<size_t>(total);
}

uint256 DeriveChunkFsSeedV1(
    const PublicDescriptorV1& descriptor,
    const ChunkRangeV1& range)
{
    if (!ValidatePublicDescriptorV1(
            descriptor, nullptr) ||
        !RangeValid(descriptor, range)) {
        return {};
    }
    std::vector<gf::Fp> message;
    AppendDigest(message, descriptor.descriptor_root);
    AppendUint256(message, descriptor.fri_fs_seed);
    AppendU32(message, range.first_column);
    AppendU32(message, range.column_count);
    const ah::Digest digest =
        SafeHash(CHUNK_FS_DOMAIN_V1, message);
    if (DigestZero(digest)) return {};
    return Fri3AlgDigestToUint256(digest);
}

ah::Digest ComputeProofStatementRootV1(
    const Fri3AlgBatchProof& proof)
{
    std::vector<unsigned char> bytes;
    if (!CanonicalCodec(proof, bytes)) return {};
    std::vector<gf::Fp> message;
    AppendU64(message, bytes.size());
    AppendU32(message, proof.version);
    AppendU64(message, proof.pow_grind_nonce);
    AppendU32(message, proof.blowup);
    AppendU32(message, proof.n_coeffs);
    AppendDigest(message, proof.row_commit.root);
    AppendU32(message, proof.row_commit.n_leaves);
    AppendU32(
        message,
        static_cast<uint32_t>(
            proof.column_len.size()));
    for (const uint32_t len : proof.column_len) {
        AppendU32(message, len);
    }
    AppendFp3(message, proof.lambda);
    AppendFp3(message, proof.z1);
    AppendFp3(message, proof.z2);
    for (const auto& value : proof.evals_z1) {
        AppendFp3(message, value);
    }
    for (const auto& value : proof.evals_z2) {
        AppendFp3(message, value);
    }
    AppendFp3(message, proof.w1);
    AppendFp3(message, proof.w2);
    AppendU32(
        message,
        static_cast<uint32_t>(
            proof.fold_layers.size()));
    for (const auto& layer : proof.fold_layers) {
        AppendDigest(message, layer.root);
        AppendU32(message, layer.n_leaves);
    }
    AppendFp3(message, proof.final_value);
    for (const auto& challenge :
         proof.fold_challenges) {
        AppendFp3(message, challenge);
    }
    AppendU32(
        message,
        static_cast<uint32_t>(
            proof.queries.size()));
    for (const auto& query : proof.queries) {
        AppendU32(message, query.index);
        AppendU32(
            message,
            static_cast<uint32_t>(
                query.steps.size()));
        for (const auto& step : query.steps) {
            AppendU32(message, step.even_index);
            AppendU32(message, step.odd_index);
        }
    }
    return SafeHash(PROOF_DOMAIN_V1, message);
}

ah::Digest ComputeEvaluationRootV1(
    const ReceiptV1& receipt)
{
    std::vector<gf::Fp> message;
    AppendU32(message, receipt.version);
    AppendDigest(message, receipt.descriptor_root);
    AppendU32(message, receipt.range.first_column);
    AppendU32(message, receipt.range.column_count);
    AppendUint256(message, receipt.chunk_fs_seed);
    AppendFp3(message, receipt.fri_proof.z1);
    AppendFp3(message, receipt.fri_proof.z2);
    AppendU32(
        message,
        static_cast<uint32_t>(
            receipt.evaluations.size()));
    for (const auto& evaluation : receipt.evaluations) {
        AppendU32(message, evaluation.global_column_id);
        AppendU32(message, evaluation.logical_len);
        AppendFp3(message, evaluation.at_z1);
        AppendFp3(message, evaluation.at_z2);
    }
    return SafeHash(EVALUATION_DOMAIN_V1, message);
}

ah::Digest ComputeReceiptRootV1(
    const ReceiptV1& receipt)
{
    std::vector<gf::Fp> message;
    AppendU32(message, receipt.version);
    AppendDigest(message, receipt.descriptor_root);
    AppendU32(message, receipt.range.first_column);
    AppendU32(message, receipt.range.column_count);
    AppendU32(message, receipt.fri_proof.version);
    AppendU64(message, receipt.fri_proof.pow_grind_nonce);
    AppendU32(message, receipt.fri_proof.blowup);
    AppendU32(message, receipt.fri_proof.n_coeffs);
    AppendDigest(message, receipt.fri_proof.row_commit.root);
    AppendU32(
        message,
        receipt.fri_proof.row_commit.n_leaves);
    AppendDigest(message, receipt.proof_statement_root);
    AppendDigest(message, receipt.evaluation_root);
    return SafeHash(RECEIPT_DOMAIN_V1, message);
}

AuditV1 BuildReceiptV1(
    const PublicDescriptorV1& descriptor,
    const ChunkRangeV1& range,
    const Fri3AlgBatchProof& fri_proof,
    ReceiptV1& out)
{
    out = {};
    Fri3AlgBatchProof canonical_proof;
    if (!CanonicalizeProverProof(
            fri_proof, canonical_proof)) {
        AuditV1 failed;
        failed.note = "receipt_prover_codec";
        return failed;
    }
    ReceiptV1 candidate;
    candidate.version = kReceiptVersionV1;
    candidate.descriptor_root =
        descriptor.descriptor_root;
    candidate.range = range;
    candidate.chunk_fs_seed =
        DeriveChunkFsSeedV1(descriptor, range);
    candidate.fri_proof = std::move(canonical_proof);
    candidate.evaluations =
        EvaluationsFromProof(
            descriptor, range,
            candidate.fri_proof);
    candidate.proof_statement_root =
        ComputeProofStatementRootV1(
            candidate.fri_proof);
    candidate.evaluation_root =
        ComputeEvaluationRootV1(candidate);
    candidate.receipt_root =
        ComputeReceiptRootV1(candidate);
    const AuditV1 audit =
        VerifyReceiptV1(descriptor, candidate);
    if (audit.valid) out = std::move(candidate);
    return audit;
}

AuditV1 VerifyReceiptV1(
    const PublicDescriptorV1& expected_descriptor,
    const ReceiptV1& receipt)
{
    AuditV1 out;
    std::string why;
    out.public_descriptor_reconstructed =
        ValidatePublicDescriptorV1(
            expected_descriptor, &why);
    if (!out.public_descriptor_reconstructed) {
        out.note = why;
        return out;
    }
    out.canonical_chunk_range =
        receipt.version == kReceiptVersionV1 &&
        RangeValid(expected_descriptor, receipt.range) &&
        DigestCanonical(receipt.descriptor_root) &&
        DigestEq(
            receipt.descriptor_root,
            expected_descriptor.descriptor_root);
    if (!out.canonical_chunk_range) {
        out.note = "receipt_range_or_descriptor";
        return out;
    }
    const auto& proof = receipt.fri_proof;
    const uint256 expected_chunk_seed =
        DeriveChunkFsSeedV1(
            expected_descriptor, receipt.range);
    if (expected_chunk_seed.IsNull() ||
        receipt.chunk_fs_seed != expected_chunk_seed) {
        out.note = "receipt_chunk_seed_transplant";
        return out;
    }
    out.exact_column_order_and_lengths =
        proof.version ==
            kRCFri3AlgSafeQ192K2ProofVersionV13 &&
        proof.column_len.size() ==
            receipt.range.column_count &&
        proof.evals_z1.size() ==
            receipt.range.column_count &&
        proof.evals_z2.size() ==
            receipt.range.column_count &&
        proof.n_coeffs != 0 &&
        (proof.n_coeffs &
         (proof.n_coeffs - 1U)) == 0 &&
        proof.n_coeffs <=
            kRCGkrColumnMaxCoeffs;
    if (out.exact_column_order_and_lengths) {
        for (uint32_t local = 0;
             local < receipt.range.column_count;
             ++local) {
            const auto& column =
                expected_descriptor.columns[
                    receipt.range.first_column + local];
            if (column.logical_len >
                    std::numeric_limits<uint32_t>::max() ||
                proof.column_len[local] !=
                    column.logical_len) {
                out.exact_column_order_and_lengths =
                    false;
                break;
            }
        }
    }
    if (!out.exact_column_order_and_lengths) {
        out.note = "receipt_column_order_or_length";
        return out;
    }
    std::vector<unsigned char> proof_bytes;
    out.canonical_codec_round_trip =
        CanonicalCodec(proof, proof_bytes);
    if (!out.canonical_codec_round_trip) {
        out.note = "receipt_noncanonical_proof";
        return out;
    }
    const auto expected_evaluations =
        EvaluationsFromProof(
            expected_descriptor,
            receipt.range, proof);
    out.dual_ood_evaluations_proof_owned =
        receipt.evaluations.size() ==
            expected_evaluations.size();
    if (out.dual_ood_evaluations_proof_owned) {
        for (uint32_t index = 0;
             index < expected_evaluations.size();
             ++index) {
            const auto& actual =
                receipt.evaluations[index];
            const auto& expected =
                expected_evaluations[index];
            if (actual.global_column_id !=
                    expected.global_column_id ||
                actual.logical_len !=
                    expected.logical_len ||
                !Fp3Canonical(actual.at_z1) ||
                !Fp3Canonical(actual.at_z2) ||
                !gf::Eq(actual.at_z1, expected.at_z1) ||
                !gf::Eq(actual.at_z2, expected.at_z2)) {
                out.dual_ood_evaluations_proof_owned =
                    false;
                break;
            }
        }
    }
    if (!out.dual_ood_evaluations_proof_owned) {
        out.note = "receipt_evaluation_transplant";
        return out;
    }
    out.v13_fri_verified =
        Fri3AlgSafeQ192K2V13BatchVerify(
            proof,
            expected_chunk_seed,
            &why);
    if (!out.v13_fri_verified) {
        out.note = "receipt_fri:" + why;
        return out;
    }
    const ah::Digest proof_root =
        ComputeProofStatementRootV1(proof);
    const ah::Digest eval_root =
        ComputeEvaluationRootV1(receipt);
    const ah::Digest receipt_root =
        ComputeReceiptRootV1(receipt);
    out.authenticated_proof_statement_bound =
        !DigestZero(proof_root) &&
        DigestEq(
            receipt.proof_statement_root,
            proof_root) &&
        DigestEq(receipt.evaluation_root, eval_root) &&
        DigestEq(receipt.receipt_root, receipt_root);
    if (!out.authenticated_proof_statement_bound) {
        out.note = "receipt_root_transplant";
        return out;
    }
    NormalizedPublicInputV1 normalized;
    FillNormalized(receipt, normalized);
    out.normalized_public_input_exported =
        !DigestZero(normalized.descriptor_root) &&
        !DigestZero(normalized.proof_statement_root) &&
        !DigestZero(normalized.evaluation_root) &&
        !DigestZero(normalized.receipt_root) &&
        !DigestZero(normalized.row_root) &&
        !normalized.chunk_fs_seed.IsNull();
    out.arbitrary_gkr_mle_claims_verified = false;
    out.episode_content_to_round_roots_verified = false;
    out.recursively_consumed = false;
    out.valid =
        out.public_descriptor_reconstructed &&
        out.canonical_chunk_range &&
        out.exact_column_order_and_lengths &&
        out.canonical_codec_round_trip &&
        out.v13_fri_verified &&
        out.dual_ood_evaluations_proof_owned &&
        out.authenticated_proof_statement_bound &&
        out.normalized_public_input_exported;
    out.note = out.valid
        ? "authenticated_dual_ood_oracle_boundary_ok;"
          "arbitrary_mle_and_recursive_consumption_open"
        : "normalized_export";
    return out;
}

bool ExportNormalizedPublicInputV1(
    const PublicDescriptorV1& expected_descriptor,
    const ReceiptV1& receipt,
    NormalizedPublicInputV1& out,
    std::string* why)
{
    out = {};
    const AuditV1 audit =
        VerifyReceiptV1(
            expected_descriptor, receipt);
    if (!audit.valid) {
        return Fail(
            why, "normalized_input:" + audit.note);
    }
    FillNormalized(receipt, out);
    return true;
}

ah::Digest ComputeOrderedSetRootV1(
    const ReceiptSetV1& set)
{
    std::vector<gf::Fp> message;
    AppendU32(message, set.version);
    AppendDigest(message, set.descriptor_root);
    AppendU32(
        message,
        static_cast<uint32_t>(set.receipts.size()));
    for (const auto& receipt : set.receipts) {
        AppendU32(message, receipt.range.first_column);
        AppendU32(message, receipt.range.column_count);
        AppendDigest(message, receipt.receipt_root);
    }
    return SafeHash(RECEIPT_SET_DOMAIN_V1, message);
}

ReceiptSetAuditV1 VerifyReceiptSetV1(
    const PublicDescriptorV1& expected_descriptor,
    const ReceiptSetV1& set)
{
    ReceiptSetAuditV1 out;
    if (!ValidatePublicDescriptorV1(
            expected_descriptor, nullptr) ||
        set.version != kReceiptVersionV1 ||
        !DigestEq(
            set.descriptor_root,
            expected_descriptor.descriptor_root) ||
        set.receipts.empty()) {
        out.note = "receipt_set_shape";
        return out;
    }
    uint32_t next = 0;
    out.every_receipt_verified = true;
    for (const auto& receipt : set.receipts) {
        if (receipt.range.first_column != next) {
            out.every_receipt_verified = false;
            break;
        }
        const AuditV1 audit =
            VerifyReceiptV1(
                expected_descriptor, receipt);
        if (!audit.valid) {
            out.every_receipt_verified = false;
            out.note = audit.note;
            break;
        }
        next += receipt.range.column_count;
    }
    out.exact_disjoint_partition =
        out.every_receipt_verified &&
        next == expected_descriptor.columns.size();
    out.ordered_set_root_bound =
        out.exact_disjoint_partition &&
        DigestCanonical(set.ordered_set_root) &&
        !DigestZero(set.ordered_set_root) &&
        DigestEq(
            set.ordered_set_root,
            ComputeOrderedSetRootV1(set));
    out.coefficient_wires_serialized = false;
    out.episode_content_to_round_roots_verified = false;
    out.arbitrary_gkr_mle_claims_verified = false;
    out.recursively_consumed = false;
    out.valid =
        out.exact_disjoint_partition &&
        out.every_receipt_verified &&
        out.ordered_set_root_bound;
    if (out.note.empty()) {
        out.note = out.valid
            ? "wireless_v13_oracle_partition_ok;"
              "arbitrary_mle_and_recursive_consumption_open"
            : "receipt_set_partition_or_root";
    }
    return out;
}

} // namespace matmul::v4::rc::stage3_gkr_wireless_receipt
