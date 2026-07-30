// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_family_fold.h>

#include <hash.h>

#include <algorithm>
#include <array>
#include <limits>
#include <memory>

namespace matmul::v4::rc::stage3_family_fold {
namespace {

namespace gf = gkr_field;

constexpr char BASE_DOMAIN[] =
    "BTX_RC_STAGE3_AUTH_LINEAR_FAMILY_FOLD_BASE_V1";
constexpr char CHALLENGE_DOMAIN[] =
    "BTX_RC_STAGE3_AUTH_LINEAR_FAMILY_FOLD_CHALLENGE_V1";
constexpr char RHO_EPOCH_DOMAIN[] =
    "BTX_RC_STAGE3_AUTH_LINEAR_FAMILY_FOLD_RHO_EPOCH_V1";
constexpr char EVAL_EPOCH_DOMAIN[] =
    "BTX_RC_STAGE3_AUTH_LINEAR_FAMILY_FOLD_EVAL_EPOCH_V1";
constexpr char FRI_EPOCH_DOMAIN[] =
    "BTX_RC_STAGE3_AUTH_LINEAR_FAMILY_FOLD_FRI_EPOCH_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:family_linear_fold:" + detail;
    }
    return false;
}

bool IsPowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

uint32_t Log2Exact(uint32_t value)
{
    uint32_t out = 0;
    while (value > 1) {
        value >>= 1;
        ++out;
    }
    return out;
}

bool CanonicalDigest(const Fri3AlgDigest& digest)
{
    for (const auto limb : digest) {
        if (limb >= gf::kP) return false;
    }
    return true;
}

bool SameDigest(const Fri3AlgDigest& a, const Fri3AlgDigest& b)
{
    for (uint32_t i = 0; i < a.size(); ++i) {
        if (gf::Canonical(a[i]) != gf::Canonical(b[i])) return false;
    }
    return true;
}

void AppendU16(std::vector<unsigned char>& out, uint16_t value)
{
    out.push_back(static_cast<unsigned char>(value));
    out.push_back(static_cast<unsigned char>(value >> 8));
}

void AppendU32(std::vector<unsigned char>& out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back(
            static_cast<unsigned char>(value >> (8 * i)));
    }
}

void AppendU64(std::vector<unsigned char>& out, uint64_t value)
{
    for (uint32_t i = 0; i < 8; ++i) {
        out.push_back(
            static_cast<unsigned char>(value >> (8 * i)));
    }
}

void AppendFp3Bytes(std::vector<unsigned char>& out, const Fp3& value)
{
    AppendU64(out, gf::Canonical(value.c0));
    AppendU64(out, gf::Canonical(value.c1));
    AppendU64(out, gf::Canonical(value.c2));
}

bool ReadU16(const std::vector<unsigned char>& bytes,
             size_t& cursor, uint16_t& out)
{
    if (cursor > bytes.size() || bytes.size() - cursor < 2) return false;
    out = static_cast<uint16_t>(bytes[cursor]) |
        (static_cast<uint16_t>(bytes[cursor + 1]) << 8);
    cursor += 2;
    return true;
}

bool ReadU32(const std::vector<unsigned char>& bytes,
             size_t& cursor, uint32_t& out)
{
    if (cursor > bytes.size() || bytes.size() - cursor < 4) return false;
    out = 0;
    for (uint32_t i = 0; i < 4; ++i) {
        out |= static_cast<uint32_t>(bytes[cursor + i]) << (8 * i);
    }
    cursor += 4;
    return true;
}

bool ReadU64(const std::vector<unsigned char>& bytes,
             size_t& cursor, uint64_t& out)
{
    if (cursor > bytes.size() || bytes.size() - cursor < 8) return false;
    out = 0;
    for (uint32_t i = 0; i < 8; ++i) {
        out |= static_cast<uint64_t>(bytes[cursor + i]) << (8 * i);
    }
    cursor += 8;
    return true;
}

bool ReadFp3Bytes(const std::vector<unsigned char>& bytes,
                  size_t& cursor, Fp3& out)
{
    if (!ReadU64(bytes, cursor, out.c0) ||
        !ReadU64(bytes, cursor, out.c1) ||
        !ReadU64(bytes, cursor, out.c2)) {
        return false;
    }
    return out.c0 < gf::kP && out.c1 < gf::kP && out.c2 < gf::kP;
}

void WriteFp3(HashWriter& hash, const Fp3& value)
{
    hash << gf::Canonical(value.c0);
    hash << gf::Canonical(value.c1);
    hash << gf::Canonical(value.c2);
}

bool ValidateMetadata(const AuthenticatedLinearFamilyFoldMetadataV1& metadata,
                      std::string* why)
{
    if (metadata.version != kAuthenticatedLinearFamilyFoldVersion) {
        return Fail(why, "metadata_version");
    }
    if (metadata.family_index >= kAuthenticatedLinearFamilyFoldMaxFamilies ||
        metadata.role_index >= kAuthenticatedLinearFamilyFoldMaxRoles) {
        return Fail(why, "family_or_role_range");
    }
    if (!IsPowerOfTwo(metadata.committed_shards) ||
        !IsPowerOfTwo(metadata.rows_per_shard)) {
        return Fail(why, "dimensions_not_power_of_two");
    }
    const uint64_t cells =
        uint64_t{metadata.committed_shards} * metadata.rows_per_shard;
    if (cells > (uint64_t{1} << kRCFriMaxColumnLog2) ||
        cells > std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "coefficient_domain");
    }
    if (metadata.program_registry_alg_root.IsNull() ||
        metadata.family_statement_binding.IsNull()) {
        return Fail(why, "public_binding_null");
    }
    return true;
}

uint256 BaseDigest(const AuthenticatedLinearFamilyFoldPublicInputsV1& public_inputs)
{
    const auto& metadata = public_inputs.metadata;
    HashWriter hash;
    hash << BASE_DOMAIN;
    hash << metadata.version;
    hash << metadata.family_index;
    hash << metadata.role_index;
    hash << metadata.committed_shards;
    hash << metadata.rows_per_shard;
    hash << metadata.program_registry_alg_root;
    hash << metadata.family_statement_binding;
    hash << Fri3AlgDigestToUint256(public_inputs.source_root);
    return hash.GetHash();
}

bool UniformChallenge(const uint256& epoch, const char* label,
                      uint32_t index, Fp3& out)
{
    std::array<uint64_t, kRCFri3AlgDualUniformWords> words{};
    for (uint32_t block = 0;
         block < kRCFri3AlgDualUniformHashBlocks;
         ++block) {
        HashWriter hash;
        hash << CHALLENGE_DOMAIN;
        hash << epoch;
        hash << std::string(label);
        hash << index;
        hash << block;
        const uint256 digest = hash.GetHash();
        for (uint32_t word = 0; word < 4; ++word) {
            words[4 * block + word] =
                digest.GetUint64(static_cast<int>(word));
        }
    }
    const auto selected = Fri3AlgSelectUniformFp3Words(words);
    if (!selected.has_value()) return false;
    out = *selected;
    return true;
}

uint256 RhoEpoch(
    const AuthenticatedLinearFamilyFoldPublicInputsV1& public_inputs,
    const Fri3AlgDigest& folded_root,
    const std::vector<Fp3>& beta)
{
    HashWriter hash;
    hash << RHO_EPOCH_DOMAIN;
    hash << BaseDigest(public_inputs);
    hash << Fri3AlgDigestToUint256(folded_root);
    hash << static_cast<uint32_t>(beta.size());
    for (const auto& value : beta) WriteFp3(hash, value);
    return hash.GetHash();
}

uint256 EvalEpoch(
    const AuthenticatedLinearFamilyFoldPublicInputsV1& public_inputs,
    const Fri3AlgDigest& folded_root,
    const std::vector<Fp3>& beta,
    const std::vector<Fp3>& rho)
{
    HashWriter hash;
    hash << EVAL_EPOCH_DOMAIN;
    hash << RhoEpoch(public_inputs, folded_root, beta);
    hash << static_cast<uint32_t>(rho.size());
    for (const auto& value : rho) WriteFp3(hash, value);
    return hash.GetHash();
}

uint256 FriEpoch(
    const AuthenticatedLinearFamilyFoldPublicInputsV1& public_inputs,
    const Fri3AlgDigest& folded_root,
    const Fri3AlgDigest& evaluation_witness_root,
    const std::vector<Fp3>& beta,
    const std::vector<Fp3>& rho)
{
    HashWriter hash;
    hash << FRI_EPOCH_DOMAIN;
    hash << EvalEpoch(public_inputs, folded_root, beta, rho);
    hash << Fri3AlgDigestToUint256(public_inputs.source_root);
    hash << Fri3AlgDigestToUint256(folded_root);
    hash << Fri3AlgDigestToUint256(evaluation_witness_root);
    return hash.GetHash();
}

Fp3 MleEval(const std::vector<Fp3>& coefficients,
            const std::vector<Fp3>& point)
{
    const std::vector<Fp3> kernel = RCGkrEqKernelCoeffs3(point);
    if (kernel.size() != coefficients.size()) return Fp3::Zero();
    Fp3 out = Fp3::Zero();
    for (uint32_t i = 0; i < coefficients.size(); ++i) {
        out = gf::Add(out, gf::Mul(coefficients[i], kernel[i]));
    }
    return out;
}

bool FlattenShards(const AuthenticatedLinearFamilyFoldMetadataV1& metadata,
                   const std::vector<std::vector<Fp3>>& shards,
                   std::vector<Fp3>& flattened,
                   std::string* why)
{
    if (!ValidateMetadata(metadata, why)) return false;
    if (shards.size() != metadata.committed_shards) {
        return Fail(why, "shard_count");
    }
    flattened.clear();
    flattened.reserve(
        uint64_t{metadata.committed_shards} * metadata.rows_per_shard);
    for (const auto& shard : shards) {
        if (shard.size() != metadata.rows_per_shard) {
            return Fail(why, "row_count");
        }
        flattened.insert(flattened.end(), shard.begin(), shard.end());
    }
    return true;
}

bool BuildCache(const std::vector<std::vector<Fp3>>& columns,
                uint32_t n_coeffs,
                std::shared_ptr<Fri3AlgRowTreeCache>& cache,
                std::string* why)
{
    cache = std::make_shared<Fri3AlgRowTreeCache>();
    std::string cache_why;
    if (!Fri3AlgBuildRowTreeCacheStreaming(
            columns, n_coeffs, *cache, &cache_why)) {
        return Fail(why, "row_commit:" + cache_why);
    }
    return true;
}

Fri3BatchProof EvalArgumentBatchView(
    const Fri3AlgMultiRowBatchProof& batch)
{
    Fri3BatchProof out;
    out.n_coeffs = batch.n_coeffs;
    out.columns.resize(batch.column_len.size());
    out.z1 = batch.z1;
    out.z2 = batch.z2;
    out.evals_z1 = batch.evals_z1;
    out.evals_z2 = batch.evals_z2;
    return out;
}

AuthenticatedLinearFamilyFoldProveResultV1 ProveCandidate(
    const AuthenticatedLinearFamilyFoldMetadataV1& metadata,
    const std::vector<std::vector<Fp3>>& shards,
    const std::vector<Fp3>* candidate)
{
    AuthenticatedLinearFamilyFoldProveResultV1 out;
    out.public_inputs.metadata = metadata;
    const auto fail = [&](const std::string& detail) {
        out.note = "stage3:family_linear_fold:prove:" + detail;
        return out;
    };

    std::vector<Fp3> source;
    std::string why;
    if (!FlattenShards(metadata, shards, source, &why)) {
        return fail(why);
    }
    const uint32_t n_coeffs = static_cast<uint32_t>(source.size());
    std::shared_ptr<Fri3AlgRowTreeCache> source_cache;
    if (!BuildCache({source}, n_coeffs, source_cache, &why)) {
        return fail(why);
    }
    out.public_inputs.source_root = source_cache->root;

    std::vector<Fp3> beta;
    if (!DeriveAuthenticatedLinearFamilyBetaV1(
            out.public_inputs, beta, &why)) {
        return fail(why);
    }
    std::vector<Fp3> honest_fold;
    if (!ComputeAuthenticatedLinearFamilyFoldV1(
            shards, beta, honest_fold, &why)) {
        return fail(why);
    }
    const std::vector<Fp3>& selected_fold =
        candidate == nullptr ? honest_fold : *candidate;
    if (selected_fold.size() != metadata.rows_per_shard) {
        return fail("candidate_row_count");
    }

    // The folded column is explicitly zero-extended to the common coefficient
    // domain. Its high-coordinate MLE point is therefore fixed to zero.
    std::vector<Fp3> folded(n_coeffs, Fp3::Zero());
    std::copy(selected_fold.begin(), selected_fold.end(), folded.begin());
    std::shared_ptr<Fri3AlgRowTreeCache> folded_cache;
    if (!BuildCache({folded}, n_coeffs, folded_cache, &why)) {
        return fail(why);
    }

    std::vector<Fp3> rho;
    if (!DeriveAuthenticatedLinearFamilyRhoV1(
            out.public_inputs, folded_cache->root, beta, rho, &why)) {
        return fail(why);
    }
    std::vector<Fp3> source_point = rho;
    source_point.insert(source_point.end(), beta.begin(), beta.end());
    std::vector<Fp3> folded_point = rho;
    folded_point.resize(source_point.size(), Fp3::Zero());
    const Fp3 evaluation = MleEval(source, source_point);
    const std::vector<RCGkrOpeningClaim3> claims{
        {0, source_point, evaluation},
        {1, folded_point, evaluation},
    };
    const uint256 eval_seed =
        EvalEpoch(out.public_inputs, folded_cache->root, beta, rho);
    const auto eval =
        EvalArgumentProve3(claims, {source, folded}, eval_seed);
    if (!eval.ok || eval.proof.f_column != 2 ||
        eval.proof.g_column != 3) {
        return fail("evaluation_argument:" + eval.note);
    }

    std::shared_ptr<Fri3AlgRowTreeCache> quotient_cache;
    if (!BuildCache(
            {eval.f_coeffs, eval.g_coeffs},
            n_coeffs, quotient_cache, &why)) {
        return fail(why);
    }
    const uint256 fri_seed =
        FriEpoch(out.public_inputs, folded_cache->root,
                 quotient_cache->root, beta, rho);
    const std::vector<std::vector<std::vector<Fp3>>> groups{
        {source},
        {folded},
        {eval.f_coeffs, eval.g_coeffs},
    };
    const std::vector<Fri3AlgMultiRowGroupRole> roles{
        Fri3AlgMultiRowGroupRole::MainTrace,
        Fri3AlgMultiRowGroupRole::AuxiliaryTrace,
        Fri3AlgMultiRowGroupRole::Quotient,
    };
    const auto batch = Fri3AlgMultiRowBatchCommitStreaming(
        groups, roles, fri_seed, 0,
        {source_cache, folded_cache, quotient_cache});
    if (!batch.ok) return fail(batch.note);

    out.proof.version = kAuthenticatedLinearFamilyFoldVersion;
    out.proof.evaluation = evaluation;
    out.proof.evaluation_argument = eval.proof;
    out.proof.batch = batch.proof;
    out.ok = true;
    out.note =
        "stage3:family_linear_fold:prove:"
        "R0_source_then_beta_Raux_fold_then_rho_Rdep_eval";
    return out;
}

} // namespace

bool ComputeAuthenticatedLinearFamilyFoldV1(
    const std::vector<std::vector<Fp3>>& shards,
    const std::vector<Fp3>& beta,
    std::vector<Fp3>& folded,
    std::string* why)
{
    if (shards.empty() ||
        shards.size() > std::numeric_limits<uint32_t>::max() ||
        !IsPowerOfTwo(static_cast<uint32_t>(shards.size()))) {
        return Fail(why, "compute_shards");
    }
    if (shards.front().empty() ||
        shards.front().size() > std::numeric_limits<uint32_t>::max() ||
        !IsPowerOfTwo(static_cast<uint32_t>(shards.front().size()))) {
        return Fail(why, "compute_rows");
    }
    const uint32_t rows = static_cast<uint32_t>(shards.front().size());
    for (const auto& shard : shards) {
        if (shard.size() != rows) return Fail(why, "compute_ragged");
    }
    if (beta.size() !=
        Log2Exact(static_cast<uint32_t>(shards.size()))) {
        return Fail(why, "compute_beta_dimension");
    }
    const std::vector<Fp3> weights = RCGkrEqKernelCoeffs3(beta);
    folded.assign(rows, Fp3::Zero());
    for (uint32_t shard = 0; shard < shards.size(); ++shard) {
        for (uint32_t row = 0; row < rows; ++row) {
            folded[row] = gf::Add(
                folded[row],
                gf::Mul(weights[shard], shards[shard][row]));
        }
    }
    return true;
}

AuthenticatedLinearFamilyFoldProveResultV1
ProveAuthenticatedLinearFamilyFoldV1(
    const AuthenticatedLinearFamilyFoldMetadataV1& metadata,
    const std::vector<std::vector<Fp3>>& shards)
{
    return ProveCandidate(metadata, shards, nullptr);
}

AuthenticatedLinearFamilyFoldProveResultV1
ProveAuthenticatedLinearFamilyFoldCandidateV1(
    const AuthenticatedLinearFamilyFoldMetadataV1& metadata,
    const std::vector<std::vector<Fp3>>& shards,
    const std::vector<Fp3>& folded_candidate)
{
    return ProveCandidate(metadata, shards, &folded_candidate);
}

bool DeriveAuthenticatedLinearFamilyBetaV1(
    const AuthenticatedLinearFamilyFoldPublicInputsV1& public_inputs,
    std::vector<Fp3>& beta,
    std::string* why)
{
    if (!ValidateMetadata(public_inputs.metadata, why) ||
        !CanonicalDigest(public_inputs.source_root) ||
        Fri3AlgDigestToUint256(public_inputs.source_root).IsNull()) {
        return Fail(why, "beta_public_inputs");
    }
    const uint256 epoch = BaseDigest(public_inputs);
    beta.resize(Log2Exact(public_inputs.metadata.committed_shards));
    for (uint32_t i = 0; i < beta.size(); ++i) {
        if (!UniformChallenge(epoch, "beta", i, beta[i])) {
            return Fail(why, "beta_sampler_exhausted");
        }
    }
    return true;
}

bool DeriveAuthenticatedLinearFamilyRhoV1(
    const AuthenticatedLinearFamilyFoldPublicInputsV1& public_inputs,
    const Fri3AlgDigest& folded_root,
    const std::vector<Fp3>& beta,
    std::vector<Fp3>& rho,
    std::string* why)
{
    std::vector<Fp3> expected_beta;
    if (!DeriveAuthenticatedLinearFamilyBetaV1(
            public_inputs, expected_beta, why)) {
        return false;
    }
    if (expected_beta.size() != beta.size()) {
        return Fail(why, "rho_beta_shape");
    }
    for (uint32_t i = 0; i < beta.size(); ++i) {
        if (!gf::Eq(expected_beta[i], beta[i])) {
            return Fail(why, "rho_beta_mismatch");
        }
    }
    if (!CanonicalDigest(folded_root) ||
        Fri3AlgDigestToUint256(folded_root).IsNull()) {
        return Fail(why, "rho_folded_root");
    }
    const uint256 epoch = RhoEpoch(public_inputs, folded_root, beta);
    rho.resize(Log2Exact(public_inputs.metadata.rows_per_shard));
    for (uint32_t i = 0; i < rho.size(); ++i) {
        if (!UniformChallenge(epoch, "rho", i, rho[i])) {
            return Fail(why, "rho_sampler_exhausted");
        }
    }
    return true;
}

bool VerifyAuthenticatedLinearFamilyFoldV1(
    const AuthenticatedLinearFamilyFoldPublicInputsV1& public_inputs,
    const AuthenticatedLinearFamilyFoldProofV1& proof,
    std::string* why)
{
    if (!ValidateMetadata(public_inputs.metadata, why)) return false;
    if (proof.version != kAuthenticatedLinearFamilyFoldVersion) {
        return Fail(why, "proof_version");
    }
    if (!CanonicalDigest(public_inputs.source_root) ||
        Fri3AlgDigestToUint256(public_inputs.source_root).IsNull()) {
        return Fail(why, "source_root");
    }
    const uint32_t n_coeffs =
        public_inputs.metadata.committed_shards *
        public_inputs.metadata.rows_per_shard;
    const auto& batch = proof.batch;
    if (batch.n_coeffs != n_coeffs ||
        batch.groups.size() != 3 ||
        batch.column_len.size() != 4 ||
        batch.column_len[0] != n_coeffs ||
        batch.column_len[1] != n_coeffs ||
        batch.column_len[2] != n_coeffs - 1 ||
        batch.column_len[3] != n_coeffs ||
        batch.groups[0].role != Fri3AlgMultiRowGroupRole::MainTrace ||
        batch.groups[0].first_column != 0 ||
        batch.groups[0].column_count != 1 ||
        batch.groups[1].role != Fri3AlgMultiRowGroupRole::AuxiliaryTrace ||
        batch.groups[1].first_column != 1 ||
        batch.groups[1].column_count != 1 ||
        batch.groups[2].role != Fri3AlgMultiRowGroupRole::Quotient ||
        batch.groups[2].first_column != 2 ||
        batch.groups[2].column_count != 2 ||
        !SameDigest(batch.groups[0].row_commit.root,
                    public_inputs.source_root) ||
        proof.evaluation_argument.f_column != 2 ||
        proof.evaluation_argument.g_column != 3) {
        return Fail(why, "canonical_shape");
    }

    std::vector<Fp3> beta;
    if (!DeriveAuthenticatedLinearFamilyBetaV1(
            public_inputs, beta, why)) {
        return false;
    }
    const Fri3AlgDigest& folded_root =
        batch.groups[1].row_commit.root;
    std::vector<Fp3> rho;
    if (!DeriveAuthenticatedLinearFamilyRhoV1(
            public_inputs, folded_root, beta, rho, why)) {
        return false;
    }
    const Fri3AlgDigest& quotient_root =
        batch.groups[2].row_commit.root;
    if (!CanonicalDigest(quotient_root) ||
        !CanonicalDigest(folded_root)) {
        return Fail(why, "group_root_noncanonical");
    }
    const uint256 eval_seed =
        EvalEpoch(public_inputs, folded_root, beta, rho);
    const uint256 fri_seed =
        FriEpoch(public_inputs, folded_root, quotient_root, beta, rho);
    std::string fri_why;
    if (!Fri3AlgMultiRowBatchVerify(batch, fri_seed, &fri_why)) {
        return Fail(why, fri_why);
    }

    std::vector<Fp3> source_point = rho;
    source_point.insert(source_point.end(), beta.begin(), beta.end());
    std::vector<Fp3> folded_point = rho;
    folded_point.resize(source_point.size(), Fp3::Zero());
    const std::vector<RCGkrOpeningClaim3> claims{
        {0, source_point, proof.evaluation},
        {1, folded_point, proof.evaluation},
    };
    const Fri3BatchProof view = EvalArgumentBatchView(batch);
    std::string eval_why;
    if (!EvalArgumentVerify3(
            claims, view, proof.evaluation_argument,
            eval_seed, &eval_why)) {
        return Fail(why, eval_why);
    }
    return true;
}

AuthenticatedLinearFamilyFoldProveResultV1
ProveAuthenticatedZeroResidualFamilyFoldV1(
    const AuthenticatedLinearFamilyFoldMetadataV1& metadata,
    const std::vector<std::vector<Fp3>>& residual_shards)
{
    return ProveAuthenticatedLinearFamilyFoldV1(
        metadata, residual_shards);
}

bool VerifyAuthenticatedZeroResidualFamilyFoldV1(
    const AuthenticatedLinearFamilyFoldPublicInputsV1& public_inputs,
    const AuthenticatedLinearFamilyFoldProofV1& proof,
    std::string* why)
{
    if (!gf::IsZero(proof.evaluation)) {
        return Fail(why, "residual_evaluation_nonzero");
    }
    return VerifyAuthenticatedLinearFamilyFoldV1(
        public_inputs, proof, why);
}

size_t SerializeAuthenticatedLinearFamilyFoldProofV1(
    const AuthenticatedLinearFamilyFoldProofV1& proof,
    std::vector<unsigned char>& out)
{
    out.clear();
    if (proof.version != kAuthenticatedLinearFamilyFoldVersion ||
        proof.evaluation_argument.version != kRCGkrEvalArgVersion) {
        return 0;
    }
    std::vector<unsigned char> batch;
    const size_t batch_size =
        SerializeFri3AlgMultiRowBatchProof(proof.batch, batch);
    if (batch_size == 0 ||
        batch_size != batch.size() ||
        batch_size > kRCFri3AlgMultiRowMaxProofBytesHard ||
        batch_size > std::numeric_limits<uint32_t>::max()) {
        return 0;
    }
    out.reserve(64 + batch.size());
    AppendU32(out, kAuthenticatedLinearFamilyFoldMagic);
    AppendU16(out, proof.version);
    AppendU16(out, 0);
    AppendFp3Bytes(out, proof.evaluation);
    AppendU32(out, proof.evaluation_argument.version);
    AppendFp3Bytes(out, proof.evaluation_argument.sigma);
    AppendU32(out, proof.evaluation_argument.f_column);
    AppendU32(out, proof.evaluation_argument.g_column);
    AppendU32(out, static_cast<uint32_t>(batch.size()));
    out.insert(out.end(), batch.begin(), batch.end());
    if (out.size() > kAuthenticatedLinearFamilyFoldMaxProofBytes) {
        out.clear();
        return 0;
    }
    return out.size();
}

std::optional<AuthenticatedLinearFamilyFoldProofV1>
DeserializeAuthenticatedLinearFamilyFoldProofV1(
    const std::vector<unsigned char>& bytes)
{
    // 4 magic + 2 version + 2 reserved + 24 evaluation + 4 eval version +
    // 24 sigma + 4 f + 4 g + 4 batch length.
    constexpr size_t HEADER_BYTES = 72;
    if (bytes.size() < HEADER_BYTES ||
        bytes.size() > kAuthenticatedLinearFamilyFoldMaxProofBytes) {
        return std::nullopt;
    }
    size_t cursor = 0;
    uint32_t magic = 0;
    uint16_t version = 0;
    uint16_t reserved = 0;
    AuthenticatedLinearFamilyFoldProofV1 out;
    if (!ReadU32(bytes, cursor, magic) ||
        !ReadU16(bytes, cursor, version) ||
        !ReadU16(bytes, cursor, reserved) ||
        magic != kAuthenticatedLinearFamilyFoldMagic ||
        version != kAuthenticatedLinearFamilyFoldVersion ||
        reserved != 0 ||
        !ReadFp3Bytes(bytes, cursor, out.evaluation) ||
        !ReadU32(bytes, cursor, out.evaluation_argument.version) ||
        out.evaluation_argument.version != kRCGkrEvalArgVersion ||
        !ReadFp3Bytes(bytes, cursor, out.evaluation_argument.sigma) ||
        !ReadU32(bytes, cursor, out.evaluation_argument.f_column) ||
        !ReadU32(bytes, cursor, out.evaluation_argument.g_column)) {
        return std::nullopt;
    }
    uint32_t batch_size = 0;
    if (!ReadU32(bytes, cursor, batch_size) ||
        batch_size > kRCFri3AlgMultiRowMaxProofBytesHard ||
        cursor > bytes.size() ||
        bytes.size() - cursor != batch_size) {
        return std::nullopt;
    }
    const std::vector<unsigned char> batch_bytes(
        bytes.begin() + cursor, bytes.end());
    auto batch =
        DeserializeFri3AlgMultiRowBatchProof(batch_bytes);
    if (!batch.has_value()) return std::nullopt;
    out.version = version;
    out.batch = std::move(*batch);
    return out;
}

NonlinearTraceFoldCounterexampleV1
BuildNonlinearTraceFoldCounterexampleV1()
{
    NonlinearTraceFoldCounterexampleV1 out;
    out.beta = gf::FromU64_3(2);
    const Fp3 one = gf::FromU64_3(1);
    const Fp3 two = gf::FromU64_3(2);
    const Fp3 folded = gf::Add(
        gf::Mul(gf::Sub(Fp3::One(), out.beta), one),
        gf::Mul(out.beta, two));
    out.fold_then_square = gf::Mul(folded, folded);
    out.square_then_fold = gf::Add(
        gf::Mul(gf::Sub(Fp3::One(), out.beta), gf::Mul(one, one)),
        gf::Mul(out.beta, gf::Mul(two, two)));
    out.unequal =
        !gf::Eq(out.fold_then_square, out.square_then_fold);
    return out;
}

} // namespace matmul::v4::rc::stage3_family_fold
