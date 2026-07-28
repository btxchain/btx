// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_consensus.h>

#include <arith_uint256.h>
#include <consensus/params.h>
#include <hash.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <matmul/matmul_v4_rc_stage3_verify.h>
#include <primitives/block.h>

#include <condition_variable>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <utility>

namespace matmul::v4::rc {
namespace {

static_assert(!kRCStage3SuccinctAuthorityReady ||
                  kRCStage3MathematicalVerifierReady,
              "Stage-3 consensus attachment cannot precede mathematical readiness");
static_assert(!kRCStage3SuccinctAuthorityReady ||
                  kRCStage3ProductionProgramRegistryReady,
              "Stage-3 authority cannot precede a frozen production ProgramTable registry");

constexpr size_t MAX_VALID_PROOF_CACHE_ENTRIES{64};

std::mutex g_valid_proof_cache_mutex;
std::map<RCStage3ProofCacheKey, bool> g_valid_proof_cache;
std::deque<RCStage3ProofCacheKey> g_valid_proof_fifo;

struct Stage3InFlight {
    std::condition_variable cv;
    bool done{false};
    bool valid{false};
    std::string why;
};

std::mutex g_stage3_singleflight_mutex;
std::map<RCStage3ProofCacheKey, std::shared_ptr<Stage3InFlight>> g_stage3_inflight;

[[maybe_unused]] void CacheMathematicallyVerifiedProof(
    const RCStage3ProofCacheKey& key)
{
    if (key.block_hash.IsNull() ||
        key.program_registry_alg_root.IsNull() ||
        key.proof_payload_digest.IsNull()) return;
    std::lock_guard<std::mutex> lock(g_valid_proof_cache_mutex);
    const auto [it, inserted] = g_valid_proof_cache.emplace(key, true);
    if (!inserted) return;
    g_valid_proof_fifo.push_back(key);
    while (g_valid_proof_fifo.size() > MAX_VALID_PROOF_CACHE_ENTRIES) {
        g_valid_proof_cache.erase(g_valid_proof_fifo.front());
        g_valid_proof_fifo.pop_front();
    }
}

[[maybe_unused]] bool IsMathematicallyVerifiedProofCached(
    const RCStage3ProofCacheKey& key)
{
    std::lock_guard<std::mutex> lock(g_valid_proof_cache_mutex);
    return g_valid_proof_cache.find(key) != g_valid_proof_cache.end();
}

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3-consensus:" + message;
    return false;
}

uint8_t BoolByte(bool value)
{
    return value ? uint8_t{1} : uint8_t{0};
}

uint32_t ExpectedTranscriptVersion(const Consensus::Params& params,
                                   RCStage3StatementKind statement)
{
    if (statement == RCStage3StatementKind::Episode) return kRCTranscriptVersion;
    return ResolveRCCoupOptions(params).transcript_version;
}

} // namespace

std::optional<RCStage3StatementKind>
RequiredRCStage3Statement(const Consensus::Params& params, int32_t height)
{
    if (height < 0) return std::nullopt;
    if (params.IsMatMulRCCoupledActive(height)) {
        return RCStage3StatementKind::Composed;
    }
    if (params.IsMatMulRCActive(height)) return RCStage3StatementKind::Episode;
    return std::nullopt;
}

uint256 RCStage3HeaderCommitment(const CBlockHeader& header)
{
    CBlockHeader projection = header;
    // final_digest separately binds header.matmul_digest. Including it in this
    // projection would make a prover solve a circular proof/digest commitment.
    projection.matmul_digest.SetNull();
    HashWriter h;
    h << std::string{"BTX_RC_STAGE3_HEADER_V1"} << projection;
    return h.GetSHA256();
}

uint256 RCStage3ParamsCommitment(const Consensus::Params& params,
                                 int32_t height,
                                 RCStage3StatementKind statement)
{
    HashWriter h;
    h << std::string{"BTX_RC_STAGE3_PARAMS_V2"}
      << static_cast<uint8_t>(statement)
      << height
      << params.nMatMulV4Dimension
      << params.hashMatMulRCStage3ProgramRegistryAlgRoot
      << params.hashMatMulRCStage3ProgramRegistryShaAuditRoot
      << params.hashMatMulRCStage3ProgramRegistryBinding;

    if (statement == RCStage3StatementKind::Episode ||
        statement == RCStage3StatementKind::Composed) {
        const RCEpisodeParams episode = ResolveRCEpisodeParams(params, height);
        h << params.nMatMulRCProfile
          << episode.rounds
          << episode.d_head
          << episode.n_q
          << episode.n_ctx
          << episode.L_lyr
          << episode.d_model
          << episode.d_ff
          << episode.b_seq
          << episode.T_leaf
          << kRCTranscriptVersion;
    }

    if (statement == RCStage3StatementKind::Coupled ||
        statement == RCStage3StatementKind::Composed) {
        const RCCoupParams coupled = ResolveRCCoupParams(params);
        const RCCoupOptions options = ResolveRCCoupOptions(params);
        h << params.nMatMulRCCoupledProfile
          << coupled.barriers
          << coupled.lobes
          << coupled.lobe_width
          << coupled.bank_pages
          << coupled.rows_per_lobe
          << coupled.pages_per_barrier_lobe
          << static_cast<uint8_t>(options.mode)
          << options.transcript_version
          << BoolByte(options.skip_barrier)
          << options.skip_barrier_index
          << BoolByte(options.skip_bank_page)
          << options.skip_page_index
          << BoolByte(options.full_bank_schedule)
          << BoolByte(options.material_exchange)
          << options.exchange_rows
          << options.exchange_rounds
          << BoolByte(options.force_signed_mix);
    }
    return h.GetSHA256();
}

uint256 ComputeRCStage3ComposedWorkDigest(
    const CBlockHeader& header,
    const Consensus::Params& params,
    int32_t height,
    const uint256& episode_digest,
    const uint256& coupled_digest)
{
    if (height < 0 || !params.IsMatMulRCActive(height) ||
        !params.IsMatMulRCCoupledActive(height) ||
        episode_digest.IsNull() || coupled_digest.IsNull()) {
        return {};
    }
    return ComputeRCStage3ComposedWorkDigest(
        kRCStage3ProofVersion, height, RCStage3HeaderCommitment(header),
        RCStage3ParamsCommitment(
            params, height, RCStage3StatementKind::Composed),
        params.nMatMulRCProfile, params.nMatMulRCCoupledProfile,
        ResolveRCCoupOptions(params).transcript_version, episode_digest,
        coupled_digest);
}

uint256 RCStage3ProofPayloadDigest(const std::vector<uint32_t>& words)
{
    HashWriter h;
    h << std::string{"BTX_RC_STAGE3_BLOCK_PAYLOAD_V2"}
      << words;
    return h.GetSHA256();
}

RCStage3ProofCacheKey RCStage3ProofKey(const CBlock& block)
{
    RCStage3ProofCacheKey out;
    out.block_hash = block.GetHash();
    out.proof_payload_digest =
        RCStage3ProofPayloadDigest(block.matrix_c_data);
    const auto proof = UnpackRCStage3ProofWords(block.matrix_c_data);
    if (proof.has_value()) {
        out.program_registry_alg_root =
            proof->public_inputs.program_consensus_pin
                .recursive_alg_hash_root;
    }
    return out;
}

bool ValidateRCStage3ConsensusBinding(const RCStage3SuccinctProof& proof,
                                      const CBlockHeader& header,
                                      const Consensus::Params& params,
                                      int32_t height,
                                      const uint256& target,
                                      std::string* why)
{
    std::string structure_why;
    if (!ValidateRCStage3ProofStructure(proof, &structure_why)) {
        return Fail(why, "structure:" + structure_why);
    }

    const auto required = RequiredRCStage3Statement(params, height);
    if (!required.has_value()) return Fail(why, "not_rc_height");
    if (proof.statement != *required) return Fail(why, "statement");

    ProductionProgramConsensusPinV1 expected_program_pin;
    expected_program_pin.recursive_alg_hash_root =
        params.hashMatMulRCStage3ProgramRegistryAlgRoot;
    expected_program_pin.external_sha256d_audit_root =
        params.hashMatMulRCStage3ProgramRegistryShaAuditRoot;
    expected_program_pin.registry_binding =
        params.hashMatMulRCStage3ProgramRegistryBinding;
    std::string expected_pin_why;
    if (!ValidateProductionProgramConsensusPinV1(
            expected_program_pin, &expected_pin_why)) {
        return Fail(
            why,
            params.hashMatMulRCStage3ProgramRegistryAlgRoot.IsNull()
                ? "program_registry_unconfigured"
                : "program_registry_expected_pin:" +
                      expected_pin_why);
    }
    if (proof.public_inputs.program_consensus_pin
            .recursive_alg_hash_root !=
        expected_program_pin.recursive_alg_hash_root) {
        return Fail(why, "program_registry_alg_root");
    }
    if (proof.public_inputs.program_consensus_pin
            .external_sha256d_audit_root !=
        expected_program_pin.external_sha256d_audit_root) {
        return Fail(why, "program_registry_sha256d_audit_root");
    }
    if (proof.public_inputs.program_consensus_pin
            .registry_binding !=
        expected_program_pin.registry_binding) {
        return Fail(why, "program_registry_binding");
    }

    // A coupled proof is never sufficient by itself. Coupled consensus is the
    // conjunction of the episode and coupled relations plus CompositionLink.
    if (*required == RCStage3StatementKind::Composed &&
        (!params.IsMatMulRCActive(height) ||
         proof.public_inputs.episode_profile == 0 ||
         proof.public_inputs.coupled_profile == 0)) {
        return Fail(why, "composed_requires_episode_and_coupled");
    }

    const auto& p = proof.public_inputs;
    if (p.height != height) return Fail(why, "height");
    if (p.n_bits != header.nBits) return Fail(why, "nbits");
    if (p.header_commitment != RCStage3HeaderCommitment(header)) {
        return Fail(why, "header_commitment");
    }
    if (p.params_commitment != RCStage3ParamsCommitment(params, height, *required)) {
        return Fail(why, "params_commitment");
    }
    if (p.target != target) return Fail(why, "target");
    if (p.sigma != matmul::v4::DeriveSigma(header)) return Fail(why, "sigma");
    if (p.final_digest != header.matmul_digest) return Fail(why, "final_digest");
    if (p.transcript_version != ExpectedTranscriptVersion(params, *required)) {
        return Fail(why, "transcript_version");
    }
    // AUTHENTICATE THE REST OF THE PAYLOAD.
    //
    // Every other public input above is compared against consensus context.
    // transcript_commitment used to be only NULL-checked
    // (matmul_v4_rc_stage3_stage3.cpp "null_transcript_commitment"), which left
    // it, every per-role commitment root, and every section body unauthenticated
    // by this layer -- 69 of 164 payload words. ComputeRCStage3TranscriptCommitment
    // binds the statement, every public input other than itself, every
    // fixed-role commitment root, and the hash of every relation-proof section
    // in canonical registry order, so recomputing and COMPARING it here binds
    // all three at once. The mathematical verifier checks this too (via
    // VerifyRCStage3CompositionLink) but is gated off; the binding layer must
    // not depend on that.
    if (p.transcript_commitment != ComputeRCStage3TranscriptCommitment(proof)) {
        return Fail(why, "transcript_commitment");
    }

    if (*required == RCStage3StatementKind::Episode) {
        if (p.episode_profile != params.nMatMulRCProfile ||
            p.episode_digest != header.matmul_digest ||
            p.coupled_profile != 0 ||
            !p.coupled_digest.IsNull()) {
            return Fail(why, "episode_public_inputs");
        }
    } else if (*required == RCStage3StatementKind::Composed) {
        if (p.episode_profile != params.nMatMulRCProfile ||
            p.coupled_profile != params.nMatMulRCCoupledProfile ||
            p.episode_digest.IsNull() ||
            p.coupled_digest.IsNull()) {
            return Fail(why, "composed_public_inputs");
        }
    } else {
        // RequiredRCStage3Statement intentionally never selects Coupled. Keep
        // the branch explicit so a future change cannot silently authorize it.
        return Fail(why, "coupled_only_not_consensus");
    }

    if (UintToArith256(header.matmul_digest) > UintToArith256(target)) {
        return Fail(why, "digest_above_target");
    }
    return true;
}

bool AttachRCStage3ConsensusProof(CBlock& block,
                                  const RCStage3SuccinctProof& proof,
                                  const Consensus::Params& params,
                                  int32_t height,
                                  const uint256& target,
                                  std::string* why)
{
    if (!ValidateRCStage3ConsensusBinding(
            proof, block, params, height, target, why)) {
        return false;
    }
    std::vector<uint32_t> packed;
    if (!PackRCStage3ProofWords(proof, packed, why)) return false;
    block.matrix_c_data = std::move(packed);
    return true;
}

RCStage3AttachmentStatus InspectRCStage3ConsensusAttachment(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    RCStage3SuccinctProof* proof_out,
    RCStage3ProofCacheKey* cache_key_out,
    std::string* why)
{
    if (proof_out != nullptr) *proof_out = {};
    if (cache_key_out != nullptr) *cache_key_out = {};

    if (!RequiredRCStage3Statement(params, height).has_value()) {
        Fail(why, "not_required");
        return RCStage3AttachmentStatus::NotRequired;
    }
    if (block.matrix_c_data.empty()) {
        Fail(why, "missing");
        return RCStage3AttachmentStatus::Missing;
    }
    if (!IsRCStage3ProofWords(block.matrix_c_data)) {
        Fail(why, "bad_payload_magic");
        return RCStage3AttachmentStatus::Malformed;
    }

    std::string unpack_why;
    const auto proof = UnpackRCStage3ProofWords(block.matrix_c_data, &unpack_why);
    if (!proof.has_value()) {
        Fail(why, "unpack:" + unpack_why);
        return RCStage3AttachmentStatus::Malformed;
    }
    if (!ValidateRCStage3ConsensusBinding(*proof, block, params, height, target, why)) {
        return RCStage3AttachmentStatus::BindingMismatch;
    }

    if (proof_out != nullptr) *proof_out = *proof;
    if (cache_key_out != nullptr) *cache_key_out = RCStage3ProofKey(block);

    if (!kRCStage3SuccinctAuthorityReady) {
        Fail(why, "authority_unavailable");
        return RCStage3AttachmentStatus::AuthorityUnavailable;
    }
    return RCStage3AttachmentStatus::ReadyForMathematicalVerification;
}

RCStage3AttachmentStatus VerifyRCStage3ConsensusAttachment(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    std::string* why)
{
    RCStage3SuccinctProof proof;
    RCStage3ProofCacheKey key;
    const RCStage3AttachmentStatus inspected = InspectRCStage3ConsensusAttachment(
        block, params, height, target, &proof, &key, why);
    if (inspected != RCStage3AttachmentStatus::ReadyForMathematicalVerification) {
        return inspected;
    }

    if constexpr (!kRCStage3SuccinctAuthorityReady) {
        Fail(why, "authority_unavailable");
        return RCStage3AttachmentStatus::AuthorityUnavailable;
    } else {
        if (IsMathematicallyVerifiedProofCached(key)) {
            return RCStage3AttachmentStatus::Valid;
        }

        std::shared_ptr<Stage3InFlight> flight;
        bool leader{false};
        {
            std::unique_lock<std::mutex> lock(g_stage3_singleflight_mutex);
            const auto [it, inserted] =
                g_stage3_inflight.emplace(key, std::make_shared<Stage3InFlight>());
            flight = it->second;
            leader = inserted;
            if (!leader) {
                flight->cv.wait(lock, [&flight] { return flight->done; });
                if (flight->valid) return RCStage3AttachmentStatus::Valid;
                Fail(why, "mathematical_verification:" + flight->why);
                return RCStage3AttachmentStatus::MathematicalVerificationFailed;
            }
        }

        std::string verify_why;
        const bool valid = VerifyRCStage3MathematicalProof(
            proof, block, params, height, UintToArith256(target), &verify_why);
        if (valid) CacheMathematicallyVerifiedProof(key);
        {
            std::lock_guard<std::mutex> lock(g_stage3_singleflight_mutex);
            flight->valid = valid;
            flight->why = verify_why;
            flight->done = true;
            g_stage3_inflight.erase(key);
            flight->cv.notify_all();
        }
        if (!valid) {
            Fail(why, "mathematical_verification:" + verify_why);
            return RCStage3AttachmentStatus::MathematicalVerificationFailed;
        }
        return RCStage3AttachmentStatus::Valid;
    }
}

bool RCStage3AttachmentIsMutation(RCStage3AttachmentStatus status)
{
    return status == RCStage3AttachmentStatus::Missing ||
           status == RCStage3AttachmentStatus::Malformed ||
           status == RCStage3AttachmentStatus::BindingMismatch ||
           status == RCStage3AttachmentStatus::MathematicalVerificationFailed;
}

} // namespace matmul::v4::rc
