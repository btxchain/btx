// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <limits>
#include <stdint.h>
#include <string>
#include <vector>

class CBlockHeader;
class CBlock;
class CBlockIndex;
class uint256;
class arith_uint256;

/**
 * Convert nBits value to target.
 *
 * @param[in] nBits     compact representation of the target
 * @param[in] pow_limit PoW limit (consensus parameter)
 *
 * @return              the proof-of-work target or nullopt if the nBits value
 *                      is invalid (due to overflow or exceeding pow_limit)
 */
std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit);

struct MatMulPeerVerificationBudget {
    // Access is externally synchronized in net_processing by peer-specific locks.
    uint32_t expensive_verifications_this_minute{0};
    std::chrono::steady_clock::time_point window_start{};
    uint32_t phase2_failures{0};
    std::chrono::steady_clock::time_point phase2_first_failure_time{};
};

enum class MatMulPhase2Punishment {
    DISCONNECT,
    DISCOURAGE,
    BAN,
};

struct MatMulSolvePipelineStats {
    bool parallel_solver_enabled{false};
    uint32_t parallel_solver_threads{1};
    bool async_prepare_enabled{false};
    bool cpu_confirm_candidates{false};
    uint64_t prepared_inputs{0};
    uint64_t overlapped_prepares{0};
    uint64_t prefetched_batches{0};
    uint64_t prefetched_inputs{0};
    uint64_t async_prepare_submissions{0};
    uint64_t async_prepare_completions{0};
    uint32_t async_prepare_worker_threads{0};
    uint32_t prefetch_depth{1};
    uint32_t batch_size{1};
    uint64_t batched_digest_requests{0};
    uint64_t batched_nonce_attempts{0};
};

struct MatMulDigestCompareStats {
    bool enabled{false};
    uint64_t compared_attempts{0};
    bool first_divergence_captured{false};
    uint64_t first_divergence_nonce64{0};
    uint32_t first_divergence_nonce32{0};
    std::string first_divergence_header_hash{};
    std::string first_divergence_backend_digest{};
    std::string first_divergence_cpu_digest{};
};

struct MatMulSolveRuntimeStats {
    uint64_t attempts{0};
    uint64_t solved_attempts{0};
    uint64_t failed_attempts{0};
    uint64_t total_elapsed_us{0};
    uint64_t last_elapsed_us{0};
    uint64_t max_elapsed_us{0};
};

struct MatMulValidationRuntimeStats {
    uint64_t phase2_checks{0};
    uint64_t freivalds_checks{0};
    uint64_t transcript_checks{0};
    uint64_t successful_checks{0};
    uint64_t failed_checks{0};
    uint64_t total_phase2_elapsed_us{0};
    uint64_t total_freivalds_elapsed_us{0};
    uint64_t total_transcript_elapsed_us{0};
    uint64_t last_phase2_elapsed_us{0};
    uint64_t last_freivalds_elapsed_us{0};
    uint64_t last_transcript_elapsed_us{0};
    uint64_t max_phase2_elapsed_us{0};
    uint64_t max_freivalds_elapsed_us{0};
    uint64_t max_transcript_elapsed_us{0};
};

struct MatMulAsertHalfLifeInfo {
    int64_t current_half_life_s{0};
    int32_t current_anchor_height{-1};
    bool upgrade_configured{false};
    bool upgrade_active{false};
    int32_t upgrade_height{-1};
    int64_t upgrade_half_life_s{0};
};

struct MatMulPreHashEpsilonBitsInfo {
    uint32_t current_bits{0};
    uint32_t next_block_bits{0};
    bool upgrade_configured{false};
    bool upgrade_active{false};
    int32_t upgrade_height{-1};
    uint32_t upgrade_bits{0};
};

inline constexpr int MATMUL_PHASE1_FAIL_MISBEHAVIOR{20};
inline constexpr int MATMUL_PHASE2_BAN_MISBEHAVIOR{100};

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);
bool EnforceTimewarpProtectionAtHeight(const Consensus::Params& params, int32_t block_height);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);
bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params&);
int64_t ExpectedDgwTimespan(int32_t height, const Consensus::Params& params);
bool CheckMatMulProofOfWork_Phase1(const CBlockHeader& block, const Consensus::Params& params);
bool CheckMatMulProofOfWork_Phase2(const CBlockHeader& block, const Consensus::Params& params, int32_t block_height = -1);
bool CheckMatMulProofOfWork_Phase2WithPayload(const CBlock& block, const Consensus::Params& params, int32_t block_height = -1);
/** Freivalds' O(n^2) probabilistic verification of MatMul PoW using the
 *  product matrix C' carried in the block payload. Requires
 *  fMatMulFreivaldsEnabled and a non-empty matrix_c_data. */
bool CheckMatMulProofOfWork_Freivalds(const CBlock& block, const Consensus::Params& params, int32_t block_height = -1);
/** Product-committed O(n^2) verification: computes digest from (sigma, A', B', C')
 *  and verifies A'*B'==C' via Freivalds. No transcript recomputation needed. */
bool CheckMatMulProofOfWork_ProductCommitted(const CBlock& block, const Consensus::Params& params, int32_t block_height = -1);
bool ShouldIncludeMatMulFreivaldsPayloadForMining(int32_t block_height, const Consensus::Params& params);
bool HasMatMulV2Payload(const CBlock& block);
bool HasMatMulFreivaldsPayload(const CBlock& block);
bool IsMatMulV2PayloadSizeValid(const CBlock& block, const Consensus::Params& params);
bool IsMatMulFreivaldsPayloadSizeValid(const CBlock& block, const Consensus::Params& params);
/** After mining solves a block, compute the product matrix C' = A'B' and
 *  populate block.matrix_c_data for O(n^2) Freivalds verification. */
void PopulateFreivaldsPayload(CBlock& block, const Consensus::Params& params);
std::chrono::milliseconds EffectiveTargetSpacingForHeight(int32_t height, const Consensus::Params& params);
int32_t MatMulPhase2ValidationStartHeight(int32_t best_known_height, const Consensus::Params& params);
bool ShouldRunMatMulPhase2ForHeight(int32_t block_height, int32_t best_known_height, const Consensus::Params& params);
bool ShouldRunMatMulPhase2Validation(
    int32_t block_height,
    int32_t best_known_height,
    const Consensus::Params& params,
    bool phase2_enabled,
    bool is_ibd);
uint32_t CountMatMulPhase2Checks(
    int64_t first_height,
    size_t header_count,
    int32_t best_known_height,
    const Consensus::Params& params,
    bool phase2_enabled,
    bool is_ibd);
uint32_t EffectivePhase2BanThreshold(const Consensus::Params& params);
void MaybeResetMatMulPhase2Window(MatMulPeerVerificationBudget& budget, std::chrono::steady_clock::time_point now);
MatMulPhase2Punishment RegisterMatMulPhase2Failure(
    MatMulPeerVerificationBudget& budget,
    const Consensus::Params& params,
    std::chrono::steady_clock::time_point now,
    uint32_t* failures_out = nullptr);
uint32_t EffectiveMatMulPeerVerifyBudgetPerMin(const Consensus::Params& params, bool is_ibd);
bool ConsumeMatMulPeerVerifyBudget(
    MatMulPeerVerificationBudget& budget,
    const Consensus::Params& params,
    std::chrono::steady_clock::time_point now,
    bool is_ibd = false,
    int32_t reference_height = std::numeric_limits<int32_t>::max());
bool CanStartMatMulVerification(uint32_t pending_verifications, const Consensus::Params& params);
bool ConsumeGlobalMatMulPhase2Budget(uint32_t max_global_per_minute, uint32_t count, std::chrono::steady_clock::time_point now);
/** Deterministically derive MatMul matrix seeds from chain context.
 *
 * This is used to keep regtest/unit tests reproducible without requiring a
 * fixed RANDOM_CTX_SEED environment variable.
 */
uint256 DeterministicMatMulSeed(const uint256& prev_block_hash, uint32_t height, uint8_t which);
MatMulSolvePipelineStats ProbeMatMulSolvePipelineStats();
void ResetMatMulSolvePipelineStats();
MatMulDigestCompareStats ProbeMatMulDigestCompareStats();
void ResetMatMulDigestCompareStats();
MatMulSolveRuntimeStats ProbeMatMulSolveRuntimeStats();
void ResetMatMulSolveRuntimeStats();
MatMulValidationRuntimeStats ProbeMatMulValidationRuntimeStats();
void ResetMatMulValidationRuntimeStats();
void RegisterMatMulDigestCompareAttempt(const CBlockHeader& block,
                                        const uint256& backend_digest,
                                        const uint256& cpu_digest,
                                        const char* backend_label = "metal");
uint32_t GetMatMulPreHashEpsilonBitsForHeight(const Consensus::Params& params, int32_t block_height);
MatMulPreHashEpsilonBitsInfo GetMatMulPreHashEpsilonBitsInfo(int32_t current_tip_height, const Consensus::Params& params);
bool SolveMatMul(CBlockHeader& block, const Consensus::Params& params, uint64_t& max_tries,
                 int32_t block_height = -1,
                 const std::atomic<bool>* abort_flag = nullptr,
                 std::vector<uint32_t>* freivalds_payload_out = nullptr);
bool CheckKAWPOWProofOfWork(const CBlockHeader& block, uint32_t block_height, const Consensus::Params&);
bool SolveKAWPOW(CBlockHeader& block, uint32_t block_height, const Consensus::Params& params, uint64_t& max_tries);

/**
 * Return false if the proof-of-work requirement specified by new_nbits at a
 * given height is not possible, given the proof-of-work on the prior block as
 * specified by old_nbits.
 *
 * This function only checks that the new value is within a factor of 4 of the
 * old value for blocks at the difficulty adjustment interval, and otherwise
 * requires the values to be the same.
 *
 * Always returns true on networks where min difficulty blocks are allowed,
 * such as regtest/testnet.
 */
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits);
MatMulAsertHalfLifeInfo GetMatMulAsertHalfLifeInfo(const CBlockIndex* pindexLast, const Consensus::Params& params);

#endif // BITCOIN_POW_H
