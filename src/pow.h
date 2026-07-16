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
#include <optional>
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

struct MatMulGpuPreHashScanStats {
    uint64_t attempts{0};
    uint64_t successes{0};
    uint64_t failures{0};
    uint64_t metal_fallbacks_to_cpu{0};
    uint64_t cuda_fallbacks_to_cpu{0};
    std::string last_backend{};
    std::string last_error{};
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
uint256 DeterministicMatMulSeed(const uint256& prev_block_hash,
                                uint32_t height,
                                uint8_t which,
                                std::optional<uint64_t> nonce = std::nullopt);
uint256 DeterministicMatMulSeedV2(const CBlockHeader& block, uint32_t height, uint8_t which);
uint256 DeterministicMatMulSeedV3(const CBlockHeader& block, uint32_t height, int64_t parent_median_time_past, uint8_t which);
[[nodiscard]] bool SetDeterministicMatMulSeeds(
    CBlockHeader& block,
    const Consensus::Params& params,
    int32_t block_height,
    std::optional<int64_t> parent_median_time_past = std::nullopt);
bool CheckMatMulProofOfWork_Phase1(const CBlockHeader& block, const Consensus::Params& params);
/** Validate the immutable MatMul-ASERT schedule parameters (ratios, ordering,
 *  branch-collision freedom). Purely a function of @p params -- @p next_height is
 *  used only for log context. Called both at chain-parameter construction
 *  (AUDIT D1: an invalid immutable config aborts node startup, rather than
 *  silently weakening current difficulty at some future height) and defensively
 *  per-block inside MatMulAsert. */
bool ValidateMatMulAsertParams(const Consensus::Params& params, int32_t next_height);
/** AUDIT D3: reduce a one-time ASERT rescale ratio num/den to lowest terms; return
 *  false (and leave outputs unspecified) unless it is strictly positive AND both
 *  reduced terms fit in uint32. Prevents ScaleTargetByTimespan's independent
 *  per-term uint32 clamp from distorting a large-but-exact ratio (e.g. 2^40/2^39).*/
bool ReduceRescaleRatioToU32(int64_t num, int64_t den, uint32_t& out_num, uint32_t& out_den);
/** AUDIT D1: the fail-CLOSED difficulty result (hardest representable target) used
 *  when a runtime ASERT invariant is breached, so an invalid config can never
 *  weaken (fail open to powLimit) current difficulty. */
unsigned int MatMulAsertFailClosedBits();
/** Header-PoW spam gate (audit F1). Returns true iff the header carries the
 *  required cheap, UNFORGEABLE hash work: H(GetHash() || spam_nonce) <=
 *  DeriveTarget(nMatMulHeaderPoWBits). spam_nonce is the legacy header `nNonce`
 *  field, which is DECOUPLED from the matmul preimage (ComputeMatMulHeaderHash),
 *  so an honest miner grinds this cheap gate without recomputing the expensive
 *  matmul. SINGLE ACTIVATION: no gate height of its own -- callers enforce it
 *  where IsMatMulV4Active(height) && params.IsMatMulHeaderPoWEnabled() (i.e.
 *  nMatMulHeaderPoWBits != 0; default 0 = disabled). NOTE (activation-blocking):
 *  `nNonce` is not yet in the P2P header wire serialization, so this is a staged
 *  mechanism -- see doc/btx-matmul-v4.2-header-pow-gate.md. */
/** AUDIT H4: the PURE header-PoW throttle target derivation (no header, no hash),
 *  exposed for direct fixed-vector testing. Returns the target a header claiming
 *  difficulty @p nBits must hash at or under, or std::nullopt when the throttle
 *  does not apply / is misconfigured: @p discount_bits == UINT32_MAX (disabled),
 *  @p discount_bits > 255 (AUDIT H2, out of range), or @p nBits undecodable. The
 *  target is DeriveTarget(nBits) shifted easier by @p discount_bits, saturating at
 *  @p pow_limit, so forging cost stays proportional to the claimed work (C2). */
std::optional<arith_uint256> DeriveMatMulHeaderPoWGateTarget(
    unsigned int nBits, uint32_t discount_bits, const uint256& pow_limit);
bool CheckMatMulHeaderSpamGate(const CBlockHeader& block, const Consensus::Params& params);
bool CheckMatMulPreHashGate(const CBlockHeader& block, const Consensus::Params& params, int32_t block_height);
bool CheckMatMulProofOfWork_Phase2(const CBlockHeader& block, const Consensus::Params& params, int32_t block_height = -1);
bool CheckMatMulProofOfWork_Phase2WithPayload(const CBlock& block, const Consensus::Params& params, int32_t block_height = -1);
/** Freivalds' O(n^2) probabilistic verification of MatMul PoW using the
 *  product matrix C' carried in the block payload. Requires
 *  fMatMulFreivaldsEnabled and a non-empty matrix_c_data. */
bool CheckMatMulProofOfWork_Freivalds(const CBlock& block, const Consensus::Params& params, int32_t block_height = -1);
/** Product-committed O(n^2) verification: computes digest from (sigma, A', B', C')
 *  and verifies A'*B'==C' via Freivalds. No transcript recomputation needed. */
bool CheckMatMulProofOfWork_ProductCommitted(const CBlock& block, const Consensus::Params& params, int32_t block_height = -1);
/** MatMul v4 (doc/btx-matmul-v4-design-spec.md, §I.2): the single v4 expensive
 *  verification check, run exclusively at and above nMatMulV4Height (no v3
 *  fallback ladder). Extracts the trailing sketch payload from
 *  block.matrix_c_data (spec §H.2's "reuses the trailing-payload
 *  serialization", byte-packed as little-endian uint32 words), regenerates
 *  A,B from the header seeds, runs matmul_v4::VerifySketch's O(n^2)
 *  deterministic Freivalds cascade over q = 2^61-1, and checks the
 *  recomputed digest against the block target. Never recomputes the O(n^3)
 *  product. */
bool CheckMatMulProofOfWork_V4ProductCommitted(const CBlock& block, const Consensus::Params& params, int32_t block_height = -1);
/** True iff the block's v4 sketch payload reconstructs the header's committed
 *  matmul_digest. A false result means the payload (block body) is a MUTATION of
 *  the committed body -- the header hash stays valid and a correct payload
 *  exists, so validators must reject with BLOCK_MUTATED (non-permanent) rather
 *  than permanently invalidating the header hash. Runs no Freivalds/target
 *  check; see CheckMatMulProofOfWork_V4ProductCommitted for the full cascade. */
bool MatMulV4PayloadMatchesCommitment(const CBlock& block);
/** Coarse DoS-bound shape check for the v4 sketch payload (dimension match,
 *  non-empty, bounded word count). The authoritative shape/canonicality check
 *  runs inside matmul_v4::VerifySketch itself. */
bool IsMatMulV4PayloadSizeValid(const CBlock& block, const Consensus::Params& params);
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
/** True when consensus will run ANY expensive MatMul verification at this height: either the legacy
 *  phase2/Freivalds path or the post-activation product-committed digest path. Mirrors the disjunction
 *  in ContextualCheckBlock (should_run_phase2 || IsMatMulProductDigestActive). The P2P expensive-
 *  verification budget must be charged for all of these — counting only phase2 (CountMatMulPhase2Checks)
 *  lets post-product-digest blocks bypass the per-peer/global DoS budget. */
bool ShouldRunMatMulExpensiveVerification(
    int32_t block_height,
    int32_t best_known_height,
    const Consensus::Params& params,
    bool phase2_enabled,
    bool is_ibd);
uint32_t CountMatMulExpensiveVerifyChecks(
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
// Height-selected DoS verify budgets (spec §G.3/§H.4/§I.5): at and above
// nMatMulV4Height the v4 budget values apply; below (or with v4 disabled) the
// v3 values apply. reference_height defaults to -1 (== v3), preserving callers
// that do not supply a height.
uint32_t EffectiveMatMulPeerVerifyBudgetPerMin(const Consensus::Params& params, bool is_ibd, int32_t reference_height = -1);
uint32_t EffectiveMatMulGlobalVerifyBudgetPerMin(const Consensus::Params& params, int32_t reference_height = -1);
bool ConsumeMatMulPeerVerifyBudget(
    MatMulPeerVerificationBudget& budget,
    const Consensus::Params& params,
    std::chrono::steady_clock::time_point now,
    bool is_ibd = false,
    int32_t reference_height = std::numeric_limits<int32_t>::max());
bool CanStartMatMulVerification(uint32_t pending_verifications, const Consensus::Params& params);
bool ConsumeGlobalMatMulPhase2Budget(uint32_t max_global_per_minute, uint32_t count, std::chrono::steady_clock::time_point now);
MatMulSolvePipelineStats ProbeMatMulSolvePipelineStats();
void ResetMatMulSolvePipelineStats();
MatMulGpuPreHashScanStats ProbeMatMulGpuPreHashScanStats();
void ResetMatMulGpuPreHashScanStats();
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
                 std::vector<uint32_t>* freivalds_payload_out = nullptr,
                 //! Optional pool/share mining target. When non-null, the solver returns as soon as it
                 //! finds a nonce whose MatMul digest is <= *share_target_override (typically an EASIER,
                 //! numerically larger target than the block target derived from nBits). This relaxes ONLY
                 //! the digest early-exit comparison: the consensus pre-hash gate (CheckMatMulPreHashGate)
                 //! and the miner-side pre-hash batch window always use the block target from nBits, so a
                 //! returned candidate that also meets the block target is a fully consensus-valid block,
                 //! and every share is a genuine block candidate. Pass nullptr (default) for solo/consensus
                 //! mining — behaviour is then identical to mining against the block target. A zero target
                 //! is rejected (returns false).
                 const uint256* share_target_override = nullptr,
                 std::optional<int64_t> parent_median_time_past = std::nullopt);
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
