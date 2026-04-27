// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <consensus/amount.h>
#include <uint256.h>

#include <chrono>
#include <limits>
#include <map>
#include <vector>

namespace Consensus {

// Budget: 1042 SMILE txns × (2×100 + 2×15) = 239,660 units.
// Set to 240,000 so block size (24MB) is the binding constraint, not verify budget.
// CPU verification: 1042 txns × 3.5ms = 3.6s (4% of 90s block time, single core).
static constexpr uint64_t DEFAULT_MAX_BLOCK_SHIELDED_VERIFY_COST{240'000};
static constexpr uint64_t DEFAULT_MAX_BLOCK_SHIELDED_SCAN_UNITS{24'576};
static constexpr uint64_t DEFAULT_MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS{24'576};
static constexpr uint64_t DEFAULT_MAX_BLOCK_SHIELDED_ACCOUNT_REGISTRY_APPENDS{4'096};
static constexpr uint64_t DEFAULT_MAX_SHIELDED_ACCOUNT_REGISTRY_ENTRIES{65'536};

/**
 * A buried deployment is one where the height of the activation has been hardcoded into
 * the client implementation long after the consensus change has activated. See BIP 90.
 */
enum BuriedDeployment : int16_t {
    // buried deployments get negative values to avoid overlap with DeploymentPos
    DEPLOYMENT_HEIGHTINCB = std::numeric_limits<int16_t>::min(),
    DEPLOYMENT_CLTV,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
    DEPLOYMENT_SEGWIT,
};
constexpr bool ValidDeployment(BuriedDeployment dep) { return dep <= DEPLOYMENT_SEGWIT; }

enum DeploymentPos : uint16_t {
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_TAPROOT, // Deployment of Schnorr/Taproot (BIPs 340-342)
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in deploymentinfo.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};
constexpr bool ValidDeployment(DeploymentPos dep) { return dep < MAX_VERSION_BITS_DEPLOYMENTS; }

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit{28};
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime{NEVER_ACTIVE};
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout{NEVER_ACTIVE};
    /** If lock in occurs, delay activation until at least this block
     *  height.  Note that activation will only occur on a retarget
     *  boundary.
     */
    int min_activation_height{0};

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;

    /** Special value for nStartTime indicating that the deployment is never active.
     *  This is useful for integrating the code changes for a new feature
     *  prior to deploying it on some or all networks. */
    static constexpr int64_t NEVER_ACTIVE = -2;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /**
     * Hashes of blocks that
     * - are known to be consensus valid, and
     * - buried in the chain, and
     * - fail if the default script verify flags are applied.
     */
    std::map<uint256, uint32_t> script_flag_exceptions;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
     * Note that segwit v0 script rules are enforced on all blocks except the
     * BIP 16 exception blocks. */
    int SegwitHeight;
    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV and segwit activations. */
    int MinBIP9WarningHeight;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    /**
      * Enforce BIP94 timewarp attack mitigation. On testnet4 this also enforces
      * the block storm mitigation.
      */
    bool enforce_BIP94;
    bool fPowNoRetargeting;
    bool fKAWPOW{false};
    bool fSkipKAWPOWValidation{false};
    int nKAWPOWHeight{std::numeric_limits<int>::max()};
    bool fReducedDataLimits{false};
    bool fEnforceP2MROnlyOutputs{false};
    unsigned int nMaxOpReturnBytes{83};
    unsigned int nMaxTxoutScriptPubKeyBytes{34};

    // MatMul PoW parameters.
    bool fMatMulPOW{false};
    bool fSkipMatMulValidation{false};
    uint32_t nMatMulDimension{512};
    uint32_t nMatMulTranscriptBlockSize{16};
    uint32_t nMatMulNoiseRank{8};
    uint32_t nMatMulMinDimension{64};
    uint32_t nMatMulMaxDimension{2048};
    uint32_t nMatMulFieldModulus{0x7FFFFFFFU};
    uint32_t nMatMulValidationWindow{1000};
    uint32_t nMatMulMaxPendingVerifications{16};
    uint32_t nMatMulPeerVerifyBudgetPerMin{32};
    uint32_t nMatMulPhase2FailBanThreshold{1};
    bool fMatMulStrictPunishment{false};
    uint32_t nMatMulSnapshotInterval{10'000};
    uint32_t nMatMulProofPruneDepth{10'000};
    /** Pre-hash epsilon bits: sigma must satisfy target << N before a nonce reaches
     *  the expensive MatMul path. This makes the sigma gate 2^N easier than the
     *  final digest target before 256-bit saturation, but the absolute pass rate
     *  still depends on the active nBits target. */
    uint32_t nMatMulPreHashEpsilonBits{10};
    /** Optional future pre-hash epsilon upgrade. At this height and above, the
     *  sigma gate uses nMatMulPreHashEpsilonBitsUpgrade instead of the base
     *  nMatMulPreHashEpsilonBits value. */
    int32_t nMatMulPreHashEpsilonBitsUpgradeHeight{std::numeric_limits<int32_t>::max()};
    uint32_t nMatMulPreHashEpsilonBitsUpgrade{10};
    /** Maximum Phase 2 verifications per minute across ALL peers combined.
     *  With n=512 each costs ~5ms, so 512/min ≈ 2.56s CPU/min. */
    uint32_t nMatMulGlobalVerifyBudgetPerMin{512};

    // Freivalds' algorithm verification parameters.
    // Verifiers use O(n^2) probabilistic verification via Freivalds' algorithm
    // as a fast product check. Full transcript recomputation can still be
    // required by a later upgrade to bind matmul_digest to the claimed work.
    bool fMatMulFreivaldsEnabled{true};
    /** Number of Freivalds' rounds per verification. Each round has false-positive
     *  probability 1/(2^31-1). With k=2 rounds, error < 2^-62. */
    uint32_t nMatMulFreivaldsRounds{2};
    /** Require blocks to carry the product matrix C' in their payload.
     *  When true, miners must include C' in the block payload.
     *  matmul_digest remains transcript-bound unless a separate digest
     *  commitment upgrade explicitly says otherwise. */
    bool fMatMulRequireProductPayload{true};
    /** Height at which Freivalds-verified blocks must also pass full
     *  transcript recomputation to bind matmul_digest to the claimed work. */
    int32_t nMatMulFreivaldsBindingHeight{std::numeric_limits<int32_t>::max()};
    /** Height at which the product-committed digest replaces the transcript
     *  digest.  Below this height the legacy transcript check remains
     *  authoritative.  Requires fMatMulFreivaldsEnabled and a non-empty
     *  matrix_c_data payload. */
    int32_t nMatMulProductDigestHeight{std::numeric_limits<int32_t>::max()};
    uint32_t nMaxReorgDepth{std::numeric_limits<uint32_t>::max()};
    int32_t nReorgProtectionStartHeight{std::numeric_limits<int32_t>::max()};

    // Monetary policy.
    CAmount nMaxMoney{21'000'000 * COIN};
    CAmount nInitialSubsidy{20 * COIN};

    // Target spacing schedule.
    int64_t nPowTargetSpacingNormal{90};
    int64_t nPowTargetSpacingFastMs{250};
    uint32_t nFastMineDifficultyScale{1};
    int32_t nFastMineHeight{61'000};
    // LEGACY DGW height gates -- NOT used for MatMul mining. DGW was
    // deliberately replaced by ASERT for all MatMul difficulty adjustment.
    // These fields are retained only for KAWPOW-era compatibility and must
    // remain at max() for all MatMul networks. Do not re-enable DGW for
    // MatMul without explicit project approval.
    int32_t nDgwAsymmetricClampHeight{std::numeric_limits<int32_t>::max()};
    int32_t nDgwEasingBoostHeight{std::numeric_limits<int32_t>::max()};
    int32_t nDgwWindowAlignmentHeight{std::numeric_limits<int32_t>::max()};
    int32_t nDgwSlewGuardHeight{std::numeric_limits<int32_t>::max()};
    // Height at which ASERT activates for MatMul mining. This MUST equal
    // nFastMineHeight so that ASERT governs difficulty from the first
    // post-bootstrap block onward. Do not change without project approval.
    int32_t nMatMulAsertHeight{std::numeric_limits<int32_t>::max()};
    // ASERT half-life in seconds (consensus-critical when ASERT is active).
    int64_t nMatMulAsertHalfLife{14'400};
    // One-time ASERT activation bootstrap multiplier applied to parent target at
    // nMatMulAsertHeight. Values >1 ease difficulty immediately at activation.
    uint32_t nMatMulAsertBootstrapFactor{1};
    // Optional one-time ASERT retune height. At this height, target can be
    // hardened by nMatMulAsertRetuneHardeningFactor to quickly recenter
    // cadence after bootstrap/ops-era drift.
    int32_t nMatMulAsertRetuneHeight{std::numeric_limits<int32_t>::max()};
    // Retune hardening factor applied at nMatMulAsertRetuneHeight:
    // next_target = parent_target / factor (factor>=1).
    uint32_t nMatMulAsertRetuneHardeningFactor{1};
    // Optional one-time ASERT recenter retune. At this height the next target
    // is scaled by (num/den) from the parent target, then ASERT re-anchors on
    // that block to preserve the recentered baseline.
    int32_t nMatMulAsertRetune2Height{std::numeric_limits<int32_t>::max()};
    uint32_t nMatMulAsertRetune2TargetNum{1};
    uint32_t nMatMulAsertRetune2TargetDen{1};
    // Optional future ASERT half-life upgrade. At this height the target is
    // inherited from the parent unchanged, then ASERT re-anchors on that block
    // and uses nMatMulAsertHalfLifeUpgrade for subsequent retargeting.
    int32_t nMatMulAsertHalfLifeUpgradeHeight{std::numeric_limits<int32_t>::max()};
    int64_t nMatMulAsertHalfLifeUpgrade{14'400};

    // Block capacity.
    uint32_t nMaxBlockWeight{24'000'000};
    uint32_t nMaxBlockSerializedSize{24'000'000};
    uint32_t nMaxBlockSigOpsCost{480'000};
    uint32_t nDefaultBlockMaxWeight{24'000'000};
    uint32_t nDefaultMempoolMaxSizeMB{2048};

    // Shielded pool consensus limits.
    uint32_t nMaxShieldedTxSize{6'500'000};
    uint32_t nMaxShieldedRingSize{32};
    uint32_t nShieldedMerkleTreeDepth{32};
    int32_t nShieldedPoolActivationHeight{0};
    int32_t nShieldedTxBindingActivationHeight{std::numeric_limits<int32_t>::max()};
    int32_t nShieldedBridgeTagActivationHeight{std::numeric_limits<int32_t>::max()};
    int32_t nShieldedSmileRiceCodecDisableHeight{std::numeric_limits<int32_t>::max()};
    int32_t nShieldedMatRiCTDisableHeight{std::numeric_limits<int32_t>::max()};
    int32_t nShieldedSpendPathRecoveryActivationHeight{std::numeric_limits<int32_t>::max()};
    int32_t nShieldedPQ128UpgradeHeight{std::numeric_limits<int32_t>::max()};
    uint32_t nShieldedSettlementAnchorMaturity{6};
    int32_t nMLDSADisableHeight{std::numeric_limits<int32_t>::max()};
    /** Maximum shielded verification cost units per block (consensus rule).
     *  SMILE v2: Each spend costs ~100 units; each output ~15 units.
     *  Budget: 1042 × 230 = 240,000. Size (24MB) is the binding constraint.
     *  CPU: 1042 × 3.5ms = 3.6s (4% of 90s block, single core). */
    uint64_t nMaxBlockShieldedVerifyCost{DEFAULT_MAX_BLOCK_SHIELDED_VERIFY_COST};
    /** Maximum wallet-facing shielded discovery units per block.
     *  Calibrated to allow one large batched egress while keeping scan pressure bounded. */
    uint64_t nMaxBlockShieldedScanUnits{DEFAULT_MAX_BLOCK_SHIELDED_SCAN_UNITS};
    /** Maximum shielded state-mutation units per block (nullifiers + commitments). */
    uint64_t nMaxBlockShieldedTreeUpdateUnits{DEFAULT_MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS};
    /** Maximum shielded account-registry appends per block after the MatRiCT disable fork. */
    uint64_t nMaxBlockShieldedAccountRegistryAppends{
        DEFAULT_MAX_BLOCK_SHIELDED_ACCOUNT_REGISTRY_APPENDS};
    /** Maximum total shielded account-registry entries after the MatRiCT disable fork. */
    uint64_t nMaxShieldedAccountRegistryEntries{
        DEFAULT_MAX_SHIELDED_ACCOUNT_REGISTRY_ENTRIES};

    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    std::chrono::seconds PowTargetSpacing() const
    {
        return std::chrono::seconds{nPowTargetSpacing};
    }
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    double GetTargetSpacing(int32_t height) const
    {
        if (height < nFastMineHeight) {
            return static_cast<double>(nPowTargetSpacingFastMs) / 1000.0;
        }
        return static_cast<double>(nPowTargetSpacingNormal);
    }
    bool IsMatMulFreivaldsBindingActive(int32_t height) const
    {
        return fMatMulFreivaldsEnabled &&
            height >= 0 &&
            nMatMulFreivaldsBindingHeight != std::numeric_limits<int32_t>::max() &&
            height >= nMatMulFreivaldsBindingHeight;
    }
    bool IsMatMulProductDigestActive(int32_t height) const
    {
        return fMatMulFreivaldsEnabled &&
            height >= 0 &&
            nMatMulProductDigestHeight != std::numeric_limits<int32_t>::max() &&
            height >= nMatMulProductDigestHeight;
    }
    bool IsMatMulProductPayloadRequired(int32_t height) const
    {
        return fMatMulFreivaldsEnabled &&
            (fMatMulRequireProductPayload || IsMatMulProductDigestActive(height));
    }
    bool IsMatMulPreHashEpsilonBitsUpgradeActive(int32_t height) const
    {
        return height >= 0 &&
            nMatMulPreHashEpsilonBitsUpgradeHeight != std::numeric_limits<int32_t>::max() &&
            height >= nMatMulPreHashEpsilonBitsUpgradeHeight;
    }
    bool IsShieldedTxBindingActive(int32_t height) const
    {
        return height >= 0 &&
            nShieldedTxBindingActivationHeight != std::numeric_limits<int32_t>::max() &&
            height >= nShieldedTxBindingActivationHeight;
    }
    bool IsShieldedBridgeTagUpgradeActive(int32_t height) const
    {
        return height >= 0 &&
            nShieldedBridgeTagActivationHeight != std::numeric_limits<int32_t>::max() &&
            height >= nShieldedBridgeTagActivationHeight;
    }
    bool IsShieldedSmileRiceCodecDisabled(int32_t height) const
    {
        return height >= 0 &&
            nShieldedSmileRiceCodecDisableHeight != std::numeric_limits<int32_t>::max() &&
            height >= nShieldedSmileRiceCodecDisableHeight;
    }
    bool IsShieldedMatRiCTDisabled(int32_t height) const
    {
        return height >= 0 &&
            nShieldedMatRiCTDisableHeight != std::numeric_limits<int32_t>::max() &&
            height >= nShieldedMatRiCTDisableHeight;
    }
    bool IsShieldedSpendPathRecoveryActive(int32_t height) const
    {
        return height >= 0 &&
            nShieldedSpendPathRecoveryActivationHeight != std::numeric_limits<int32_t>::max() &&
            height >= nShieldedSpendPathRecoveryActivationHeight;
    }
    bool IsShieldedPQ128UpgradeActive(int32_t height) const
    {
        return height >= 0 &&
            nShieldedPQ128UpgradeHeight != std::numeric_limits<int32_t>::max() &&
            height >= nShieldedPQ128UpgradeHeight;
    }
    uint32_t GetShieldedSettlementAnchorMaturityDepth(int32_t height) const
    {
        return IsShieldedMatRiCTDisabled(height) ? nShieldedSettlementAnchorMaturity : 0;
    }
    uint32_t GetMatMulPreHashEpsilonBitsForHeight(int32_t height) const
    {
        return IsMatMulPreHashEpsilonBitsUpgradeActive(height)
            ? nMatMulPreHashEpsilonBitsUpgrade
            : nMatMulPreHashEpsilonBits;
    }
    /** The best chain should have at least this much work */
    uint256 nMinimumChainWork;
    /** By default assume that the signatures in ancestors of this block are valid */
    uint256 defaultAssumeValid;

    /**
     * If true, witness commitments contain a payload equal to a Bitcoin Script solution
     * to the signet challenge. See BIP325.
     */
    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;

    int DeploymentHeight(BuriedDeployment dep) const
    {
        switch (dep) {
        case DEPLOYMENT_HEIGHTINCB:
            return BIP34Height;
        case DEPLOYMENT_CLTV:
            return BIP65Height;
        case DEPLOYMENT_DERSIG:
            return BIP66Height;
        case DEPLOYMENT_CSV:
            return CSVHeight;
        case DEPLOYMENT_SEGWIT:
            return SegwitHeight;
        } // no default case, so the compiler can warn about missing cases
        return std::numeric_limits<int>::max();
    }
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
