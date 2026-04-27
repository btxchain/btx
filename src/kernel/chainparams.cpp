// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iterator>


using namespace util::hex_literals;

// Workaround MSVC bug triggering C7595 when calling consteval constructors in
// initializer lists.
// A fix may be on the way:
// https://developercommunity.visualstudio.com/t/consteval-conversion-function-fails/1579014
#if defined(_MSC_VER)
auto consteval_ctor(auto&& input) { return input; }
#else
#define consteval_ctor(input) (input)
#endif

static CBlock CreateGenesisBlock(const char* pszTimestamp,
                                 const CScript& genesisOutputScript,
                                 uint32_t nTime,
                                 uint32_t nNonce,
                                 uint64_t nNonce64,
                                 uint32_t nBits,
                                 int32_t nVersion,
                                 const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nNonce64 = nNonce64;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateBTXGenesisBlock(uint32_t nTime,
                                    uint32_t nNonce,
                                    uint64_t nNonce64,
                                    uint32_t nBits,
                                    int32_t nVersion,
                                    const CAmount& genesisReward,
                                    uint16_t matmul_dim,
                                    const uint256& matmul_digest)
{
    const char* pszTimestamp = "BTX 19/Mar/2026 SMILE v2 Post-Quantum Shielded Transactions";
    // Unspendable P2MR commitment:
    // merkle_root = SHA256("BTX P2MR Genesis - Quantum Safe Since Block 0")
    const auto genesis_script_bytes{ParseHex("5220afa45d6891836c7314dded4dbd0e7aacde3de0d7fa9a12aeac06e2296c794226")};
    const CScript genesisOutputScript{genesis_script_bytes.begin(), genesis_script_bytes.end()};
    CBlock genesis = CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nNonce64, nBits, nVersion, genesisReward);
    genesis.matmul_dim = matmul_dim;
    // Deterministic genesis seeds derived for prevhash=0 and height=0.
    genesis.seed_a = uint256{"a8a82ec830e8346550cad66c4cf43985dddd6a056d4bed2a5dcace445fa924ab"};
    genesis.seed_b = uint256{"f9aaa742cdbfb26be3d22d743b548740ff0a9e00f9cc977c1fb03df85fdf978d"};
    genesis.matmul_digest = matmul_digest;
    return genesis;
}

static CBlock CreateShieldedV2DevGenesisBlock(uint32_t nTime,
                                              uint32_t nNonce,
                                              uint64_t nNonce64,
                                              uint32_t nBits,
                                              int32_t nVersion,
                                              const CAmount& genesisReward,
                                              uint16_t matmul_dim,
                                              const uint256& matmul_digest)
{
    const char* pszTimestamp = "BTX 14/Mar/2026 shieldedv2dev genesis";
    const auto genesis_script_bytes{ParseHex("5220afa45d6891836c7314dded4dbd0e7aacde3de0d7fa9a12aeac06e2296c794226")};
    const CScript genesisOutputScript{genesis_script_bytes.begin(), genesis_script_bytes.end()};
    CBlock genesis = CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nNonce64, nBits, nVersion, genesisReward);
    genesis.matmul_dim = matmul_dim;
    genesis.seed_a = uint256{"a8a82ec830e8346550cad66c4cf43985dddd6a056d4bed2a5dcace445fa924ab"};
    genesis.seed_b = uint256{"f9aaa742cdbfb26be3d22d743b548740ff0a9e00f9cc977c1fb03df85fdf978d"};
    genesis.matmul_digest = matmul_digest;
    return genesis;
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 525000;
        consensus.script_flag_exceptions.clear(); // New chain has no exceptions
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        // MatMul powLimit calibrated for fast-phase SLA targeting ~0.25s blocks
        // on current Apple Silicon throughput (n=512), while retaining compact
        // headroom above genesis nBits so bootstrap scaling is not clamped out.
        // 2026-03-08 retune: eased from 0x205aa936 to 0x2066c154 based on live
        // throughput telemetry (~3.53 bps, ~0.283s over a 30s run) to target
        // the configured fast-phase SLA (~0.25s mean) on this host profile.
        consensus.powLimit = uint256{"66c1540000000000000000000000000000000000000000000000000000000000"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 90;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = false;
        consensus.fKAWPOW = false;
        consensus.fSkipKAWPOWValidation = false;
        consensus.fReducedDataLimits = true;
        consensus.fEnforceP2MROnlyOutputs = true;
        consensus.nKAWPOWHeight = std::numeric_limits<int>::max();
        consensus.fMatMulPOW = true;
        consensus.nMatMulDimension = 512;
        consensus.nMatMulTranscriptBlockSize = 16;
        consensus.nMatMulNoiseRank = 8;
        consensus.nMatMulValidationWindow = 1000;
        consensus.nMatMulPhase2FailBanThreshold = 1;
        consensus.fMatMulStrictPunishment = false;
        consensus.nMatMulSnapshotInterval = 10'000;
        consensus.nMatMulProofPruneDepth = 10'000;
        // Freivalds' O(n^2) probabilistic verification (k=2 rounds, error < 2^-62).
        consensus.fMatMulFreivaldsEnabled = true;
        consensus.nMatMulFreivaldsRounds = 2;
        // Mainnet peers currently mine and relay payload-less MatMul blocks.
        // Keep Freivalds payloads optional on mainnet until an explicit upgrade
        // activates the stricter serialization rule across the full network.
        consensus.fMatMulRequireProductPayload = false;
        consensus.nMatMulFreivaldsBindingHeight = 61'000;
        consensus.nMatMulProductDigestHeight = 61'000;
        consensus.nMaxReorgDepth = 144;
        consensus.nReorgProtectionStartHeight = 61'000;
        consensus.nPowTargetSpacingFastMs = 250;
        // Fast-phase bootstrap scale for heights [0, nFastMineHeight). Effective
        // ease is bounded by powLimit; keep this >1 so fast bootstrap can
        // converge to the configured floor.
        consensus.nFastMineDifficultyScale = 6;
        consensus.nPowTargetSpacingNormal = 90;
        // Mainnet launched with the MatMul bootstrap window ending at 50,000.
        // Keep that historical PoW schedule frozen; later hardening work at
        // 61,000 must not rewrite already-mined header difficulty history.
        consensus.nFastMineHeight = 50'000;
        // DGW is NOT used for MatMul mining. These heights are disabled.
        // ASERT governs all difficulty adjustment from nFastMineHeight onward.
        // Do not re-enable DGW -- see pow.cpp design invariant comments.
        consensus.nDgwAsymmetricClampHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwEasingBoostHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwWindowAlignmentHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwSlewGuardHeight = std::numeric_limits<int32_t>::max();
        // ASERT activates at nFastMineHeight. This MUST equal nFastMineHeight.
        consensus.nMatMulAsertHeight = 50'000;
        consensus.nMatMulAsertHalfLife = 3'600;
        consensus.nMatMulAsertBootstrapFactor = 180;
        // No retune or half-life upgrade needed — fresh chain starts with
        // the target 3,600s half-life directly.
        consensus.nMatMulAsertRetuneHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertRetuneHardeningFactor = 1;
        consensus.nMatMulAsertRetune2Height = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertRetune2TargetNum = 1;
        consensus.nMatMulAsertRetune2TargetDen = 1;
        consensus.nMatMulAsertHalfLifeUpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertHalfLifeUpgrade = 3'600;
        // Hardened pre-hash epsilon (18 bits) has been active on mainnet since
        // the historical ASERT transition at 50,000.
        consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = 50'000;
        consensus.nMatMulPreHashEpsilonBitsUpgrade = 18;
        consensus.nMaxBlockWeight = 24'000'000;
        consensus.nMaxBlockSerializedSize = 24'000'000;
        consensus.nMaxBlockSigOpsCost = 480'000;
        consensus.nDefaultBlockMaxWeight = 24'000'000;
        consensus.nDefaultMempoolMaxSizeMB = 2048;
        consensus.nMaxShieldedTxSize = 6'500'000;
        consensus.nMaxShieldedRingSize = 32;
        consensus.nShieldedMerkleTreeDepth = 32;
        consensus.nShieldedPoolActivationHeight = 0;
        consensus.nShieldedTxBindingActivationHeight = 61'000;
        consensus.nShieldedBridgeTagActivationHeight = 61'000;
        consensus.nShieldedSmileRiceCodecDisableHeight = 61'000;
        consensus.nShieldedMatRiCTDisableHeight = 61'000;
        consensus.nShieldedPQ128UpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nShieldedSettlementAnchorMaturity = 6;
        consensus.nMLDSADisableHeight = std::numeric_limits<int32_t>::max();
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        // Mainnet anchor refreshed on 2026-04-14 at height 71'433 from a
        // synced canonical node so stale history below the current public
        // release floor is rejected quickly.
        consensus.nMinimumChainWork = uint256{"0000000000000000000000000000000000000000000000000000000278daaa26"};
        // Assume signatures valid up to the same anchored block to speed sync.
        consensus.defaultAssumeValid = uint256{"d58f6755e52467ed624dfcd0be4e8ee0731b8e7525e8dc4cf9482879d0dfe3f8"};

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xb7;
        pchMessageStart[1] = 0x54;
        pchMessageStart[2] = 0x58;
        pchMessageStart[3] = 0x01;
        nDefaultPort = 19335;
        nPruneAfterHeight = 100000;
        // Measured from the 2026-04-14 mainnet canonical datadir at height
        // 71'435: ~14.5 GiB blocks plus ~210 MiB chain/shielded state, rounded
        // up so users see a conservative disk estimate before sync begins.
        m_assumed_blockchain_size = 16;
        m_assumed_chain_state_size = 1;

        genesis = CreateBTXGenesisBlock(
            1773878400,  // Mar 19, 2026 00:00:00 UTC — SMILE v2 chain restart
            0,
            1,
            0x20147ae1,
            1,
            consensus.nInitialSubsidy,
            static_cast<uint16_t>(consensus.nMatMulDimension),
            uint256{"07226e4fdc368a067ef904b9fdddf9763e2782fda4e695788240077805643edd"});
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"75a998a39d2d6e25a9ca7de2cc659309c4105839c06cd435ba2b1aabf0fa4601"});
        assert(genesis.hashMerkleRoot == uint256{"94ae75cb0cd5f08b9447306ae914635d1c36d1a43d330daf596957e91cee002a"});

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,25);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,50);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,153);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "btx";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        // Primary live bootstrap DNS seed for mainnet peer discovery.
        vSeeds.clear();
        vSeeds.emplace_back("node.btx.tools.");

        // Fixed seeds mirror the public BTX infrastructure endpoints so nodes
        // can still bootstrap if DNS seed lookups are unavailable.
        vFixedSeeds = std::vector<uint8_t>{std::begin(chainparams_seed_main), std::end(chainparams_seed_main)};

        checkpointData = {
            {
                {0, uint256{"75a998a39d2d6e25a9ca7de2cc659309c4105839c06cd435ba2b1aabf0fa4601"}},
                {71433, uint256{"d58f6755e52467ed624dfcd0be4e8ee0731b8e7525e8dc4cf9482879d0dfe3f8"}},
            }
        };
        m_assumeutxo_data = {
            {
                // main assumeutxo snapshot at height 55'000
                .height = 55'000,
                .hash_serialized = AssumeutxoHash{uint256{"3fdff3b95b68ae2d40ef949e41d9e39fe68591f7fcc4cbfbc46c04f58030dda5"}},
                .m_chain_tx_count = 56'457,
                .blockhash = consteval_ctor(uint256{"db5e6530e55606be66aa78fe3f711e9dc4406ee4b26dde2ed819103c37d97d63"}),
            },
            {
                // main assumeutxo snapshot at height 60'760
                .height = 60'760,
                .hash_serialized = AssumeutxoHash{uint256{"e05de35057bbb3b8fa3834c9a2b557b8d54328b2100c06396a0741ab06c98e2a"}},
                .m_chain_tx_count = 66'205,
                .blockhash = consteval_ctor(uint256{"6528ebf50342363b63c17afd851a28307bc2c0fac596373ca9f59c30726d169c"}),
            },
            {
                // main assumeutxo snapshot at height 64'900
                .height = 64'900,
                .hash_serialized = AssumeutxoHash{uint256{"696f6ae3bcfed21881647be3871bf9574eb02fc10b7082677cc29a9b98529459"}},
                .m_chain_tx_count = 73'257,
                .blockhash = consteval_ctor(uint256{"6e5ebacea9f8168371f7c0255e7314aefa69516224675aa326166dbbf39b85f0"}),
            },
            {
                // main assumeutxo snapshot at height 71'260
                .height = 71'260,
                .hash_serialized = AssumeutxoHash{uint256{"46c2582d63ebb1aaf3865f0541e39287c59970ce890253c426b65911eb87e5fa"}},
                .m_chain_tx_count = 83'531,
                .blockhash = consteval_ctor(uint256{"993ddd9ccd08820ad4df089de6a444ffacc788b1b3b9015657d60e353fbad924"}),
            },
            {
                // main assumeutxo snapshot at height 71'435
                .height = 71'435,
                .hash_serialized = AssumeutxoHash{uint256{"9739e6a5891433d542617d28ae71131d976fe60d51a06af87db49f4a0c5a68d6"}},
                .m_chain_tx_count = 83'851,
                .blockhash = consteval_ctor(uint256{"46f81957ac0d40c57eef01810f4da3abb8e8a2c67ebb9fd88f36b1cc5a8e7be0"}),
            },
        };
        chainTxData = ChainTxData{
            .nTime = 1776151754,
            .tx_count = 83851,
            .dTxRate = 0.018807452734,
        };
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 525000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        // MatMul powLimit calibrated assuming T_attempt ~0.6ms per solve attempt (n=256)
        // targeting ~0.25s fast-phase blocks on single modern GPU reference hardware.
        consensus.powLimit = uint256{"027525460aa64c2f837b4a2339c0ebedfa43fe5c91d14e3bcd35a858793dd970"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 90;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = false;
        consensus.fKAWPOW = false;
        consensus.fSkipKAWPOWValidation = false;
        consensus.fReducedDataLimits = true;
        consensus.fEnforceP2MROnlyOutputs = true;
        consensus.nKAWPOWHeight = std::numeric_limits<int>::max();
        consensus.fMatMulPOW = true;
        consensus.nMatMulDimension = 256;
        consensus.nMatMulTranscriptBlockSize = 8;
        consensus.nMatMulNoiseRank = 4;
        consensus.nMatMulValidationWindow = 500;
        consensus.nMatMulPhase2FailBanThreshold = std::numeric_limits<uint32_t>::max();
        consensus.fMatMulStrictPunishment = false;
        consensus.nMatMulSnapshotInterval = 10'000;
        consensus.nMatMulProofPruneDepth = 10'000;
        consensus.fMatMulFreivaldsEnabled = true;
        consensus.nMatMulFreivaldsRounds = 2;
        consensus.fMatMulRequireProductPayload = true;
        consensus.nMatMulFreivaldsBindingHeight = 61'000;
        consensus.nMatMulProductDigestHeight = 61'000;
        consensus.nMaxReorgDepth = 144;
        consensus.nReorgProtectionStartHeight = 61'000;
        consensus.nPowTargetSpacingFastMs = 250;
        consensus.nFastMineDifficultyScale = 4;
        consensus.nPowTargetSpacingNormal = 90;
        consensus.nFastMineHeight = 61'000;
        // DGW is NOT used for MatMul mining -- ASERT only. See pow.cpp.
        consensus.nDgwAsymmetricClampHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwEasingBoostHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwWindowAlignmentHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwSlewGuardHeight = std::numeric_limits<int32_t>::max();
        // ASERT activates at nFastMineHeight. This MUST equal nFastMineHeight.
        consensus.nMatMulAsertHeight = 61'000;
        consensus.nMatMulAsertHalfLife = 3'600;
        consensus.nMatMulAsertBootstrapFactor = 180;
        // No retune or half-life upgrade needed — fresh chain starts with
        // the target 3,600s half-life directly.
        consensus.nMatMulAsertRetuneHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertRetuneHardeningFactor = 1;
        consensus.nMatMulAsertRetune2Height = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertRetune2TargetNum = 1;
        consensus.nMatMulAsertRetune2TargetDen = 1;
        consensus.nMatMulAsertHalfLifeUpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertHalfLifeUpgrade = 3'600;
        // Hardened pre-hash epsilon (18 bits) active from ASERT activation.
        consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = 61'000;
        consensus.nMatMulPreHashEpsilonBitsUpgrade = 18;
        consensus.nMaxBlockWeight = 24'000'000;
        consensus.nMaxBlockSerializedSize = 24'000'000;
        consensus.nMaxBlockSigOpsCost = 480'000;
        consensus.nDefaultBlockMaxWeight = 24'000'000;
        consensus.nDefaultMempoolMaxSizeMB = 2048;
        consensus.nMaxShieldedTxSize = 6'500'000;
        consensus.nMaxShieldedRingSize = 32;
        consensus.nShieldedMerkleTreeDepth = 32;
        consensus.nShieldedPoolActivationHeight = 0;
        consensus.nShieldedTxBindingActivationHeight = 61'000;
        consensus.nShieldedBridgeTagActivationHeight = 61'000;
        consensus.nShieldedSmileRiceCodecDisableHeight = 61'000;
        consensus.nShieldedMatRiCTDisableHeight = 61'000;
        consensus.nShieldedPQ128UpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nShieldedSettlementAnchorMaturity = 6;
        consensus.nMLDSADisableHeight = std::numeric_limits<int32_t>::max();
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // Bootstrap floor: disabled (zero) for young chain; update once the
        // chain has matured and a representative cumulative work is known.
        consensus.nMinimumChainWork = uint256{};
        // Assume signatures valid up to genesis (updated post-launch).
        consensus.defaultAssumeValid = uint256{"f2bc3fb2eca6aa6059c4d0178b56efe038d46aa440d406905ef752179aa0e1a4"};

        pchMessageStart[0] = 0xb7;
        pchMessageStart[1] = 0x54;
        pchMessageStart[2] = 0x58;
        pchMessageStart[3] = 0x02;
        nDefaultPort = 29335;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateBTXGenesisBlock(
            1773878400,  // Mar 19, 2026 — SMILE v2 chain restart
            0,
            238,
            0x20027525,
            1,
            consensus.nInitialSubsidy,
            static_cast<uint16_t>(consensus.nMatMulDimension),
            uint256{"00230371b05217711a10cf44983c2ffc3d82da06369fd0e640b6d20c033e38da"});
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"f2bc3fb2eca6aa6059c4d0178b56efe038d46aa440d406905ef752179aa0e1a4"});
        assert(genesis.hashMerkleRoot == uint256{"94ae75cb0cd5f08b9447306ae914635d1c36d1a43d330daf596957e91cee002a"});

        // Testnet DNS seeds mirror mainnet domains; fixed seeds provide fallback.
        vSeeds.clear();
        vSeeds.emplace_back("testnet.btxchain.org.");
        vSeeds.emplace_back("testnet.btx.dev.");
        vSeeds.emplace_back("testnet.btx.tools.");
        vFixedSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tbtx";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        m_assumeutxo_data = {};

        chainTxData = ChainTxData{
            .nTime = 0,
            .tx_count = 0,
            .dTxRate = 0,
        };
    }
};

/**
 * Testnet (v4): public test network which is reset from time to time.
 */
class CTestNet4Params : public CChainParams {
public:
    CTestNet4Params() {
        m_chain_type = ChainType::TESTNET4;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 525000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        // MatMul powLimit calibrated assuming T_attempt ~0.6ms per solve attempt (n=256)
        // targeting ~0.25s fast-phase blocks on single modern GPU reference hardware.
        consensus.powLimit = uint256{"027525460aa64c2f837b4a2339c0ebedfa43fe5c91d14e3bcd35a858793dd970"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 90;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = false;
        consensus.fKAWPOW = false;
        consensus.fSkipKAWPOWValidation = false;
        consensus.fReducedDataLimits = true;
        consensus.fEnforceP2MROnlyOutputs = true;
        consensus.nKAWPOWHeight = std::numeric_limits<int>::max();
        consensus.fMatMulPOW = true;
        consensus.nMatMulDimension = 256;
        consensus.nMatMulTranscriptBlockSize = 8;
        consensus.nMatMulNoiseRank = 4;
        consensus.nMatMulValidationWindow = 500;
        consensus.nMatMulPhase2FailBanThreshold = std::numeric_limits<uint32_t>::max();
        consensus.fMatMulStrictPunishment = false;
        consensus.nMatMulSnapshotInterval = 10'000;
        consensus.nMatMulProofPruneDepth = 10'000;
        consensus.fMatMulFreivaldsEnabled = true;
        consensus.nMatMulFreivaldsRounds = 2;
        consensus.fMatMulRequireProductPayload = true;
        consensus.nMatMulFreivaldsBindingHeight = 61'000;
        consensus.nMatMulProductDigestHeight = 61'000;
        consensus.nMaxReorgDepth = 144;
        consensus.nReorgProtectionStartHeight = 61'000;
        consensus.nPowTargetSpacingFastMs = 250;
        consensus.nFastMineDifficultyScale = 4;
        consensus.nPowTargetSpacingNormal = 90;
        consensus.nFastMineHeight = 61'000;
        // DGW is NOT used for MatMul mining -- ASERT only. See pow.cpp.
        consensus.nDgwAsymmetricClampHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwEasingBoostHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwWindowAlignmentHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwSlewGuardHeight = std::numeric_limits<int32_t>::max();
        // ASERT activates at nFastMineHeight. This MUST equal nFastMineHeight.
        consensus.nMatMulAsertHeight = 61'000;
        consensus.nMatMulAsertHalfLife = 3'600;
        consensus.nMatMulAsertBootstrapFactor = 180;
        // No retune or half-life upgrade needed — fresh chain starts with
        // the target 3,600s half-life directly.
        consensus.nMatMulAsertRetuneHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertRetuneHardeningFactor = 1;
        consensus.nMatMulAsertRetune2Height = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertRetune2TargetNum = 1;
        consensus.nMatMulAsertRetune2TargetDen = 1;
        consensus.nMatMulAsertHalfLifeUpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertHalfLifeUpgrade = 3'600;
        // Hardened pre-hash epsilon (18 bits) active from ASERT activation.
        consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = 61'000;
        consensus.nMatMulPreHashEpsilonBitsUpgrade = 18;
        consensus.nMaxBlockWeight = 24'000'000;
        consensus.nMaxBlockSerializedSize = 24'000'000;
        consensus.nMaxBlockSigOpsCost = 480'000;
        consensus.nDefaultBlockMaxWeight = 24'000'000;
        consensus.nDefaultMempoolMaxSizeMB = 2048;
        consensus.nMaxShieldedTxSize = 6'500'000;
        consensus.nMaxShieldedRingSize = 32;
        consensus.nShieldedMerkleTreeDepth = 32;
        consensus.nShieldedPoolActivationHeight = 0;
        consensus.nShieldedTxBindingActivationHeight = 61'000;
        consensus.nShieldedBridgeTagActivationHeight = 61'000;
        consensus.nShieldedSmileRiceCodecDisableHeight = 61'000;
        consensus.nShieldedMatRiCTDisableHeight = 61'000;
        consensus.nShieldedPQ128UpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nShieldedSettlementAnchorMaturity = 6;
        consensus.nMLDSADisableHeight = std::numeric_limits<int32_t>::max();
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // Bootstrap floor: disabled (zero) for young chain; update once the
        // chain has matured and a representative cumulative work is known.
        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{"f2bc3fb2eca6aa6059c4d0178b56efe038d46aa440d406905ef752179aa0e1a4"};

        pchMessageStart[0] = 0x1c;
        pchMessageStart[1] = 0x16;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x28;
        nDefaultPort = 48333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateBTXGenesisBlock(
            1773878400,  // Mar 19, 2026 — SMILE v2 chain restart
            0,
            238,
            0x20027525,
            1,
            consensus.nInitialSubsidy,
            static_cast<uint16_t>(consensus.nMatMulDimension),
            uint256{"00230371b05217711a10cf44983c2ffc3d82da06369fd0e640b6d20c033e38da"});
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"f2bc3fb2eca6aa6059c4d0178b56efe038d46aa440d406905ef752179aa0e1a4"});
        assert(genesis.hashMerkleRoot == uint256{"94ae75cb0cd5f08b9447306ae914635d1c36d1a43d330daf596957e91cee002a"});

        vSeeds.clear();
        vSeeds.emplace_back("testnet4.btxchain.org.");
        vSeeds.emplace_back("testnet4.btx.dev.");
        vSeeds.emplace_back("testnet4.btx.tools.");
        vFixedSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tbtx4";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        m_assumeutxo_data = {};

        chainTxData = ChainTxData{
            .nTime = 0,
            .tx_count = 0,
            .dTxRate = 0,
        };
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vFixedSeeds.clear();
        vSeeds.clear();

        if (!options.challenge) {
            // BTX does not operate a default signet.  When no custom
            // --signetchallenge is provided, use a trivial OP_TRUE
            // challenge so that tests and tooling can instantiate signet
            // params without crashing.  This creates an isolated signet
            // that cannot connect to any real network.
            //
            // Note: this constructor is also called from ChainTypeFromMagic()
            // during startup for message-magic detection, so we only log a
            // warning when -signet was explicitly selected (options.seeds is
            // populated or the caller is creating params for actual use).
            bin = {0x51};
        } else {
            bin = *options.challenge;
            LogPrintf("Signet with challenge %s\n", HexStr(bin));
        }

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;
        chainTxData = ChainTxData{
            0,
            0,
            0,
        };

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 525000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = options.pow_target_spacing;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = false;
        consensus.fKAWPOW = false;
        consensus.fSkipKAWPOWValidation = false;
        consensus.fReducedDataLimits = true;
        consensus.fEnforceP2MROnlyOutputs = true;
        consensus.nKAWPOWHeight = std::numeric_limits<int>::max();
        consensus.fMatMulPOW = true;
        consensus.nMatMulDimension = 256;
        consensus.nMatMulTranscriptBlockSize = 8;
        consensus.nMatMulNoiseRank = 4;
        consensus.nMatMulValidationWindow = 500;
        consensus.nMatMulPhase2FailBanThreshold = std::numeric_limits<uint32_t>::max();
        consensus.fMatMulStrictPunishment = false;
        consensus.nMatMulSnapshotInterval = 10'000;
        consensus.nMatMulProofPruneDepth = 10'000;
        consensus.fMatMulFreivaldsEnabled = true;
        consensus.nMatMulFreivaldsRounds = 2;
        consensus.fMatMulRequireProductPayload = true;
        consensus.nMatMulFreivaldsBindingHeight = 61'000;
        consensus.nMatMulProductDigestHeight = 61'000;
        consensus.nMaxReorgDepth = 144;
        consensus.nReorgProtectionStartHeight = 61'000;
        consensus.nPowTargetSpacingFastMs = 250;
        consensus.nFastMineDifficultyScale = 4;
        consensus.nPowTargetSpacingNormal = 90;
        consensus.nFastMineHeight = 61'000;
        // DGW is NOT used for MatMul mining -- ASERT only. See pow.cpp.
        consensus.nDgwAsymmetricClampHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwEasingBoostHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwWindowAlignmentHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwSlewGuardHeight = std::numeric_limits<int32_t>::max();
        // ASERT activates at nFastMineHeight. This MUST equal nFastMineHeight.
        consensus.nMatMulAsertHeight = 61'000;
        consensus.nMatMulAsertHalfLife = 3'600;
        consensus.nMatMulAsertBootstrapFactor = 180;
        // No retune or half-life upgrade needed — fresh chain starts with
        // the target 3,600s half-life directly.
        consensus.nMatMulAsertRetuneHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertRetuneHardeningFactor = 1;
        consensus.nMatMulAsertRetune2Height = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertRetune2TargetNum = 1;
        consensus.nMatMulAsertRetune2TargetDen = 1;
        consensus.nMatMulAsertHalfLifeUpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertHalfLifeUpgrade = 3'600;
        // Hardened pre-hash epsilon (18 bits) active from ASERT activation.
        consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = 61'000;
        consensus.nMatMulPreHashEpsilonBitsUpgrade = 18;
        consensus.nMaxBlockWeight = 24'000'000;
        consensus.nMaxBlockSerializedSize = 24'000'000;
        consensus.nMaxBlockSigOpsCost = 480'000;
        consensus.nDefaultBlockMaxWeight = 24'000'000;
        consensus.nDefaultMempoolMaxSizeMB = 2048;
        consensus.nMaxShieldedTxSize = 6'500'000;
        consensus.nMaxShieldedRingSize = 32;
        consensus.nShieldedMerkleTreeDepth = 32;
        consensus.nShieldedPoolActivationHeight = 0;
        consensus.nShieldedTxBindingActivationHeight = 61'000;
        consensus.nShieldedBridgeTagActivationHeight = 61'000;
        consensus.nShieldedSmileRiceCodecDisableHeight = 61'000;
        consensus.nShieldedMatRiCTDisableHeight = 61'000;
        consensus.nShieldedPQ128UpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nShieldedSettlementAnchorMaturity = 6;
        consensus.nMLDSADisableHeight = std::numeric_limits<int32_t>::max();
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"027525460aa64c2f837b4a2339c0ebedfa43fe5c91d14e3bcd35a858793dd970"};
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Activation of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 38333;
        nPruneAfterHeight = 1000;

        // Reuse the testnet genesis block for signet.
        genesis = CreateBTXGenesisBlock(
            1773878400,  // Mar 19, 2026 — SMILE v2 chain restart
            0,
            238,
            0x20027525,
            1,
            consensus.nInitialSubsidy,
            static_cast<uint16_t>(consensus.nMatMulDimension),
            uint256{"00230371b05217711a10cf44983c2ffc3d82da06369fd0e640b6d20c033e38da"});
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"f2bc3fb2eca6aa6059c4d0178b56efe038d46aa440d406905ef752179aa0e1a4"});
        assert(genesis.hashMerkleRoot == uint256{"94ae75cb0cd5f08b9447306ae914635d1c36d1a43d330daf596957e91cee002a"});

        m_assumeutxo_data = {};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tbtx";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.CSVHeight = 1;    // Always active unless overridden
        consensus.SegwitHeight = 0; // Always active unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = 90;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = opts.enforce_bip94;
        consensus.fPowNoRetargeting = true;
        consensus.fKAWPOW = false;
        consensus.fSkipKAWPOWValidation = !opts.matmul_strict;
        consensus.fReducedDataLimits = true;
        consensus.fEnforceP2MROnlyOutputs = false;
        consensus.nKAWPOWHeight = std::numeric_limits<int>::max();
        consensus.fMatMulPOW = true;
        consensus.fSkipMatMulValidation = !opts.matmul_strict;
        consensus.nMatMulDimension = 64;
        consensus.nMatMulTranscriptBlockSize = 8;
        consensus.nMatMulNoiseRank = 4;
        consensus.nMatMulValidationWindow = 10;
        consensus.nMatMulPhase2FailBanThreshold = std::numeric_limits<uint32_t>::max();
        consensus.fMatMulStrictPunishment = false;
        consensus.nMatMulSnapshotInterval = 10'000;
        consensus.nMatMulProofPruneDepth = 10'000;
        consensus.fMatMulFreivaldsEnabled = true;
        consensus.nMatMulFreivaldsRounds = 2;
        consensus.fMatMulRequireProductPayload = true;
        consensus.nMatMulFreivaldsBindingHeight = 0;
        consensus.nMatMulProductDigestHeight = 0;
        consensus.nMatMulPreHashEpsilonBits = 0; // Disable pre-hash filter for fast regtest mining
        consensus.nMatMulPreHashEpsilonBitsUpgrade = consensus.nMatMulPreHashEpsilonBits;
        consensus.nMatMulGlobalVerifyBudgetPerMin = std::numeric_limits<uint32_t>::max(); // No global budget limit in regtest
        consensus.nPowTargetSpacingFastMs = 250;
        consensus.nFastMineDifficultyScale = 4;
        consensus.nPowTargetSpacingNormal = 90;
        consensus.nFastMineHeight = 0;
        // DGW is NOT used for MatMul mining -- ASERT only. See pow.cpp.
        consensus.nDgwAsymmetricClampHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwEasingBoostHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwWindowAlignmentHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwSlewGuardHeight = std::numeric_limits<int32_t>::max();
        // ASERT activates at nFastMineHeight (0 for regtest = immediate).
        consensus.nMatMulAsertHeight = 0;
        consensus.nMatMulAsertHalfLife = 14'400;
        if (opts.matmul_dgw) {
            consensus.fPowNoRetargeting = false;
            consensus.fPowAllowMinDifficultyBlocks = false;
            // Keep a short fast phase so tests can mine both phases and still
            // exercise ASERT retargeting at practical regtest speed.
            consensus.nFastMineHeight = 2;
            consensus.nMatMulAsertHeight = 2;
        }
        if (opts.matmul_binding_height.has_value()) {
            consensus.nMatMulFreivaldsBindingHeight = *opts.matmul_binding_height;
        }
        if (opts.matmul_product_digest_height.has_value()) {
            consensus.nMatMulProductDigestHeight = *opts.matmul_product_digest_height;
        }
        if (opts.matmul_require_product_payload.has_value()) {
            consensus.fMatMulRequireProductPayload = *opts.matmul_require_product_payload;
        }
        if (opts.matmul_asert_half_life.has_value()) {
            consensus.nMatMulAsertHalfLife = *opts.matmul_asert_half_life;
        }
        if (opts.matmul_asert_half_life_upgrade_height.has_value()) {
            consensus.nMatMulAsertHalfLifeUpgradeHeight = *opts.matmul_asert_half_life_upgrade_height;
            consensus.nMatMulAsertHalfLifeUpgrade = *opts.matmul_asert_half_life_upgrade;
        }
        if (opts.matmul_pre_hash_epsilon_bits_upgrade_height.has_value()) {
            consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = *opts.matmul_pre_hash_epsilon_bits_upgrade_height;
            consensus.nMatMulPreHashEpsilonBitsUpgrade = *opts.matmul_pre_hash_epsilon_bits_upgrade;
        }
        consensus.nMaxBlockWeight = 24'000'000;
        consensus.nMaxBlockSerializedSize = 24'000'000;
        consensus.nMaxBlockSigOpsCost = 480'000;
        consensus.nDefaultBlockMaxWeight = 24'000'000;
        consensus.nDefaultMempoolMaxSizeMB = 2048;
        consensus.nMaxShieldedTxSize = 6'500'000;
        consensus.nMaxShieldedRingSize = 32;
        consensus.nShieldedMerkleTreeDepth = 32;
        consensus.nShieldedPoolActivationHeight = 0;
        consensus.nShieldedTxBindingActivationHeight = 0;  // Activate at genesis for instant regtest
        consensus.nShieldedBridgeTagActivationHeight = 0;  // Activate at genesis for instant regtest
        consensus.nShieldedSmileRiceCodecDisableHeight = 0;  // Activate at genesis for instant regtest
        consensus.nShieldedMatRiCTDisableHeight =
            opts.shielded_matrict_disable_height.value_or(0);  // Activate at genesis for instant regtest
        consensus.nShieldedSpendPathRecoveryActivationHeight =
            opts.shielded_spend_path_recovery_activation_height.value_or(std::numeric_limits<int32_t>::max());
        consensus.nShieldedPQ128UpgradeHeight =
            opts.shielded_pq128_upgrade_height.value_or(std::numeric_limits<int32_t>::max());
        consensus.nShieldedSettlementAnchorMaturity = 6;
        consensus.nMLDSADisableHeight = opts.mldsa_disable_height.value_or(std::numeric_limits<int32_t>::max());
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        constexpr MessageStartChars default_message_start{0xfa, 0xbf, 0xb5, 0xda};
        constexpr uint16_t default_port{18444};
        constexpr uint32_t default_genesis_time{1296688602};
        constexpr uint32_t default_genesis_nonce{2};
        constexpr uint32_t default_genesis_bits{0x207fffff};
        constexpr int32_t default_genesis_version{1};

        pchMessageStart = opts.message_start.value_or(default_message_start);
        nDefaultPort = opts.default_port.value_or(default_port);
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        const uint32_t genesis_time = opts.genesis_time.value_or(default_genesis_time);
        const uint32_t genesis_nonce = opts.genesis_nonce.value_or(default_genesis_nonce);
        const uint32_t genesis_bits = opts.genesis_bits.value_or(default_genesis_bits);
        const int32_t genesis_version = opts.genesis_version.value_or(default_genesis_version);

        const bool custom_genesis =
            opts.genesis_time.has_value() ||
            opts.genesis_nonce.has_value() ||
            opts.genesis_bits.has_value() ||
            opts.genesis_version.has_value();
        const bool custom_consensus =
            custom_genesis ||
            !opts.activation_heights.empty() ||
            !opts.version_bits_parameters.empty() ||
            opts.enforce_bip94 ||
            opts.matmul_dgw ||
            opts.matmul_binding_height.has_value() ||
            opts.matmul_product_digest_height.has_value() ||
            opts.matmul_require_product_payload.has_value() ||
            opts.matmul_asert_half_life.has_value() ||
            opts.matmul_asert_half_life_upgrade_height.has_value() ||
            opts.shielded_matrict_disable_height.has_value() ||
            opts.shielded_spend_path_recovery_activation_height.has_value() ||
            opts.shielded_pq128_upgrade_height.has_value() ||
            opts.mldsa_disable_height.has_value();

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        genesis = CreateBTXGenesisBlock(
            genesis_time,
            genesis_nonce,
            genesis_nonce,
            genesis_bits,
            genesis_version,
            consensus.nInitialSubsidy,
            static_cast<uint16_t>(consensus.nMatMulDimension),
            custom_genesis
                ? uint256{}
                : uint256{"7ff451fb9e39ebaa8447435600978167d9cb8b9ee1d6933eb5e1ad84d05a2a37"});
        consensus.hashGenesisBlock = genesis.GetHash();
        if (!custom_genesis) {
            assert(consensus.hashGenesisBlock == uint256{"521ad0951ed299e9c56aeb7db8188972772067560351b8e55adf71dbed532360"});
        }
        assert(genesis.hashMerkleRoot == uint256{"94ae75cb0cd5f08b9447306ae914635d1c36d1a43d330daf596957e91cee002a"});

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        if (!custom_consensus) {
            m_assumeutxo_data = {
                {
                    // Deterministic TestChain100Setup (regtest) snapshot metadata at height 110.
                    .height = 110,
                    .hash_serialized = AssumeutxoHash{uint256{"c35580bfd4f6c2ab69a8b1ac446962e5aacb164dc13e237867bd2170b91d7c98"}},
                    .m_chain_tx_count = 111,
                    .blockhash = consteval_ctor(uint256{"9e3817054fd9df2c2a27f647a3b9f55f8bc91f05168753543a902074a8f21700"}),
                },
                {
                    // Deterministic TestChain100Setup + BTX-compatible
                    // feature_assumeutxo extension using RAW_P2PKH wallet flows.
                    .height = 299,
                    .hash_serialized = AssumeutxoHash{uint256{"0ffcf7afd7682a59057ad717784b70ca8fb86cf9209912ccca20261aafa5001a"}},
                    .m_chain_tx_count = 300,
                    .blockhash = consteval_ctor(uint256{"78e6ea382d4d5466b1d8421c1b8789e9c7cde9de8b6da4042be00ca2948a4860"}),
                },
                {
                    // Post-shielded-activation regtest snapshot for btx-p2p
                    // fast-start testing. IsMockableChain() allows height-only
                    // matching, and validation treats all-zero blockhash /
                    // hash_serialized as a mockable-chain wildcard so any
                    // regtest snapshot at this height can be used.
                    .height = 61'010,
                    .hash_serialized = AssumeutxoHash{uint256{"0000000000000000000000000000000000000000000000000000000000000000"}},
                    .m_chain_tx_count = 61'011,
                    .blockhash = consteval_ctor(uint256{"0000000000000000000000000000000000000000000000000000000000000000"}),
                },
            };
        } else {
            // Consensus-altering regtest overrides invalidate canned snapshot metadata.
            m_assumeutxo_data.clear();
        }

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "btxrt";
    }
};

class CShieldedV2DevParams : public CChainParams
{
public:
    CShieldedV2DevParams()
    {
        m_chain_type = ChainType::SHIELDEDV2DEV;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60;
        consensus.nPowTargetSpacing = 90;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = true;
        consensus.fKAWPOW = false;
        consensus.fSkipKAWPOWValidation = true;
        consensus.fReducedDataLimits = true;
        consensus.fEnforceP2MROnlyOutputs = false;
        consensus.nKAWPOWHeight = std::numeric_limits<int>::max();
        consensus.fMatMulPOW = true;
        consensus.fSkipMatMulValidation = true;
        consensus.nMatMulDimension = 64;
        consensus.nMatMulTranscriptBlockSize = 8;
        consensus.nMatMulNoiseRank = 4;
        consensus.nMatMulValidationWindow = 10;
        consensus.nMatMulPhase2FailBanThreshold = std::numeric_limits<uint32_t>::max();
        consensus.fMatMulStrictPunishment = false;
        consensus.nMatMulSnapshotInterval = 10'000;
        consensus.nMatMulProofPruneDepth = 10'000;
        consensus.fMatMulFreivaldsEnabled = true;
        consensus.nMatMulFreivaldsRounds = 2;
        consensus.fMatMulRequireProductPayload = true;
        consensus.nMatMulFreivaldsBindingHeight = 0;
        consensus.nMatMulProductDigestHeight = 0;
        consensus.nMatMulPreHashEpsilonBits = 0;
        consensus.nMatMulPreHashEpsilonBitsUpgrade = consensus.nMatMulPreHashEpsilonBits;
        consensus.nMatMulGlobalVerifyBudgetPerMin = std::numeric_limits<uint32_t>::max();
        consensus.nPowTargetSpacingFastMs = 250;
        consensus.nFastMineDifficultyScale = 4;
        consensus.nPowTargetSpacingNormal = 90;
        consensus.nFastMineHeight = 0;
        consensus.nDgwAsymmetricClampHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwEasingBoostHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwWindowAlignmentHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwSlewGuardHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertHeight = 0;
        consensus.nMatMulAsertHalfLife = 14'400;
        consensus.nMaxBlockWeight = 24'000'000;
        consensus.nMaxBlockSerializedSize = 24'000'000;
        consensus.nMaxBlockSigOpsCost = 480'000;
        consensus.nDefaultBlockMaxWeight = 24'000'000;
        consensus.nDefaultMempoolMaxSizeMB = 2048;
        consensus.nMaxShieldedTxSize = 6'500'000;
        consensus.nMaxShieldedRingSize = 32;
        consensus.nShieldedMerkleTreeDepth = 32;
        consensus.nShieldedPoolActivationHeight = 0;
        consensus.nShieldedTxBindingActivationHeight = 61'000;
        consensus.nShieldedBridgeTagActivationHeight = 61'000;
        consensus.nShieldedSmileRiceCodecDisableHeight = 61'000;
        consensus.nShieldedMatRiCTDisableHeight = 61'000;
        consensus.nShieldedPQ128UpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nShieldedSettlementAnchorMaturity = 6;
        consensus.nMLDSADisableHeight = std::numeric_limits<int32_t>::max();
        consensus.nRuleChangeActivationThreshold = 108;
        consensus.nMinerConfirmationWindow = 144;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart = MessageStartChars{0xe2, 0xb7, 0xda, 0x7a};
        nDefaultPort = 19444;
        nPruneAfterHeight = 100;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        constexpr uint32_t genesis_time{1773446400};
        constexpr uint32_t genesis_nonce{0};
        constexpr uint32_t genesis_bits{0x207fffff};
        constexpr int32_t genesis_version{1};
        constexpr uint64_t genesis_nonce64{0};

        genesis = CreateShieldedV2DevGenesisBlock(
            genesis_time,
            genesis_nonce,
            genesis_nonce64,
            genesis_bits,
            genesis_version,
            consensus.nInitialSubsidy,
            static_cast<uint16_t>(consensus.nMatMulDimension),
            uint256{});
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"4ed72f2a7db044ff555197cddde63b1f50b74d750674316f75c3571ade9c80a3"});

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.emplace_back("shieldedv2dev.invalid.");

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        m_assumeutxo_data.clear();

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "btxv2";
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet4()
{
    return std::make_unique<const CTestNet4Params>();
}

std::unique_ptr<const CChainParams> CChainParams::ShieldedV2Dev()
{
    return std::make_unique<const CShieldedV2DevParams>();
}

std::vector<int> CChainParams::GetAvailableSnapshotHeights() const
{
    std::vector<int> heights;
    heights.reserve(m_assumeutxo_data.size());

    for (const auto& data : m_assumeutxo_data) {
        heights.emplace_back(data.height);
    }
    return heights;
}

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& message)
{
    const auto mainnet_msg = CChainParams::Main()->MessageStart();
    const auto testnet_msg = CChainParams::TestNet()->MessageStart();
    const auto testnet4_msg = CChainParams::TestNet4()->MessageStart();
    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();
    const auto shieldedv2dev_msg = CChainParams::ShieldedV2Dev()->MessageStart();
    const auto signet_msg = CChainParams::SigNet({})->MessageStart();

    if (std::ranges::equal(message, mainnet_msg)) {
        return ChainType::MAIN;
    } else if (std::ranges::equal(message, testnet_msg)) {
        return ChainType::TESTNET;
    } else if (std::ranges::equal(message, testnet4_msg)) {
        return ChainType::TESTNET4;
    } else if (std::ranges::equal(message, regtest_msg)) {
        return ChainType::REGTEST;
    } else if (std::ranges::equal(message, shieldedv2dev_msg)) {
        return ChainType::SHIELDEDV2DEV;
    } else if (std::ranges::equal(message, signet_msg)) {
        return ChainType::SIGNET;
    }
    return std::nullopt;
}
