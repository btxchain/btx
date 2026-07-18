// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_CHAINPARAMS_H
#define BITCOIN_KERNEL_CHAINPARAMS_H

#include <consensus/params.h>
#include <kernel/messagestartchars.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/hash_type.h>
#include <util/vector.h>

#include <cstdint>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

typedef std::map<int, uint256> MapCheckpoints;

struct CCheckpointData {
    MapCheckpoints mapCheckpoints;

    int GetHeight() const {
        if (mapCheckpoints.empty()) return 0;
        const auto& final_checkpoint = mapCheckpoints.rbegin();
        return final_checkpoint->first /* height */;
    }

    bool CheckBlock(int height, const uint256& hash) const {
        const auto i = mapCheckpoints.find(height);
        if (i == mapCheckpoints.end()) return true;
        return hash == i->second;
    }
};

struct AssumeutxoHash : public BaseHash<uint256> {
    explicit AssumeutxoHash(const uint256& hash) : BaseHash(hash) {}
};

/**
 * Holds configuration for use during UTXO snapshot load and validation. The contents
 * here are security critical, since they dictate which UTXO snapshots are recognized
 * as valid.
 */
struct AssumeutxoData {
    int height;

    //! The expected hash of the deserialized UTXO set.
    AssumeutxoHash hash_serialized;

    //! Used to populate the m_chain_tx_count value, which is used during BlockManager::LoadBlockIndex().
    //!
    //! We need to hardcode the value here because this is computed cumulatively using block data,
    //! which we do not necessarily have at the time of snapshot load.
    uint64_t m_chain_tx_count;

    //! The hash of the base block for this snapshot. Used to refer to assumeutxo data
    //! prior to having a loaded blockindex.
    uint256 blockhash;

    //! DS-3 fix: consensus-pinned commitment to the BTX shielded state (note-commitment root,
    //! nullifier-set root, and pool balance) at the snapshot base height. The shielded snapshot section
    //! is otherwise attacker-supplied and unvalidated; loading is rejected unless the loaded shielded
    //! state hashes to this value. Null (default) means "not pinned" -- the legacy behavior, retained
    //! for snapshots whose shielded pin has not yet been computed at snapshot-generation time.
    uint256 shielded_state_commitment{};
};

/**
 * Holds various statistics on transactions within a chain. Used to estimate
 * verification progress during chain sync.
 *
 * See also: CChainParams::TxData, GuessVerificationProgress.
 */
struct ChainTxData {
    int64_t nTime;    //!< UNIX timestamp of last known number of transactions
    uint64_t tx_count; //!< total number of transactions between genesis and that timestamp
    double dTxRate;   //!< estimated number of transactions per second after that timestamp
};

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Bitcoin system.
 */
class CChainParams
{
public:
    enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,

        MAX_BASE58_TYPES
    };

    const Consensus::Params& GetConsensus() const { return consensus; }
    const MessageStartChars& MessageStart() const { return pchMessageStart; }
    uint16_t GetDefaultPort() const { return nDefaultPort; }
    std::vector<int> GetAvailableSnapshotHeights() const;

    const CBlock& GenesisBlock() const { return genesis; }
    /** Default value for -checkmempool and -checkblockindex argument */
    bool DefaultConsistencyChecks() const { return fDefaultConsistencyChecks; }
    /** If this chain is exclusively used for testing */
    bool IsTestChain() const { return m_chain_type != ChainType::MAIN; }
    /** If this chain allows time to be mocked */
    bool IsMockableChain() const { return m_is_mockable_chain; }
    uint64_t PruneAfterHeight() const { return nPruneAfterHeight; }
    /** Minimum free space (in GB) needed for data directory */
    uint64_t AssumedBlockchainSize() const { return m_assumed_blockchain_size; }
    /** Minimum free space (in GB) needed for data directory when pruned; Does not include prune target*/
    uint64_t AssumedChainStateSize() const { return m_assumed_chain_state_size; }
    /** Whether it is possible to mine blocks on demand (no retargeting) */
    bool MineBlocksOnDemand() const { return consensus.fPowNoRetargeting; }
    /** Return the chain type string */
    std::string GetChainTypeString() const { return ChainTypeToString(m_chain_type); }
    /** Return the chain type */
    ChainType GetChainType() const { return m_chain_type; }
    /** Return the list of hostnames to look up for DNS seeds */
    const std::vector<std::string>& DNSSeeds() const { return vSeeds; }
    const std::vector<unsigned char>& Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    const std::string& Bech32HRP() const { return bech32_hrp; }
    const std::vector<uint8_t>& FixedSeeds() const { return vFixedSeeds; }
    const CCheckpointData& Checkpoints() const { return checkpointData; }

    std::optional<AssumeutxoData> AssumeutxoForHeight(int height) const
    {
        return FindFirst(m_assumeutxo_data, [&](const auto& d) { return d.height == height; });
    }
    std::optional<AssumeutxoData> AssumeutxoForBlockhash(const uint256& blockhash) const
    {
        return FindFirst(m_assumeutxo_data, [&](const auto& d) { return d.blockhash == blockhash; });
    }
    bool AssumeutxoHashMatches(const AssumeutxoData& data, const uint256& actual_hash) const
    {
        return (m_is_mockable_chain && data.hash_serialized == AssumeutxoHash{uint256{}}) ||
            data.hash_serialized == AssumeutxoHash{actual_hash};
    }

    const ChainTxData& TxData() const { return chainTxData; }

    /**
     * SigNetOptions holds configurations for creating a signet CChainParams.
     */
    struct SigNetOptions {
        std::optional<std::vector<uint8_t>> challenge{};
        std::optional<std::vector<std::string>> seeds{};
        int64_t pow_target_spacing{10 * 60};
    };

    /**
     * VersionBitsParameters holds activation parameters
     */
    struct VersionBitsParameters {
        int64_t start_time;
        int64_t timeout;
        int min_activation_height;
    };

    /**
     * RegTestOptions holds configurations for creating a regtest CChainParams.
     */
    struct RegTestOptions {
        std::unordered_map<Consensus::DeploymentPos, VersionBitsParameters> version_bits_parameters{};
        std::unordered_map<Consensus::BuriedDeployment, int> activation_heights{};
        std::optional<MessageStartChars> message_start{};
        std::optional<uint16_t> default_port{};
        std::optional<uint32_t> genesis_time{};
        std::optional<uint32_t> genesis_nonce{};
        std::optional<uint32_t> genesis_bits{};
        std::optional<int32_t> genesis_version{};
        std::optional<int32_t> mldsa_disable_height{};
        std::optional<int32_t> shielded_tx_binding_activation_height{};
        std::optional<int32_t> shielded_bridge_tag_activation_height{};
        std::optional<int32_t> shielded_smile_rice_codec_disable_height{};
        std::optional<int32_t> shielded_matrict_disable_height{};
        std::optional<int32_t> shielded_spend_path_recovery_activation_height{};
        std::optional<int32_t> shielded_c002_activation_height{};
        std::optional<int32_t> shielded_unshield_velocity_activation_height{};
        std::optional<int32_t> shielded_unshield_velocity_end_height{};
        std::optional<int32_t> shielded_unshield_velocity_min_cap_height{};
        std::optional<CAmount> shielded_unshield_velocity_min_cap{};
        std::optional<int32_t> shielded_pq128_upgrade_height{};
        std::optional<int32_t> shielded_pool_credit_disable_height{};
        std::optional<int32_t> shielded_sunset_height{};
        std::optional<int32_t> shielded_direct_send_public_flow_disable_height{};
        std::optional<int32_t> shielded_v2_send_zero_output_exit_activation_height{};
        std::optional<int32_t> shielded_recovery_exit_activation_height{};
        std::optional<uint256> shielded_recovery_exit_frozen_root{};
        std::optional<int32_t> reorg_protection_start_height{};
        std::optional<int32_t> empty_block_subsidy_penalty_height{};
        std::optional<int32_t> empty_block_subsidy_penalty_end_height{};
        std::optional<int32_t> matmul_binding_height{};
        std::optional<int32_t> matmul_product_digest_height{};
        std::optional<bool> matmul_require_product_payload{};
        std::optional<uint32_t> matmul_dimension{};
        std::optional<uint32_t> matmul_transcript_block_size{};
        std::optional<uint32_t> matmul_noise_rank{};
        std::optional<int64_t> matmul_asert_half_life{};
        std::optional<int32_t> matmul_asert_half_life_upgrade_height{};
        std::optional<int64_t> matmul_asert_half_life_upgrade{};
        std::optional<int32_t> matmul_pre_hash_epsilon_bits_upgrade_height{};
        std::optional<uint32_t> matmul_pre_hash_epsilon_bits_upgrade{};
        std::optional<int32_t> matmul_nonce_seed_height{};
        std::optional<int32_t> matmul_parent_mtp_seed_height{};
        std::optional<int32_t> matmul_v4_height{};
        std::optional<uint32_t> matmul_v4_dimension{};
        std::optional<uint32_t> matmul_v4_max_dimension{};
        std::optional<int32_t> matmul_bmx4c_height{};
        bool matmul_flat_sketch_replay{false};
        std::optional<uint32_t> matmul_proof_assumevalid_min_age{};
        bool fastprune{false};
        bool enforce_bip94{false};
        bool matmul_strict{false};
        bool matmul_dgw{false};
    };

    static std::unique_ptr<const CChainParams> RegTest(const RegTestOptions& options);
    static std::unique_ptr<const CChainParams> SigNet(const SigNetOptions& options);
    static std::unique_ptr<const CChainParams> Main();
    static std::unique_ptr<const CChainParams> TestNet();
    static std::unique_ptr<const CChainParams> TestNet4();
    static std::unique_ptr<const CChainParams> ShieldedV2Dev();

protected:
    CChainParams() = default;

    Consensus::Params consensus;
    MessageStartChars pchMessageStart;
    uint16_t nDefaultPort;
    uint64_t nPruneAfterHeight;
    uint64_t m_assumed_blockchain_size;
    uint64_t m_assumed_chain_state_size;
    std::vector<std::string> vSeeds;
    std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];
    std::string bech32_hrp;
    ChainType m_chain_type;
    CBlock genesis;
    std::vector<uint8_t> vFixedSeeds;
    bool fDefaultConsistencyChecks;
    bool m_is_mockable_chain;
    CCheckpointData checkpointData;
    std::vector<AssumeutxoData> m_assumeutxo_data;
    ChainTxData chainTxData;
};

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& pchMessageStart);

#endif // BITCOIN_KERNEL_CHAINPARAMS_H
