// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_UTXO_SNAPSHOT_H
#define BITCOIN_NODE_UTXO_SNAPSHOT_H

#include <chainparams.h>
#include <consensus/amount.h>
#include <kernel/chainparams.h>
#include <kernel/cs_main.h>
#include <serialize.h>
#include <shielded/bundle.h>
#include <sync.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/fs.h>

#include <cstdint>
#include <optional>
#include <string_view>

// UTXO set snapshot magic bytes
static constexpr std::array<uint8_t, 5> SNAPSHOT_MAGIC_BYTES = {'u', 't', 'x', 'o', 0xff};

class Chainstate;

namespace node {
//! Metadata describing a serialized version of a UTXO set from which an
//! assumeutxo Chainstate can be constructed.
//! All metadata fields come from an untrusted file, so must be validated
//! before being used. Thus, new fields should be added only if needed.
class SnapshotMetadata
{
public:
    inline static constexpr uint16_t CURRENT_VERSION{6};

private:
    const std::set<uint16_t> m_supported_versions{2, 3, 4, 5, CURRENT_VERSION};
    const MessageStartChars m_network_magic;
    uint16_t m_version{CURRENT_VERSION};

public:
    //! The hash of the block that reflects the tip of the chain for the
    //! UTXO set contained in this snapshot.
    uint256 m_base_blockhash;


    //! The number of coins in the UTXO set contained in this snapshot. Used
    //! during snapshot load to estimate progress of UTXO set reconstruction.
    uint64_t m_coins_count = 0;

    SnapshotMetadata(
        const MessageStartChars network_magic) :
            m_network_magic(network_magic) { }
    SnapshotMetadata(
        const MessageStartChars network_magic,
        const uint256& base_blockhash,
        uint64_t coins_count) :
            m_network_magic(network_magic),
            m_base_blockhash(base_blockhash),
            m_coins_count(coins_count) { }

    [[nodiscard]] uint16_t Version() const { return m_version; }
    [[nodiscard]] bool HasShieldedSection() const { return m_version >= 3; }

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        s << SNAPSHOT_MAGIC_BYTES;
        s << m_version;
        s << m_network_magic;
        s << m_base_blockhash;
        s << m_coins_count;
    }

    template <typename Stream>
    inline void Unserialize(Stream& s) {
        // Read the snapshot magic bytes
        std::array<uint8_t, SNAPSHOT_MAGIC_BYTES.size()> snapshot_magic;
        s >> snapshot_magic;
        if (snapshot_magic != SNAPSHOT_MAGIC_BYTES) {
            throw std::ios_base::failure("Invalid UTXO set snapshot magic bytes. Please check if this is indeed a snapshot file or if you are using an outdated snapshot format.");
        }

        // Read the version
        uint16_t version;
        s >> version;
        if (m_supported_versions.find(version) == m_supported_versions.end()) {
            throw std::ios_base::failure(strprintf("Version of snapshot %s does not match any of the supported versions.", version));
        }
        m_version = version;

        // Read the network magic (pchMessageStart)
        MessageStartChars message;
        s >> message;
        if (!std::equal(message.begin(), message.end(), m_network_magic.data())) {
            auto metadata_network{GetNetworkForMagic(message)};
            if (metadata_network) {
                std::string network_string{ChainTypeToString(metadata_network.value())};
                auto node_network{GetNetworkForMagic(m_network_magic)};
                std::string node_network_string{ChainTypeToString(node_network.value())};
                throw std::ios_base::failure(strprintf("The network of the snapshot (%s) does not match the network of this node (%s).", network_string, node_network_string));
            } else {
                throw std::ios_base::failure("This snapshot has been created for an unrecognized network. This could be a custom signet, a new testnet or possibly caused by data corruption.");
            }
        }

        s >> m_base_blockhash;
        s >> m_coins_count;
    }
};

static constexpr std::array<uint8_t, 5> SHIELDED_SNAPSHOT_MAGIC_BYTES = {'s', 'h', 'l', 'd', 0xfe};

class ShieldedSnapshotSectionHeader
{
public:
    uint16_t m_snapshot_version{SnapshotMetadata::CURRENT_VERSION};
    uint64_t m_commitment_count{0};
    uint64_t m_nullifier_count{0};
    uint64_t m_settlement_anchor_count{0};
    uint64_t m_netting_manifest_count{0};
    uint64_t m_account_registry_entry_count{0};
    std::vector<uint64_t> m_recent_output_counts;
    CAmount m_pool_balance{0};

    template <typename Stream>
    inline void Serialize(Stream& s) const
    {
        s << SHIELDED_SNAPSHOT_MAGIC_BYTES;
        s << m_commitment_count;
        s << m_nullifier_count;
        s << m_recent_output_counts;
        s << m_pool_balance;
        if (m_snapshot_version >= 4) {
            s << m_settlement_anchor_count;
            s << m_netting_manifest_count;
            if (m_snapshot_version >= SnapshotMetadata::CURRENT_VERSION) {
                s << m_account_registry_entry_count;
            }
        }
    }

    template <typename Stream>
    inline void Unserialize(Stream& s)
    {
        std::array<uint8_t, SHIELDED_SNAPSHOT_MAGIC_BYTES.size()> snapshot_magic;
        s >> snapshot_magic;
        if (snapshot_magic != SHIELDED_SNAPSHOT_MAGIC_BYTES) {
            throw std::ios_base::failure("Invalid BTX shielded snapshot section magic bytes.");
        }

        s >> m_commitment_count;
        s >> m_nullifier_count;
        s >> m_recent_output_counts;
        s >> m_pool_balance;
        if (m_snapshot_version >= 4) {
            s >> m_settlement_anchor_count;
            s >> m_netting_manifest_count;
            if (m_snapshot_version >= SnapshotMetadata::CURRENT_VERSION) {
                s >> m_account_registry_entry_count;
            } else {
                m_account_registry_entry_count = 0;
            }
        } else {
            m_settlement_anchor_count = 0;
            m_netting_manifest_count = 0;
            m_account_registry_entry_count = 0;
        }
        if (m_recent_output_counts.size() > static_cast<size_t>(SHIELDED_ANCHOR_DEPTH)) {
            throw std::ios_base::failure("BTX shielded snapshot section has too many anchor history entries.");
        }
    }
};

//! The file in the snapshot chainstate dir which stores the base blockhash. This is
//! needed to reconstruct snapshot chainstates on init.
//!
//! Because we only allow loading a single snapshot at a time, there will only be one
//! chainstate directory with this filename present within it.
const fs::path SNAPSHOT_BLOCKHASH_FILENAME{"base_blockhash"};

//! Write out the blockhash of the snapshot base block that was used to construct
//! this chainstate. This value is read in during subsequent initializations and
//! used to reconstruct snapshot-based chainstates.
bool WriteSnapshotBaseBlockhash(Chainstate& snapshot_chainstate)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

//! Read the blockhash of the snapshot base block that was used to construct the
//! chainstate.
std::optional<uint256> ReadSnapshotBaseBlockhash(fs::path chaindir)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

//! Suffix appended to the chainstate (leveldb) dir when created based upon
//! a snapshot.
constexpr std::string_view SNAPSHOT_CHAINSTATE_SUFFIX = "_snapshot";


//! Return a path to the snapshot-based chainstate dir, if one exists.
std::optional<fs::path> FindSnapshotChainstateDir(const fs::path& data_dir);

} // namespace node

#endif // BITCOIN_NODE_UTXO_SNAPSHOT_H
