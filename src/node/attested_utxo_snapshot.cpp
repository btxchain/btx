// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/attested_utxo_snapshot.h>

#include <chain.h>
#include <coins.h>
#include <hash.h>
#include <kernel/cs_main.h>
#include <logging.h>
#include <logging/timer.h>
#include <node/utxo_snapshot.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <sync.h>
#include <util/check.h>
#include <util/fs_helpers.h>
#include <util/syserror.h>
#include <validation.h>

#include <algorithm>
#include <array>
#include <vector>
#include <atomic>
#include <cstdio>
#include <map>
#include <stdexcept>

namespace node {
namespace {

Mutex g_attested_offer_mutex;
std::optional<AttestedUTXOSnapshotOffer> g_attested_offer GUARDED_BY(g_attested_offer_mutex);
std::atomic<int64_t> g_last_max_cs_main_hold_us{0};

class CsMainHoldScope
{
    std::chrono::steady_clock::time_point m_start;
    std::chrono::microseconds& m_accum;
    std::chrono::microseconds& m_max;

public:
    explicit CsMainHoldScope(std::chrono::microseconds& accum,
                             std::chrono::microseconds& max_hold)
        : m_start{std::chrono::steady_clock::now()},
          m_accum{accum},
          m_max{max_hold}
    {
        AssertLockHeld(::cs_main);
    }
    ~CsMainHoldScope()
    {
        const auto held{std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - m_start)};
        m_accum += held;
        m_max = std::max(m_max, held);
    }
};

void HashCoin(HashWriter& ss, const COutPoint& outpoint, const Coin& coin)
{
    // Must match kernel::ComputeUTXOStats HASH_SERIALIZED construction.
    ss << outpoint;
    const uint32_t height_and_coinbase{
        (static_cast<uint32_t>(coin.nHeight) << 1U) |
        static_cast<uint32_t>(coin.fCoinBase)};
    ss << height_and_coinbase;
    ss << coin.out;
}

void HashTxOutputs(HashWriter& ss, const Txid& hash, const std::map<uint32_t, Coin>& outputs)
{
    for (const auto& [n, coin] : outputs) {
        HashCoin(ss, COutPoint(hash, n), coin);
    }
}

void WriteTxOutputs(AutoFile& afile,
                    const Txid& hash,
                    const std::map<uint32_t, Coin>& outputs,
                    size_t& written_coins_count)
{
    afile << hash;
    WriteCompactSize(afile, outputs.size());
    for (const auto& [n, coin] : outputs) {
        WriteCompactSize(afile, n);
        afile << coin;
        ++written_coins_count;
    }
}

bool CaptureShieldedSection(Chainstate& chainstate,
                            const CBlockIndex* tip,
                            DataStream& out,
                            uint256& shielded_state_pin,
                            std::string& error) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);
    if (!chainstate.m_chainman.EnsureShieldedStateInitialized()) {
        error = "Failed to initialize BTX shielded state for snapshot";
        return false;
    }
    try {
        const ShieldedSnapshotSectionHeader header{
            chainstate.m_chainman.GetShieldedSnapshotSectionHeader(chainstate, tip)};
        out << header;

        const auto& shielded_tree = chainstate.m_chainman.GetShieldedMerkleTree();
        for (uint64_t pos = 0; pos < shielded_tree.Size(); ++pos) {
            const auto commitment = shielded_tree.CommitmentAt(pos);
            if (!commitment.has_value()) {
                error = strprintf("Missing BTX shielded commitment at position %u", pos);
                return false;
            }
            out << *commitment;
        }
        if (!chainstate.m_chainman.ForEachShieldedNullifier([&](const Nullifier& nf) {
                out << nf;
                return true;
            })) {
            error = "Failed to serialize BTX shielded nullifiers";
            return false;
        }
        uint64_t written_recovery_exit_commitments{0};
        if (!chainstate.m_chainman.ForEachShieldedRecoveryExitCommitment(
                [&](const uint256& commitment) {
                    out << commitment;
                    ++written_recovery_exit_commitments;
                    return true;
                })) {
            error = "Failed to serialize BTX recovery-exit commitments";
            return false;
        }
        if (written_recovery_exit_commitments != header.m_recovery_exit_commitment_count) {
            error = "Recovery-exit commitment count mismatch during shielded capture";
            return false;
        }
        if (!chainstate.m_chainman.ForEachShieldedSettlementAnchor([&](const uint256& anchor) {
                out << anchor;
                return true;
            })) {
            error = "Failed to serialize BTX shielded settlement anchors";
            return false;
        }
        if (!chainstate.m_chainman.ForEachShieldedNettingManifestState(
                [&](const ConfirmedNettingManifestState& manifest_state) {
                    out << manifest_state;
                    return true;
                })) {
            error = "Failed to serialize BTX shielded netting manifests";
            return false;
        }
        const auto account_registry_snapshot =
            chainstate.m_chainman.ExportShieldedAccountRegistrySnapshot(chainstate, tip);
        if (!account_registry_snapshot.has_value()) {
            error = "Failed to serialize BTX shielded account-registry entries";
            return false;
        }
        if (account_registry_snapshot->entries.size() !=
            header.m_account_registry_entry_count) {
            error = "Account-registry entry count mismatch during shielded capture";
            return false;
        }
        for (const auto& entry : account_registry_snapshot->entries) {
            out << entry;
        }
        const auto pin = chainstate.m_chainman.ComputeShieldedSnapshotStatePin();
        if (!pin) {
            error = "Failed to compute shielded state pin";
            return false;
        }
        shielded_state_pin = *pin;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    return true;
}

} // namespace

uint256 AttestedUTXOSnapshotBytesHash(Span<const uint8_t> data)
{
    HashWriter writer{};
    writer.write(AsBytes(data));
    return writer.GetHash();
}

std::chrono::microseconds AttestedUTXOSnapshotLastMaxCsMainHoldForTest()
{
    return std::chrono::microseconds{g_last_max_cs_main_hold_us.load()};
}

AttestedUTXOSnapshotExportResult CreateAttestedUTXOSnapshot(
    Chainstate& chainstate,
    AutoFile&& afile,
    const fs::path& path,
    const fs::path& tmppath,
    const std::function<void()>& interruption_point)
{
    std::unique_ptr<CCoinsViewCursor> pcursor;
    const CBlockIndex* tip{nullptr};
    DataStream shielded_bytes{};
    uint256 shielded_state_pin{};
    std::chrono::microseconds max_hold{0};
    std::chrono::microseconds flush_hold{0};
    std::chrono::microseconds shielded_hold{0};

    // Critical section 1: flush dirty cache and open a LevelDB snapshot cursor.
    {
        LOCK(::cs_main);
        CsMainHoldScope hold{flush_hold, max_hold};
        chainstate.ForceFlushStateToDisk(/*wipe_cache=*/false);
        pcursor = chainstate.CoinsDB().Cursor();
        tip = CHECK_NONFATAL(
            chainstate.m_blockman.LookupBlockIndex(pcursor->GetBestBlock()));
    }

    // Critical section 2: capture shielded state into a buffer while still at
    // the flushed tip. Tip may advance after we release; the coins cursor is a
    // LevelDB snapshot of the flushed tip, and the shielded section must match
    // that same tip. Re-check tip hash under the lock.
    {
        LOCK(::cs_main);
        CsMainHoldScope hold{shielded_hold, max_hold};
        const CBlockIndex* live_tip{chainstate.m_chain.Tip()};
        if (!live_tip || live_tip->GetBlockHash() != tip->GetBlockHash()) {
            // Tip moved before shielded capture. The coins snapshot is still
            // the old tip; refuse rather than mix tip heights.
            throw std::runtime_error(
                "Active tip moved during attested UTXO snapshot preparation; "
                "retry the export");
        }
        std::string error;
        if (!CaptureShieldedSection(chainstate, tip, shielded_bytes,
                                    shielded_state_pin, error)) {
            throw std::runtime_error(error);
        }
    }

    g_last_max_cs_main_hold_us.store(max_hold.count());

    LOG_TIME_SECONDS(strprintf(
        "writing attested UTXO snapshot at height %s (%s) to file %s without "
        "holding cs_main across the coin walk (max prior cs_main hold %sus)",
        tip->nHeight, tip->GetBlockHash().ToString(),
        fs::PathToString(path), max_hold.count()));

    // Coin walk + hash_serialized: MUST NOT hold cs_main. Write coin bytes to a
    // side file first so SnapshotMetadata.coins_count (needed before the coin
    // payload in the on-disk format) is known before composing the final file.
    AssertLockNotHeld(::cs_main);

    const fs::path coins_tmp{tmppath + ".coins"};
    FILE* coins_file{fsbridge::fopen(coins_tmp, "wb")};
    if (!coins_file) {
        throw std::runtime_error("Couldn't open temporary coins file for attested snapshot");
    }
    AutoFile coins_afile{coins_file};

    HashWriter hash_ss{};
    Txid prevkey{};
    std::map<uint32_t, Coin> outputs;
    size_t written_coins_count{0};
    unsigned int iter{0};

    auto flush_group = [&](const Txid& hash, std::map<uint32_t, Coin>& group) {
        if (group.empty()) return;
        HashTxOutputs(hash_ss, hash, group);
        WriteTxOutputs(coins_afile, hash, group, written_coins_count);
        group.clear();
    };

    while (pcursor->Valid()) {
        if (iter % 5000 == 0 && interruption_point) interruption_point();
        ++iter;
        AssertLockNotHeld(::cs_main);
        COutPoint key;
        Coin coin;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            if (!outputs.empty() && key.hash != prevkey) {
                flush_group(prevkey, outputs);
            }
            prevkey = key.hash;
            outputs[key.n] = std::move(coin);
        } else {
            coins_afile.fclose();
            fs::remove(coins_tmp);
            throw std::runtime_error("Unable to read UTXO set during attested snapshot");
        }
        pcursor->Next();
    }
    flush_group(prevkey, outputs);
    pcursor.reset();

    const uint256 txoutset_hash{hash_ss.GetHash()};

    if (coins_afile.fclose() != 0) {
        fs::remove(coins_tmp);
        throw std::runtime_error("Error closing temporary coins file");
    }

    SnapshotMetadata metadata{chainstate.m_chainman.GetParams().MessageStart(),
                              tip->GetBlockHash(), written_coins_count};
    afile << metadata;

    FILE* coins_in{fsbridge::fopen(coins_tmp, "rb")};
    if (!coins_in) {
        fs::remove(coins_tmp);
        throw std::runtime_error("Couldn't reopen temporary coins file");
    }
    {
        // Heap, not stack: a 1 MiB std::array overflows the ~544 KiB RPC
        // worker stack and crashes btxd deterministically (audit P0).
        std::vector<uint8_t> buf(1 << 20);
        while (true) {
            const size_t n{fread(buf.data(), 1, buf.size(), coins_in)};
            if (n > 0) {
                afile.write(AsBytes(Span{buf.data(), n}));
            }
            if (n < buf.size()) {
                if (ferror(coins_in)) {
                    fclose(coins_in);
                    fs::remove(coins_tmp);
                    throw std::runtime_error("Error reading temporary coins file");
                }
                break;
            }
            if (interruption_point) interruption_point();
        }
    }
    fclose(coins_in);
    fs::remove(coins_tmp);

    if (!shielded_bytes.empty()) {
        afile.write(AsBytes(Span{shielded_bytes.data(), shielded_bytes.size()}));
    }

    if (afile.fclose() != 0) {
        throw std::runtime_error(strprintf(
            "Error closing %s: %s", fs::PathToString(tmppath), SysErrorString(errno)));
    }

    AttestedUTXOSnapshotExportResult result;
    result.path = path;
    result.base_hash = tip->GetBlockHash();
    result.base_height = tip->nHeight;
    result.coins_written = written_coins_count;
    result.txoutset_hash = txoutset_hash;
    result.nchaintx = tip->m_chain_tx_count;
    result.shielded_state_pin = shielded_state_pin;
    result.max_cs_main_hold = max_hold;
    result.flush_hold = flush_hold;
    result.shielded_hold = shielded_hold;
    g_last_max_cs_main_hold_us.store(max_hold.count());
    return result;
}

bool OfferAttestedUTXOSnapshot(AttestedUTXOSnapshotOffer offer, std::string& error)
{
    if (offer.block_hash.IsNull() || offer.height < 0 || offer.file_size == 0 ||
        offer.chunk_size == 0 ||
        offer.chunk_size > ATTESTED_UTXO_SNAPSHOT_MAX_CHUNK_SIZE ||
        offer.chunk_count == 0 || offer.snapshot_path.empty() ||
        offer.manifest_path.empty() || offer.manifest.signatures.empty()) {
        error = "Invalid attested UTXO snapshot offer";
        return false;
    }
    if (!fs::exists(offer.snapshot_path) || !fs::exists(offer.manifest_path)) {
        error = "Snapshot or manifest file missing for offer";
        return false;
    }
    LOCK(g_attested_offer_mutex);
    g_attested_offer = std::move(offer);
    return true;
}

void ClearAttestedUTXOSnapshotOffer()
{
    LOCK(g_attested_offer_mutex);
    g_attested_offer.reset();
}

std::optional<AttestedUTXOSnapshotOffer> GetAttestedUTXOSnapshotOffer()
{
    LOCK(g_attested_offer_mutex);
    return g_attested_offer;
}

bool HasAttestedUTXOSnapshotOffer()
{
    LOCK(g_attested_offer_mutex);
    return g_attested_offer.has_value();
}

bool ReadAttestedUTXOSnapshotChunk(const AttestedUTXOSnapshotOffer& offer,
                                   uint32_t chunk_index,
                                   std::vector<uint8_t>& out_data,
                                   uint256& out_chunk_hash,
                                   std::string& error)
{
    out_data.clear();
    if (chunk_index >= offer.chunk_count) {
        error = "Chunk index out of range";
        return false;
    }
    const uint64_t offset{
        static_cast<uint64_t>(chunk_index) * static_cast<uint64_t>(offer.chunk_size)};
    if (offset >= offer.file_size) {
        error = "Chunk offset past end of file";
        return false;
    }
    const uint64_t remaining{offer.file_size - offset};
    const size_t to_read{static_cast<size_t>(
        std::min<uint64_t>(remaining, offer.chunk_size))};
    if (to_read > ATTESTED_UTXO_SNAPSHOT_MAX_SERVE_BUFFER) {
        error = "Chunk exceeds serve buffer cap";
        return false;
    }

    FILE* file{fsbridge::fopen(offer.snapshot_path, "rb")};
    if (!file) {
        error = "Couldn't open offered snapshot file";
        return false;
    }
    if (fseeko(file, static_cast<off_t>(offset), SEEK_SET) != 0) {
        fclose(file);
        error = "Couldn't seek in offered snapshot file";
        return false;
    }
    out_data.resize(to_read);
    const size_t n{fread(out_data.data(), 1, to_read, file)};
    fclose(file);
    if (n != to_read) {
        out_data.clear();
        error = "Short read from offered snapshot file";
        return false;
    }
    out_chunk_hash = AttestedUTXOSnapshotBytesHash(Span{out_data.data(), out_data.size()});
    return true;
}

bool BuildAttestedUTXOSnapshotOfferFromFiles(const fs::path& snapshot_path,
                                             const fs::path& manifest_path,
                                             uint32_t chunk_size,
                                             AttestedUTXOSnapshotOffer& out,
                                             std::string& error)
{
    if (chunk_size == 0 || chunk_size > ATTESTED_UTXO_SNAPSHOT_MAX_CHUNK_SIZE) {
        error = "Invalid chunk size";
        return false;
    }
    FILE* mfile{fsbridge::fopen(manifest_path, "rb")};
    if (!mfile) {
        error = "Couldn't open manifest file";
        return false;
    }
    AutoFile mafile{mfile};
    matmul::trusted::UtxoSnapshotManifest manifest;
    try {
        mafile >> manifest;
    } catch (const std::exception& e) {
        error = strprintf("Unable to parse manifest: %s", e.what());
        return false;
    }

    FILE* sfile{fsbridge::fopen(snapshot_path, "rb")};
    if (!sfile) {
        error = "Couldn't open snapshot file";
        return false;
    }
    if (fseeko(sfile, 0, SEEK_END) != 0) {
        fclose(sfile);
        error = "Couldn't stat snapshot file";
        return false;
    }
    const off_t sz{ftello(sfile)};
    if (sz < 0) {
        fclose(sfile);
        error = "Couldn't determine snapshot file size";
        return false;
    }
    if (fseeko(sfile, 0, SEEK_SET) != 0) {
        fclose(sfile);
        error = "Couldn't rewind snapshot file";
        return false;
    }

    HashWriter file_hash{};
    // Heap, not stack (see above): avoids RPC-worker stack overflow.
    std::vector<uint8_t> buf(1 << 20);
    uint64_t total{0};
    while (true) {
        const size_t n{fread(buf.data(), 1, buf.size(), sfile)};
        if (n > 0) {
            file_hash.write(AsBytes(Span{buf.data(), n}));
            total += n;
        }
        if (n < buf.size()) {
            if (ferror(sfile)) {
                fclose(sfile);
                error = "Error hashing snapshot file";
                return false;
            }
            break;
        }
    }
    fclose(sfile);
    if (total != static_cast<uint64_t>(sz)) {
        error = "Snapshot size mismatch while hashing";
        return false;
    }

    out.block_hash = manifest.statement.block_hash;
    out.height = manifest.statement.block_height;
    out.file_size = total;
    out.chunk_size = chunk_size;
    out.chunk_count = static_cast<uint32_t>(
        (total + chunk_size - 1) / chunk_size);
    out.file_hash = file_hash.GetHash();
    out.snapshot_path = snapshot_path;
    out.manifest_path = manifest_path;
    out.manifest = std::move(manifest);
    return true;
}

} // namespace node
