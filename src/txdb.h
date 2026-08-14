// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXDB_H
#define BITCOIN_TXDB_H

#include <coins.h>
#include <dbwrapper.h>
#include <kernel/cs_main.h>
#include <sync.h>
#include <util/fs.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <vector>

class COutPoint;
class uint256;

//! -dbbatchsize default (bytes)
static const int64_t nDefaultDbBatchSize = 64 << 20;

//! User-controlled performance and debug options.
struct CoinsViewOptions {
    //! Maximum database write batch size in bytes.
    size_t batch_write_bytes = nDefaultDbBatchSize;
    //! If non-zero, randomly exit when the database is flushed with (1/ratio)
    //! probability.
    int simulate_crash_ratio = 0;
};

/** CCoinsView backed by the coin database (chainstate/)
 * Cursor requires FlushStateToDisk for consistency.
 */
class CCoinsViewDB final : public CCoinsView
{
protected:
    DBParams m_db_params;
    CoinsViewOptions m_options;
    //! Prevent CompactFull() from using m_db while ResizeCache() replaces it.
    Mutex m_db_mutex;
    std::unique_ptr<CDBWrapper> m_db;
    std::shared_future<void> m_compaction;
    std::atomic<bool> m_compaction_allowed{true};
public:
    explicit CCoinsViewDB(DBParams db_params, CoinsViewOptions options);
    ~CCoinsViewDB() override;

    std::optional<Coin> GetCoin(const COutPoint& outpoint) const override;
    bool HaveCoin(const COutPoint &outpoint) const override;
    uint256 GetBestBlock() const override;
    std::vector<uint256> GetHeadBlocks() const override;
    bool BatchWrite(CoinsViewCacheCursor& cursor, const uint256 &hashBlock) override;
    std::unique_ptr<CCoinsViewCursor> Cursor() const override;

    //! Whether an unsupported database format is used.
    bool NeedsUpgrade();
    size_t EstimateSize() const override;

    //! Dynamically alter the underlying leveldb cache size.
    void ResizeCache(size_t new_cache_size) EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_db_mutex);

    //! Perform a full LevelDB compaction on a one-shot background thread.
    std::shared_future<void> CompactFull() EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_db_mutex);

    //! Refuse to start a new CompactFull (in-flight work is left running).
    void DisableNewCompaction();

    //! Block until any in-flight CompactFull finishes. Does not require cs_main.
    void WaitForCompaction();

    //! @returns filesystem path to on-disk storage or std::nullopt if in memory.
    std::optional<fs::path> StoragePath() { return m_db->StoragePath(); }
};

#endif // BITCOIN_TXDB_H
