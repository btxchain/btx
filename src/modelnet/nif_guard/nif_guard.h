// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_GUARD_NIF_GUARD_H
#define BITCOIN_MODELNET_NIF_GUARD_NIF_GUARD_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-process admission guard.
 *
 * Every refusal returns false, sets err, and inserts nothing. A record
 * already stored is left in place.
 *
 * Leader: an epoch below current_epoch is STALE and is not stored. An
 * epoch that is not below current_epoch stores that id once, so an equal
 * epoch is stored. A second store of the same id is NIFDT_REPLAY and keeps
 * the first epoch.
 *
 * Cohort: now_ms greater than or equal to until_ms is EXPIRED, including
 * equality, and stores nothing. A live window stores that id once. The
 * same id again is NIFDT_REPLAY.
 *
 * Data: revoked true is NIFDT_REVOKED and stores nothing. A live id is
 * stored once. The same id again is NIFDT_REPLAY.
 *
 * Cache: other_tenant different from tenant is TENANT and stores nothing.
 * The same tenant stores one cache key. A later key for that tenant is
 * NIFDT_REPLAY and the first key stays.
 *
 * Receipt: the first id is stored. The same id again is NIFDT_REPLAY and
 * does not add a second receipt.
 *
 * Checkpoint: a body that contains the ASCII PYTHON_PICKLE, or begins with
 * the four bytes 0x7f ELF, is CODE and stores nothing. A short plain vector
 * is stored. executable() stays false.
 *
 * Tensor: rank below 0 is METADATA and stores nothing.
 *
 * Wallet: has_spend_key true is WALLET and stores nothing. This class does
 * not retain a spend key. automatic_spend() stays NIFDT_AUTOMATIC_SPEND.
 *
 * launched(), gpu(), and broadcast() stay false. No socket is opened.
 */
class NifGuard {
public:
    bool Leader(const std::string& id, int64_t epoch, int64_t current_epoch, std::string& err);
    bool Cohort(const std::string& id, int64_t now_ms, int64_t until_ms, std::string& err);
    bool Data(const std::string& id, bool revoked, std::string& err);
    bool Cache(const std::string& tenant, const std::string& key, const std::string& other_tenant, std::string& err);
    bool Receipt(const std::string& id, std::string& err);
    bool Checkpoint(const std::vector<unsigned char>& body, std::string& err);
    bool Tensor(int64_t rank, std::string& err);
    bool Wallet(bool has_spend_key, std::string& err);

    int64_t leader_count() const { return static_cast<int64_t>(m_leaders.size()); }
    bool leader_stored(const std::string& id) const;
    int64_t leader_epoch(const std::string& id) const;

    int64_t cohort_count() const { return static_cast<int64_t>(m_cohorts.size()); }
    bool cohort_stored(const std::string& id) const;

    int64_t data_count() const { return static_cast<int64_t>(m_data.size()); }
    bool data_stored(const std::string& id) const;

    int64_t cache_count() const { return static_cast<int64_t>(m_cache.size()); }
    bool cache_stored(const std::string& tenant) const;
    std::string cache_key(const std::string& tenant) const;

    int64_t receipt_count() const { return static_cast<int64_t>(m_receipts.size()); }
    bool receipt_stored(const std::string& id) const;

    int64_t checkpoint_count() const
    {
        return m_checkpoint_set ? static_cast<int64_t>(1) : static_cast<int64_t>(0);
    }
    const std::vector<unsigned char>& checkpoint() const { return m_checkpoint; }
    bool executable() const { return false; }

    int64_t tensor_count() const { return static_cast<int64_t>(m_ranks.size()); }
    bool tensor_stored(int64_t rank) const;

    int64_t wallet_count() const
    {
        return m_wallet_noted ? static_cast<int64_t>(1) : static_cast<int64_t>(0);
    }
    bool spend_key_held() const { return false; }

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct LeaderRecord {
        std::string id;
        int64_t epoch{0};
    };
    struct CohortRecord {
        std::string id;
        int64_t now_ms{0};
        int64_t until_ms{0};
    };
    struct DataRecord {
        std::string id;
    };
    struct CacheRecord {
        std::string tenant;
        std::string key;
    };
    struct ReceiptRecord {
        std::string id;
    };

    std::vector<LeaderRecord> m_leaders;
    std::vector<CohortRecord> m_cohorts;
    std::vector<DataRecord> m_data;
    std::vector<CacheRecord> m_cache;
    std::vector<ReceiptRecord> m_receipts;
    std::vector<unsigned char> m_checkpoint;
    bool m_checkpoint_set{false};
    std::vector<int64_t> m_ranks;
    bool m_wallet_noted{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_GUARD_NIF_GUARD_H
