// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_IDENTITY_CHAIN_IDENTITY_CHAIN_H
#define BITCOIN_MODELNET_IDENTITY_CHAIN_IDENTITY_CHAIN_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Open refused an empty id. Nothing is stored. */
inline constexpr char IDENTITY_CHAIN_FIELD[] = "FIELD";

/** Rotate or Recover named an id that was never opened. */
inline constexpr char IDENTITY_CHAIN_IDENTITY[] = "IDENTITY";

/** until_ms is less than or equal to now_ms. The epoch stays. */
inline constexpr char IDENTITY_CHAIN_EXPIRED[] = "EXPIRED";

/** Recover named an epoch below the current epoch. The epoch stays. */
inline constexpr char IDENTITY_CHAIN_STALE[] = "STALE";

/** Recover named an epoch above the current epoch. The epoch stays. */
inline constexpr char IDENTITY_CHAIN_EPOCH[] = "EPOCH";

/**
 * In-process identity epoch.
 *
 * Open stores one id at epoch 1. An empty id is FIELD and stores nothing.
 * A second Open of the same id is NIFDT_REPLAY and keeps the stored epoch.
 *
 * Rotate of an unknown id is IDENTITY and stores nothing. until_ms less
 * than or equal to now_ms is EXPIRED, including equality, and does not
 * advance the epoch. A live window increments that id's epoch by 1.
 *
 * Recover of an unknown id is IDENTITY. The epoch argument must equal the
 * current epoch. A lower epoch is STALE and keeps the current epoch. A
 * higher epoch is EPOCH and keeps the current epoch. An equal epoch
 * returns true and leaves the epoch unchanged.
 *
 * Spend returns false with NIFDT_AUTOMATIC_SPEND. Release returns false
 * with NIFDT_UNQUALIFIED. Vendor and Gpu return false with
 * NIFDT_ENGINE_ABSENT.
 *
 * qualified(), release_qualified(), hardware_qualified(), launched(),
 * gpu(), and broadcast() stay false. hosts() and physical_hosts() stay 1.
 * bytes_moved() stays 0. automatic_spend() is "0".
 *
 * This class opens no file, opens no socket, starts no process, and holds
 * no spend key.
 */
class IdentityChainRecord {
public:
    bool Open(const std::string& id, std::string& err);
    bool Rotate(const std::string& id, int64_t now_ms, int64_t until_ms, std::string& err);
    bool Recover(const std::string& id, int64_t epoch, std::string& err);
    bool Spend(std::string& err);
    bool Release(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);

    bool stored(const std::string& id) const;
    int64_t epoch(const std::string& id) const;

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Record {
        std::string id;
        int64_t epoch{static_cast<int64_t>(0)};
    };

    Record* Find(const std::string& id);
    const Record* Find(const std::string& id) const;

    std::vector<Record> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_IDENTITY_CHAIN_IDENTITY_CHAIN_H
