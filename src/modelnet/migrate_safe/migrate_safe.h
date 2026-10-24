// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_MIGRATE_SAFE_MIGRATE_SAFE_H
#define BITCOIN_MODELNET_MIGRATE_SAFE_MIGRATE_SAFE_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** Empty id or empty body. Nothing is stored. */
inline constexpr char MIGRATE_SAFE_FIELD[] = "FIELD";

/** Assurance below zero. Nothing is stored. */
inline constexpr char MIGRATE_SAFE_BOUND[] = "BOUND";

/** Move named an id that is not stored. */
inline constexpr char MIGRATE_SAFE_ID[] = "ID";

/** Claimed assurance is above the stored assurance. The record stays. */
inline constexpr char MIGRATE_SAFE_UPGRADE[] = "UPGRADE";

/** Fail() was set. Move changes nothing until Clear(). */
inline constexpr char MIGRATE_SAFE_JOURNAL[] = "JOURNAL";

/**
 * In-memory migration gate. A move may not raise assurance, and a crash flag
 * keeps the stored body until Clear(). This class opens no file, socket, or
 * process.
 *
 * Store: an empty id or an empty body is FIELD. assurance below 0 is BOUND.
 * Either refusal leaves a previous record unchanged. Success stores body and
 * assurance for id. A later success for the same id replaces both.
 *
 * Move: while Fail() is set, the result is JOURNAL and the stored body and
 * assurance stay. Clear() drops only that flag. An unknown id is ID. A claim
 * above the stored assurance is UPGRADE and keeps the stored assurance and
 * body. A claim equal to the stored assurance returns true and does not change
 * the body. A claim below the stored assurance returns true and also leaves
 * the stored assurance and body unchanged.
 *
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * qualified(), release_qualified(), hardware_qualified(), launched(), gpu(),
 * and broadcast() stay false. hosts() and physical_hosts() stay 1.
 * bytes_moved() stays 0. automatic_spend() is "0".
 */
class MigrateSafe {
public:
    bool Store(const std::string& id, const std::string& body, int64_t assurance, std::string& err);
    bool Move(const std::string& id, int64_t claimed, std::string& err);
    void Fail();
    void Clear();
    bool Release(std::string& err);
    bool Spend(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);

    bool present(const std::string& id) const;
    std::string body(const std::string& id) const;
    int64_t assurance(const std::string& id) const;
    bool failed() const { return m_failed; }

    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Row {
        std::string body;
        int64_t assurance{static_cast<int64_t>(0)};
    };

    std::map<std::string, Row> m_rows;
    bool m_failed{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_MIGRATE_SAFE_MIGRATE_SAFE_H
