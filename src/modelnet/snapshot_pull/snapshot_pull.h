// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SNAPSHOT_PULL_SNAPSHOT_PULL_H
#define BITCOIN_MODELNET_SNAPSHOT_PULL_SNAPSHOT_PULL_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** An empty digest or body. Nothing is stored. */
inline constexpr char SNAPSHOT_PULL_FIELD[] = "FIELD";

/** sequence < 1. Nothing is stored. */
inline constexpr char SNAPSHOT_PULL_SEQUENCE[] = "SEQUENCE";

/** Unknown digest, or a different body under a published digest. */
inline constexpr char SNAPSHOT_PULL_MISMATCH[] = "MISMATCH";

/** sequence is lower than the published sequence. The body stays. */
inline constexpr char SNAPSHOT_PULL_ROLLBACK[] = "ROLLBACK";

/** n is not 1. This object stays one host. */
inline constexpr char SNAPSHOT_PULL_HOSTS[] = "HOSTS";

/**
 * One host and two logical peers.
 *
 * The peers share this object. They are not two machines.
 * hosts() and physical_hosts() stay 1. logical_peers() stays 2.
 * Hosts(n) with n other than 1 returns HOSTS and changes neither count.
 *
 * Publish stores a body under a digest. An empty digest or body is FIELD.
 * sequence < 1 is SEQUENCE. A different body under an already published
 * digest is MISMATCH and keeps the first body. The same body with a lower
 * sequence is ROLLBACK and keeps the first body and the first sequence.
 * The same body with a higher sequence stores that sequence and keeps the
 * first body.
 *
 * Pull of an unknown digest is MISMATCH. A sequence lower than the
 * published sequence for that digest is ROLLBACK and does not replace the
 * body. A matching digest returns true and records pulled().
 *
 * Replace of a different body under an already published digest is
 * MISMATCH and keeps the first body.
 *
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * qualified(), release_qualified(), hardware_qualified(), launched(),
 * gpu(), and broadcast() stay false. bytes_moved() stays 0.
 * This class opens no socket and spawns no process.
 */
class SnapshotPull {
public:
    bool Publish(int64_t sequence, const std::string& digest, const std::string& body, std::string& err);
    bool Pull(int64_t sequence, const std::string& digest, std::string& err);
    bool Replace(const std::string& digest, const std::string& body, std::string& err);
    bool Hosts(int64_t n, std::string& err);

    bool stored(const std::string& digest) const;
    std::string body(const std::string& digest) const;
    int64_t sequence(const std::string& digest) const;
    int64_t pulled() const { return m_pulled; }

    bool Release(std::string& err);
    bool Spend(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);

    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t logical_peers() const { return static_cast<int64_t>(2); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Row {
        std::string body;
        int64_t sequence{0};
    };
    std::map<std::string, Row> m_rows;
    int64_t m_pulled{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SNAPSHOT_PULL_SNAPSHOT_PULL_H
