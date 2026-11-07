// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SLICE_SOURCE_SLICE_SOURCE_H
#define BITCOIN_MODELNET_SLICE_SOURCE_SLICE_SOURCE_H

#include <modelnet/snapshot_pull/snapshot_pull.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * SliceSource. Pass default-constructs two SnapshotPull objects in this
 * process. On the first, Publish(1, "d1", "body") and Pull(1, "d1")
 * succeed. On the second, Pull(1, "d1") returns SNAPSHOT_PULL_MISMATCH.
 * Hosts(2) on the first returns SNAPSHOT_PULL_HOSTS.
 * hosts() and physical_hosts() stay 1. logical_peers() stays 2.
 * bytes_moved() stays 0.
 * passed(), launched(), gpu(), broadcast(), qualified(), and
 * release_qualified() stay false.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * No socket and no process.
 */
class SliceSource {
public:
    bool Pass(std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);

    bool passed() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t logical_peers() const { return static_cast<int64_t>(2); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
};

} // namespace modelnet

#endif
