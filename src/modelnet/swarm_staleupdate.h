// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_STALEUPDATE_H
#define BTX_MODELNET_SWARM_STALEUPDATE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-memory local step and hash, plus one pending remote hash.
 * The local step starts at 0 and the local hash starts empty.
 * A local call accepts only the next step and stores that hash.
 * A remote step at or behind the local step is stale and does not
 * replace the local hash. A later remote hash is stored as pending
 * only. bytes_moved stays 0.
 *
 * This record does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or IP.
 */
class SwarmStaleUpdate {
public:
    /**
     * An empty hash is HASH and leaves the local step and hash.
     * step other than the current step plus one is GAP and leaves the
     * local hash. Otherwise the local step and hash are set, err is
     * cleared, and the call returns true.
     */
    bool Local(uint64_t step, const std::string& hash, std::string& err);

    /**
     * An empty hash is HASH and leaves the local hash.
     * step at or behind the local step is STALE and does not change the
     * local hash. Otherwise the hash is recorded as pending only, the
     * local hash is left unchanged, err is cleared, and the call returns
     * true.
     */
    bool Remote(uint64_t step, const std::string& hash, std::string& err);

    /** Current local step. Starts at 0. */
    uint64_t step() const;

    /** Current local hash. Starts empty. */
    const std::string& hash() const;

    /** Pending remote hash. Starts empty. A stale step does not set it. */
    const std::string& pending() const;

    /** Always 0. A stale or pending update moves no bytes. */
    int64_t bytes_moved() const;

private:
    uint64_t m_step{0};
    std::string m_hash;
    std::string m_pending;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_STALEUPDATE_H
