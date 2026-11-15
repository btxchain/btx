// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_LIQUIDITY_H
#define BTX_MODELNET_SWARM_LIQUIDITY_H

#include <util/fs.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** One pool's slice of a single shared channel capacity. */
struct SwarmReservation {
    std::string reservation_id;
    std::string pool_id;
    int64_t atoms{0};
    bool frozen{false};
};

/**
 * One channel capacity shared by many pools. A reservation gives one pool a
 * slice. The same atoms cannot be reserved by two pools. Persist renames
 * liquidity.json into place before it returns success, so Load after a
 * restart sees the same rows.
 */
class SwarmLiquidityBook {
public:
    /** capacity > 0, otherwise CAPACITY. A second Open is REOPEN. */
    bool Open(int64_t capacity, std::string& err);
    bool Reserve(const std::string& reservation_id, const std::string& pool_id, int64_t atoms, std::string& err);
    bool Release(const std::string& reservation_id, std::string& err);
    /** Reorg freeze. No new reserves. Existing rows stay reserved. */
    bool Freeze(std::string& err);
    int64_t Reserved() const;
    int64_t Available() const;
    bool Persist(const fs::path& modeldir, std::string& err);
    bool Load(const fs::path& modeldir, std::string& err);

private:
    bool m_open{false};
    bool m_frozen{false};
    int64_t m_capacity{0};
    std::map<std::string, SwarmReservation> m_rows;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_LIQUIDITY_H
