// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_BODYGATE_MANIFEST_H
#define BITCOIN_MODELNET_SWARM_BODYGATE_MANIFEST_H

#include <cstdint>

namespace modelnet {

/**
 * Flat manifest entry count. The count is a number of entries, not a payload.
 * A negative count is not stored. A count above the flat cap is not stored.
 */
class SwarmBodyManifest {
public:
    bool SetEntries(int64_t count);
    int64_t entries() const { return m_entries; }

private:
    int64_t m_entries{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_BODYGATE_MANIFEST_H
