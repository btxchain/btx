// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WATCHHOLD_NOTE_H
#define BITCOIN_MODELNET_SWARM_WATCHHOLD_NOTE_H

#include <cstdint>

namespace modelnet {

/**
 * Local memory of a refund that was held.
 * Remember stores the two heights only after the close margin is met.
 * A short margin leaves the note unchanged.
 * built() stays false: the note is not a transaction and it is not broadcast.
 * There is no field for secret bytes.
 */
class SwarmWatchHoldNote {
public:
    bool noted() const;
    bool built() const;
    int64_t height() const;
    int64_t refund_height() const;

    /**
     * Remember a held refund.
     * A short margin is refused and the previous heights stay.
     * On success the heights are replaced and built() is still false.
     */
    bool Remember(int64_t height, int64_t refund_height);

private:
    int64_t m_height{0};
    int64_t m_refund_height{0};
    bool m_noted{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WATCHHOLD_NOTE_H
