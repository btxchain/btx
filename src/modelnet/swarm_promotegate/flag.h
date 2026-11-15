// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PROMOTEGATE_FLAG_H
#define BITCOIN_MODELNET_SWARM_PROMOTEGATE_FLAG_H

namespace modelnet {

/**
 * Interrupt mark for the staged promotion.
 * The mark stores no id. mark() sets it. clear() drops it.
 * Begin does not take this flag, so replacing the staged candidate
 * leaves the mark as it was.
 */
class SwarmPromoteFlag {
public:
    bool marked() const { return m_marked; }
    void mark();
    void clear();

private:
    bool m_marked{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PROMOTEGATE_FLAG_H
