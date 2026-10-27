// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FLAGSHIP_SLOT_H
#define BITCOIN_MODELNET_SWARM_FLAGSHIP_SLOT_H

#include <string>

namespace modelnet {

/**
 * One flagship stage's evidence id.
 * Empty means the stage has no evidence. store keeps the first non-empty
 * id and refuses a later write. clear drops the id. This cell has no
 * pass bit: holding an evidence id does not pass the stage.
 */
class SwarmFlagshipSlot {
public:
    bool recorded() const;
    const std::string& evidence() const;

    /**
     * Store evidence when this cell is empty and evidence is non-empty.
     * A second write returns false and leaves the first id in place.
     */
    bool store(const std::string& evidence);

    /** Drop the evidence id. The cell is unrecorded afterwards. */
    void clear();

private:
    std::string m_evidence;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FLAGSHIP_SLOT_H
