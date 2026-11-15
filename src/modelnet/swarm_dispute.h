// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_DISPUTE_H
#define BTX_MODELNET_SWARM_DISPUTE_H

#include <map>
#include <string>

namespace modelnet {

enum class SwarmDisputeState { Open, Evidence, Refused, Accepted };

/**
 * Local dispute record. Accepted is not a settled outpoint.
 * settled stays false, broadcast stays false, and outpoint stays empty.
 * This record does not broadcast.
 */
struct SwarmDispute {
    std::string dispute_id;
    std::string receipt_id;
    SwarmDisputeState state{SwarmDisputeState::Open};
    bool settled{false};
    bool broadcast{false};
    std::string outpoint;
};

/**
 * In-memory dispute book. Open stores an id and a receipt. Evidence moves
 * Open to Evidence. Resolve from Evidence sets Accepted or Refused and does
 * not settle, fill an outpoint, or broadcast.
 */
class SwarmDisputeBook {
public:
    /**
     * An empty id or receipt is DISPUTE. A duplicate id is REPLAY.
     * State is Open. settled is false, broadcast is false, and outpoint
     * is empty.
     */
    bool OpenDispute(const std::string& dispute_id, const std::string& receipt_id, std::string& err);

    /**
     * An unknown id is DISPUTE. Empty evidence is DISPUTE.
     * The first evidence moves Open to Evidence. A later evidence while
     * the state is Evidence succeeds and does not change state.
     */
    bool AddEvidence(const std::string& dispute_id, const std::string& evidence, std::string& err);

    /**
     * Resolve before evidence is EVIDENCE and the state stays Open.
     * Accept from Evidence sets Accepted. Refuse from Evidence sets Refused.
     * settled stays false, broadcast stays false, and outpoint stays empty.
     * Resolve again is REPLAY.
     */
    bool Resolve(const std::string& dispute_id, bool accept, std::string& err);

    /** Local lookup. Does not settle, broadcast, or fill an outpoint. */
    const SwarmDispute* Find(const std::string& dispute_id) const;

private:
    struct Row {
        SwarmDispute dispute;
        std::string evidence;
    };

    std::map<std::string, Row> m_rows;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_DISPUTE_H
