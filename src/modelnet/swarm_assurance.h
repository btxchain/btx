// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ASSURANCE_H
#define BTX_MODELNET_SWARM_ASSURANCE_H

#include <string>

namespace modelnet {

/**
 * A local note about one cumulative channel. channel_id names the
 * channel in this note. want_work_proof asks this note to treat the
 * channel as proof of work.
 *
 * A cumulative channel is not proof of work. work_proof stays false
 * on every path. Nothing is mined and nothing is broadcast. No
 * hostnames or IPs are used.
 */
struct SwarmAssurance {
    std::string channel_id;
    bool want_work_proof{false};
};

/**
 * Outcome of noting a cumulative channel. work_proof stays false on
 * every path: a cumulative channel is not proof of work. assurance is
 * empty when the channel id is missing, and is exactly
 * CUMULATIVE_NOT_WORK_PROOF otherwise.
 */
struct SwarmAssuranceResult {
    bool work_proof{false};
    std::string assurance;
    std::string code;
};

/**
 * Note a cumulative channel without treating it as proof of work.
 * Order, first match wins: an empty channel_id is ASSURANCE.
 * want_work_proof is NOT_WORK_PROOF. Otherwise the note is NOTED and
 * err is clear. work_proof stays false on every path. A cumulative
 * channel is not proof of work. Nothing is mined and nothing is
 * broadcast.
 */
SwarmAssuranceResult SwarmNoteAssurance(const SwarmAssurance& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ASSURANCE_H
