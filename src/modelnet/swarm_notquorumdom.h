// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTQUORUMDOM_H
#define BTX_MODELNET_SWARM_NOTQUORUMDOM_H

#include <string>

namespace modelnet {

/**
 * A local note about one quorum. distinct_evaluators and distinct_domains
 * record whether evaluators and trust domains are distinct. want_settle
 * asks this note to settle.
 *
 * A quorum needs distinct evaluators and distinct trust domains. This
 * note settles nothing. settled stays false and atoms stays 0 on every
 * path.
 */
struct SwarmNotQuorumDom {
    std::string quorum_id;
    bool distinct_evaluators{false};
    bool distinct_domains{false};
    bool want_settle{false};
};

/**
 * Outcome of noting a quorum. settled stays false and atoms stays 0 on
 * every path. A quorum needs distinct evaluators and distinct trust
 * domains. This note settles nothing.
 */
struct SwarmNotQuorumDomResult {
    std::string code;
    bool settled{false};
    int atoms{0};
};

/**
 * Note a quorum without settling it. Order, first match wins: an empty
 * quorum_id is QUORUM. distinct_evaluators false is SAME_EVALUATOR, even
 * when want_settle is false. distinct_domains false is SAME_DOMAIN, even
 * when want_settle is false. want_settle is HELD. Otherwise the note is
 * NOTED and err is clear. settled stays false and atoms stays 0 on every
 * path. A quorum needs distinct evaluators and distinct trust domains.
 * This note settles nothing.
 */
SwarmNotQuorumDomResult SwarmNoteNotQuorumDom(const SwarmNotQuorumDom& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTQUORUMDOM_H
