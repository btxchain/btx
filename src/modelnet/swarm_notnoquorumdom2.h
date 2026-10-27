// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOQUORUMDOM2_H
#define BTX_MODELNET_SWARM_NOTNOQUORUMDOM2_H

#include <string>

namespace modelnet {

/**
 * A local note about one quorum. same_domain records that this note
 * shares a trust domain. want_count asks this note to count.
 *
 * The same trust domain is not a quorum. counted stays false on every
 * path.
 */
struct SwarmNotNoQuorumDom2 {
    std::string quorum_id;
    bool same_domain{false};
    bool want_count{false};
};

/**
 * Outcome of noting a quorum. counted stays false on every path. The
 * same trust domain is not a quorum.
 */
struct SwarmNotNoQuorumDom2Result {
    std::string code;
    bool counted{false};
};

/**
 * Note a quorum without counting it. Order, first match wins: an empty
 * quorum_id is QUORUM. same_domain is NOT_QUORUM even when want_count is
 * false. want_count is HELD. Otherwise the note is NOTED and err is
 * cleared. counted stays false on every path. The same trust domain is
 * not a quorum.
 */
SwarmNotNoQuorumDom2Result SwarmNoteNotNoQuorumDom2(const SwarmNotNoQuorumDom2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOQUORUMDOM2_H
