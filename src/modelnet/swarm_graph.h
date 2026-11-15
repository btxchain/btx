// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_GRAPH_H
#define BTX_MODELNET_SWARM_GRAPH_H

#include <string>

namespace modelnet {

/**
 * Next-use hints only. Runtime allocators keep residency authority.
 * bytes_moved stays false. This function does not copy a tensor.
 */
struct SwarmWorkHint {
    bool retain_parent{false};
    bool prefetch_child{false};
    bool demote_inactive{false};
    bool prefer_ancestor{false};
    bool bytes_moved{false};
    std::string code;
};

/**
 * retain_parent follows tool_running. prefetch_child is set only when the
 * child is known. A known child with no engine is ENGINE_ABSENT; a known
 * child with an engine is LOCAL. An unknown child leaves the code empty.
 * demote_inactive follows branch_inactive. prefer_ancestor follows
 * shared_ancestor. err is cleared. The call returns the hint.
 */
SwarmWorkHint SwarmPlanWorkGraph(bool tool_running, bool child_known, bool branch_inactive, bool shared_ancestor,
                                 bool engine_present, std::string& err);

/** A causal append leaves the existing prefix unchanged and extends only the suffix. */
struct SwarmPrefixBytes {
    std::string prefix;
    std::string suffix;
};

bool SwarmAppendCausal(const SwarmPrefixBytes& base, const std::string& token, SwarmPrefixBytes& out, std::string& err);

/** A peer may stay passive, disappear, or follow an older generation. */
struct SwarmParticipation {
    bool passive{false};
    bool disappeared{false};
    bool follows_older{false};
    bool community_continues{false};
};

bool SwarmNoteParticipant(SwarmParticipation& row, bool passive, bool disappeared, bool follows_older, bool any_other_active, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_GRAPH_H
