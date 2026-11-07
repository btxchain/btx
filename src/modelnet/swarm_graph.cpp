// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_graph.h>

namespace modelnet {

SwarmWorkHint SwarmPlanWorkGraph(bool tool_running, bool child_known, bool branch_inactive, bool shared_ancestor,
                                 bool engine_present, std::string& err)
{
    SwarmWorkHint hint;
    hint.retain_parent = tool_running;
    hint.demote_inactive = branch_inactive;
    hint.prefer_ancestor = shared_ancestor;
    hint.bytes_moved = false;
    hint.prefetch_child = false;
    if (child_known) {
        hint.prefetch_child = true;
        hint.code = engine_present ? "LOCAL" : "ENGINE_ABSENT";
    }
    err.clear();
    return hint;
}

bool SwarmAppendCausal(const SwarmPrefixBytes& base, const std::string& token, SwarmPrefixBytes& out, std::string& err)
{
    if (token.empty()) {
        err = "CAUSAL";
        return false;
    }
    out.prefix = base.prefix;
    out.suffix = base.suffix + token;
    err.clear();
    return true;
}

bool SwarmNoteParticipant(SwarmParticipation& row, bool passive, bool disappeared, bool follows_older, bool any_other_active, std::string& err)
{
    row.passive = passive;
    row.disappeared = disappeared;
    row.follows_older = follows_older;
    row.community_continues = any_other_active;
    err.clear();
    return true;
}

} // namespace modelnet
