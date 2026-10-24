// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_bodygate/join.h>

#include <modelnet/swarm_bodygate/lastmark.h>
#include <modelnet/swarm_bodygate/limits.h>
#include <modelnet/swarm_bodygate/span.h>

namespace modelnet {

SwarmBodyJoinView SwarmBodyEvaluateJoin(const std::map<int64_t, SwarmBodyPiece>& pieces, int64_t stored_bytes)
{
    SwarmBodyJoinView view;
    view.joined = false;
    view.bytes = 0;
    view.bytes_moved = 0;
    if (!SwarmBodyIndexesContiguous(pieces)) {
        view.code = kSwarmBodyGateGap;
        return view;
    }
    if (!SwarmBodyLastIsHighest(pieces)) {
        view.code = kSwarmBodyGateLast;
        return view;
    }
    view.joined = true;
    view.code = kSwarmBodyGateOk;
    view.bytes = stored_bytes;
    view.bytes_moved = 0;
    return view;
}

} // namespace modelnet
