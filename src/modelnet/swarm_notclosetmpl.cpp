// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notclosetmpl.h>

#include <string>

namespace modelnet {

SwarmNotCloseTmplResult SwarmNoteNotCloseTmpl(const SwarmNotCloseTmpl& note, std::string& err)
{
    SwarmNotCloseTmplResult result;
    result.closed = false;
    result.broadcast = false;
    // High-speed settlement keeps one close template. This note does not close or broadcast.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.closed = false;
        result.broadcast = false;
        err = "CHANNEL";
        return result;
    }
    if (note.template_count != 1) {
        result.code = "ONE_TEMPLATE";
        result.closed = false;
        result.broadcast = false;
        err = "ONE_TEMPLATE";
        return result;
    }
    if (note.want_close) {
        result.code = "HELD";
        result.closed = false;
        result.broadcast = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.closed = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
