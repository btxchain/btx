// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_headkeep.h>

#include <string>

namespace modelnet {

SwarmHeadKeepResult SwarmKeepHeads(const SwarmHeadKeep& head, std::string& err)
{
    SwarmHeadKeepResult result;
    result.hidden = false;
    result.graduated = false;
    // Visible heads stay visible. A majority vote does not hide or graduate one.
    if (head.head_id.empty()) {
        result.code = "HEAD";
        result.hidden = false;
        result.graduated = false;
        result.visible = 0;
        err = "HEAD";
        return result;
    }
    if (head.visible < 1) {
        result.code = "EMPTY";
        result.hidden = false;
        result.graduated = false;
        result.visible = 0;
        err = "EMPTY";
        return result;
    }
    if (head.majority) {
        result.code = "NOT_HIDDEN";
        result.hidden = false;
        result.graduated = false;
        result.visible = head.visible;
        err = "NOT_HIDDEN";
        return result;
    }
    if (head.want_hide || head.want_graduate) {
        result.code = "HELD";
        result.hidden = false;
        result.graduated = false;
        result.visible = head.visible;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.hidden = false;
    result.graduated = false;
    result.visible = head.visible;
    err.clear();
    return result;
}

} // namespace modelnet
