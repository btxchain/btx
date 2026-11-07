// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closemargin.h>

#include <cstdint>

namespace modelnet {

static constexpr int64_t kRequiredCloseMargin = 160;

SwarmCloseMarginResult SwarmNoteCloseMargin(const SwarmCloseMargin& note, std::string& err)
{
    SwarmCloseMarginResult result;
    result.work_started = false;
    if (note.channel_id.empty() || note.height < 0 || note.refund_height < 1) {
        result.work_started = false;
        result.code = "MARGIN";
        err = "MARGIN";
        return result;
    }
    // A close margin other than the required margin is refused. This
    // wins even when new work is requested. Nothing is broadcast.
    if (note.close_margin != kRequiredCloseMargin) {
        result.work_started = false;
        result.code = "MARGIN_REFUSED";
        err = "MARGIN_REFUSED";
        return result;
    }
    // New work stops inside the close margin. Equality stops. This wins
    // even when new work is requested. Nothing is broadcast. The
    // comparison avoids signed overflow: close_margin is 160 here.
    const bool stops = note.refund_height <= note.close_margin ||
                       note.height >= note.refund_height - note.close_margin;
    if (stops) {
        result.work_started = false;
        result.code = "STOP";
        err = "STOP";
        return result;
    }
    if (note.want_new_work) {
        result.work_started = false;
        result.code = "HELD";
        err.clear();
        return result;
    }
    result.work_started = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
