// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clockspan/note.h>

#include <modelnet/swarm_clockspan/codes.h>
#include <modelnet/swarm_clockspan/gate.h>
#include <modelnet/swarm_clockspan/span.h>

namespace modelnet {

bool SwarmClockSpanNote::Apply(SwarmClockSpanBook& book, int64_t seconds, std::string& err) const
{
    const std::string refusal = SwarmClockSpanRefusal(book, seconds);
    if (!refusal.empty()) {
        err = refusal;
        return false;
    }
    if (!book.store(seconds)) {
        if (book.noted()) {
            err = kSwarmClockSpanReplay;
        } else if (SwarmClockSpanBelowOne(seconds)) {
            err = kSwarmClockSpanRange;
        } else {
            err = kSwarmClockSpanSpacing;
        }
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
