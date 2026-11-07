// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clockspan/swarm_clockspan.h>

#include <modelnet/swarm_clockspan/deadline.h>
#include <modelnet/swarm_clockspan/note.h>

namespace modelnet {

bool SwarmClockSpan::Note(int64_t seconds, std::string& err)
{
    return SwarmClockSpanNote{}.Apply(m_book, seconds, err);
}

bool SwarmClockSpan::ClaimDeadline(std::string& err)
{
    return SwarmClockSpanDeadline{}.ClaimDeadline(err);
}

bool SwarmClockSpan::noted() const
{
    return m_book.noted();
}

int64_t SwarmClockSpan::spacing() const
{
    return m_book.spacing();
}

bool SwarmClockSpan::mined() const
{
    return m_mine.mined();
}

int64_t SwarmClockSpan::blocks() const
{
    return m_mine.blocks();
}

int64_t SwarmClockSpan::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

bool SwarmClockSpan::broadcast() const
{
    return m_quiet.broadcast();
}

} // namespace modelnet
