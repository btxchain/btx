// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchhold/swarm_watchhold.h>

#include <modelnet/swarm_watchhold/observe.h>
#include <modelnet/swarm_watchhold/refund.h>
#include <modelnet/swarm_watchhold/release.h>

namespace modelnet {

bool SwarmWatchHold::Observe(int64_t sequence, std::string& err)
{
    return SwarmWatchHoldObserve(m_cursor, sequence, err);
}

bool SwarmWatchHold::Release(std::string& err)
{
    return SwarmWatchHoldRelease(err);
}

bool SwarmWatchHold::Refund(int64_t height, int64_t refund_height, std::string& err)
{
    return SwarmWatchHoldRefund(m_cursor, m_note, height, refund_height, err);
}

int64_t SwarmWatchHold::latest() const
{
    return m_cursor.latest();
}

bool SwarmWatchHold::observed() const
{
    return m_cursor.observed();
}

bool SwarmWatchHold::secret_released() const
{
    return m_secret.released();
}

std::size_t SwarmWatchHold::secret_bytes() const
{
    return m_secret.bytes();
}

bool SwarmWatchHold::broadcast() const
{
    return m_silence.broadcast();
}

bool SwarmWatchHold::mined() const
{
    return m_silence.mined();
}

int64_t SwarmWatchHold::bytes_moved() const
{
    return m_silence.bytes_moved();
}

bool SwarmWatchHold::refund_noted() const
{
    return m_note.noted();
}

bool SwarmWatchHold::refund_built() const
{
    return m_note.built();
}

int64_t SwarmWatchHold::noted_height() const
{
    return m_note.height();
}

int64_t SwarmWatchHold::noted_refund_height() const
{
    return m_note.refund_height();
}

} // namespace modelnet
