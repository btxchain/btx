// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/readfence.h>

#include <modelnet/swarm_readfence/accept.h>
#include <modelnet/swarm_readfence/place.h>
#include <modelnet/swarm_readfence/prefetch.h>
#include <modelnet/swarm_readfence/probe.h>
#include <modelnet/swarm_readfence/read.h>
#include <modelnet/swarm_readfence/revoke.h>

namespace modelnet {

bool SwarmReadFence::Place(const std::string& page, const std::string& family, std::string& err)
{
    return SwarmReadPlace{}.Apply(m_book, page, family, err);
}

bool SwarmReadFence::Probe(const std::string& name, bool present, std::string& err)
{
    return SwarmReadProbe{}.Apply(m_engine, name, present, err);
}

bool SwarmReadFence::Prefetch(const std::string& page, std::string& err)
{
    return SwarmReadPrefetch{}.Apply(m_engine, m_warm, page, err);
}

bool SwarmReadFence::Revoke(const std::string& member, std::string& err)
{
    return SwarmReadRevoke{}.Apply(m_roster, member, err);
}

bool SwarmReadFence::Read(const std::string& member, const std::string& page, std::string& err)
{
    return SwarmReadRead{}.Apply(m_roster, m_book, m_ledger, member, page, err);
}

bool SwarmReadFence::Accept(int64_t size, std::string& err)
{
    return SwarmReadAccept{}.Apply(m_span, size, err);
}

} // namespace modelnet
