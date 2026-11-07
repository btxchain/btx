// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_remedy/book.h>

#include <modelnet/swarm_remedy/codes.h>

namespace modelnet {

bool SwarmRemedyBook::Open(int sequence, unsigned char fill, std::string& err)
{
    SwarmRevocation created;
    if (!m_open.Create(sequence, fill, created, err)) {
        return false;
    }
    if (m_opened) {
        err = kSwarmRemedyReplay;
        return false;
    }
    m_current = created;
    m_opened = true;
    err.clear();
    return true;
}

bool SwarmRemedyBook::Supersede(int sequence, unsigned char fill, std::string& err)
{
    if (!m_opened) {
        err = kSwarmRemedyStale;
        return false;
    }
    SwarmRevocation prior;
    SwarmRevocation next;
    if (!m_supersede.Apply(m_current, sequence, fill, prior, next, err)) {
        return false;
    }
    m_prior = prior;
    m_has_prior = true;
    m_current = next;
    err.clear();
    return true;
}

bool SwarmRemedyBook::secret_released() const
{
    if (m_has_prior) {
        return m_prior.released;
    }
    return m_current.released;
}

} // namespace modelnet
