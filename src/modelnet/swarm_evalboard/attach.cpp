// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalboard/attach.h>

#include <modelnet/swarm_evalboard/codes.h>

namespace modelnet {

bool SwarmEvalAttachGate::Attach(const std::string& subject, bool accepted, std::string& err)
{
    if (m_regressed.count(subject) != 0) {
        err = kSwarmEvalRegression;
        return false;
    }
    if (!accepted) {
        err = kSwarmEvalAttach;
        return false;
    }
    m_attached.insert(subject);
    err.clear();
    return true;
}

bool SwarmEvalAttachGate::Regress(const std::string& subject, std::string& err)
{
    m_regressed.insert(subject);
    err = kSwarmEvalRegression;
    return false;
}

bool SwarmEvalAttachGate::attached(const std::string& subject) const
{
    return m_attached.count(subject) != 0;
}

bool SwarmEvalAttachGate::regressed(const std::string& subject) const
{
    return m_regressed.count(subject) != 0;
}

} // namespace modelnet
