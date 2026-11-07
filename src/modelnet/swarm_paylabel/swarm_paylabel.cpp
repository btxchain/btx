// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paylabel/swarm_paylabel.h>

#include <modelnet/swarm_paylabel/accept.h>

namespace modelnet {

bool SwarmPayLabel::Accept(const std::string& label, std::string& err)
{
    return SwarmPayLabelAccept{}.Apply(m_book, label, err);
}

bool SwarmPayLabel::accepted() const
{
    return m_book.accepted();
}

std::string SwarmPayLabel::label() const
{
    return m_book.label();
}

int64_t SwarmPayLabel::atoms() const
{
    return m_quiet.atoms();
}

std::string SwarmPayLabel::automatic_spend() const
{
    return m_quiet.automatic_spend();
}

bool SwarmPayLabel::broadcast() const
{
    return m_quiet.broadcast();
}

int64_t SwarmPayLabel::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

} // namespace modelnet
