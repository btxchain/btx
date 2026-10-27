// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourbook.h>

#include <limits>

namespace modelnet {

int64_t* SwarmFourBook::Slot(const std::string& bucket)
{
    if (bucket == "escrow") return &m_escrow;
    if (bucket == "collateral") return &m_collateral;
    if (bucket == "earned") return &m_earned;
    if (bucket == "fees") return &m_fees;
    return nullptr;
}

const int64_t* SwarmFourBook::Slot(const std::string& bucket) const
{
    if (bucket == "escrow") return &m_escrow;
    if (bucket == "collateral") return &m_collateral;
    if (bucket == "earned") return &m_earned;
    if (bucket == "fees") return &m_fees;
    return nullptr;
}

bool SwarmFourBook::Credit(const std::string& bucket, int64_t atoms, std::string& err)
{
    int64_t* slot = Slot(bucket);
    if (slot == nullptr) {
        err = "BUCKET";
        return false;
    }
    if (atoms < 1) {
        err = "ATOMS";
        return false;
    }
    if (*slot > std::numeric_limits<int64_t>::max() - atoms) {
        err = "ATOMS";
        return false;
    }
    *slot += atoms;
    err.clear();
    return true;
}

bool SwarmFourBook::Merge(std::string& err)
{
    err = "NOT_MERGED";
    return false;
}

int64_t SwarmFourBook::Balance(const std::string& bucket) const
{
    const int64_t* slot = Slot(bucket);
    if (slot == nullptr) return 0;
    return *slot;
}

} // namespace modelnet
