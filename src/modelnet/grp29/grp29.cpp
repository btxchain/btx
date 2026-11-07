// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp29/grp29.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool Grp29::Store(int64_t amount, std::string& err)
{
    if (amount < static_cast<int64_t>(1)) {
        err = GRP29_BYTES;
        return false;
    }
    m_n = amount;
    m_have = true;
    err.clear();
    return true;
}

bool Grp29::FailWorker(std::string& err)
{
    m_worker_failed = true;
    err.clear();
    return true;
}

bool Grp29::Advance(bool journal_ok, std::string& err)
{
    if (!m_have) {
        err = GRP29_ORDER;
        return false;
    }
    if (!journal_ok) {
        err = GRP29_JOURNAL;
        return false;
    }
    if (m_generation != static_cast<int64_t>(0)) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_generation = static_cast<int64_t>(1);
    err.clear();
    return true;
}

bool Grp29::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp29::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp29::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp29::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

} // namespace modelnet
