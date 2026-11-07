// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_schedlive/dt_schedlive.h>

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <limits>
#include <string>

namespace modelnet {

bool DtSchedLive::Reserve(int64_t bytes, std::string& err)
{
    if (bytes < static_cast<int64_t>(1)) {
        err = DT_SCHEDLIVE_BYTES;
        return false;
    }
    if (bytes > DT_SCHEDLIVE_CAPACITY_BYTES) {
        err = DT_SCHEDLIVE_CAPACITY;
        return false;
    }
    if (m_physical > std::numeric_limits<int64_t>::max() - bytes) {
        err = DT_SCHEDLIVE_CAPACITY;
        return false;
    }
    const int64_t sum = m_physical + bytes;
    if (sum > DT_SCHEDLIVE_CAPACITY_BYTES) {
        err = DT_SCHEDLIVE_CAPACITY;
        return false;
    }
    m_physical = sum;
    m_had_reserve = true;
    m_quiesced = false;
    err.clear();
    return true;
}

bool DtSchedLive::Schedule(std::string& err)
{
    if (!m_had_reserve) {
        err = DT_SCHEDLIVE_ORDER;
        return false;
    }
    if (m_scheduled) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_scheduled = true;
    err.clear();
    return true;
}

bool DtSchedLive::Cancel(std::string& err)
{
    m_canceled = true;
    err.clear();
    return true;
}

bool DtSchedLive::Quiesce(std::string& err)
{
    if (!m_canceled) {
        err = DT_SCHEDLIVE_ORDER;
        return false;
    }
    m_quiesced = true;
    err.clear();
    return true;
}

bool DtSchedLive::Release(std::string& err)
{
    if (!m_quiesced) {
        err = DT_SCHEDLIVE_PINNED;
        return false;
    }
    m_physical = static_cast<int64_t>(0);
    err.clear();
    return true;
}

bool DtSchedLive::FailWorker(std::string& err)
{
    m_worker_failed = true;
    err.clear();
    return true;
}

bool DtSchedLive::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
