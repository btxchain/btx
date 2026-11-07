// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_delay/dt_delay.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <limits>
#include <string>

namespace modelnet {
namespace {

bool FitsInt64(__int128 value)
{
    return value <= static_cast<__int128>(std::numeric_limits<int64_t>::max()) &&
           value >= static_cast<__int128>(std::numeric_limits<int64_t>::min());
}

} // namespace

bool DtDelay::Base(const std::string& id, std::string& err)
{
    if (id.empty()) {
        err = DT_DELAY_BASE;
        return false;
    }
    if (m_have_base) {
        if (id == m_base) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = DT_DELAY_CHANGE;
        return false;
    }
    m_base = id;
    m_have_base = true;
    err.clear();
    return true;
}

bool DtDelay::Delay(int64_t delta, int64_t lag, std::string& err)
{
    if (lag > static_cast<int64_t>(2)) {
        err = DT_DELAY_STALE;
        return false;
    }
    const __int128 sum = static_cast<__int128>(m_pending) + static_cast<__int128>(delta);
    if (!FitsInt64(sum)) {
        err = DT_DELAY_OVERFLOW;
        return false;
    }
    m_pending = static_cast<int64_t>(sum);
    err.clear();
    return true;
}

bool DtDelay::Resume(const std::string& id, std::string& err)
{
    if (!m_have_base || id != m_base) {
        err = DT_DELAY_CHANGE;
        return false;
    }
    if (m_resumed && m_pending == static_cast<int64_t>(0)) {
        err = DT_DELAY_UNCHANGED;
        return false;
    }
    const __int128 sum = static_cast<__int128>(m_head) + static_cast<__int128>(m_pending);
    if (!FitsInt64(sum)) {
        err = DT_DELAY_OVERFLOW;
        return false;
    }
    m_head = static_cast<int64_t>(sum);
    m_pending = static_cast<int64_t>(0);
    m_resumed = true;
    err.clear();
    return true;
}

bool DtDelay::Wan(std::string& err)
{
    err = NIFDT_NO_ROUTE;
    return false;
}

} // namespace modelnet
