// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/io_executor.h>

namespace modelnet {

IoExecutor::IoExecutor(size_t max_outstanding) : m_max(max_outstanding ? max_outstanding : IO_EXECUTOR_MAX_OUTSTANDING) {}

bool IoExecutor::Submit(std::string& err)
{
    if (m_outstanding >= m_max) {
        err = "io executor full";
        return false;
    }
    ++m_outstanding;
    return true;
}

void IoExecutor::Complete()
{
    if (m_outstanding > 0) --m_outstanding;
}

void IoExecutor::Drain()
{
    m_outstanding = 0;
}

UniValue IoExecutor::StatusJson() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("outstanding", static_cast<int>(m_outstanding));
    o.pushKV("max_outstanding", static_cast<int>(m_max));
    o.pushKV("io_uring", false);
    return o;
}

} // namespace modelnet
