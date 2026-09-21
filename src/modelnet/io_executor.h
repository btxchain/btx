// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_IO_EXECUTOR_H
#define BITCOIN_MODELNET_IO_EXECUTOR_H

#include <univalue.h>

#include <cstddef>
#include <string>

namespace modelnet {

/** Spec §10: bounded outstanding I/O. Not io_uring; not an unbounded queue. */
inline constexpr size_t IO_EXECUTOR_MAX_OUTSTANDING = 8;

class IoExecutor {
    size_t m_max{IO_EXECUTOR_MAX_OUTSTANDING};
    size_t m_outstanding{0};

public:
    explicit IoExecutor(size_t max_outstanding = IO_EXECUTOR_MAX_OUTSTANDING);
    bool Submit(std::string& err);
    void Complete();
    void Drain();
    size_t Outstanding() const { return m_outstanding; }
    size_t MaxOutstanding() const { return m_max; }
    UniValue StatusJson() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_IO_EXECUTOR_H
