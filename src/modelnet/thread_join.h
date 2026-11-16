// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_THREAD_JOIN_H
#define BITCOIN_MODELNET_THREAD_JOIN_H

#include <thread>

namespace modelnet {

//! Join a worker thread, unless the caller IS that worker. When a job's last
//! owner is released on the job's own worker thread, the job destructor runs
//! there; a plain join() would then join the thread to itself, which throws
//! std::system_error (resource_deadlock_would_occur) from a noexcept
//! destructor and calls std::terminate. Detach in that case: the worker is
//! already finishing, so there is nothing left to wait for.
inline void JoinWorkerUnlessSelf(std::thread& worker)
{
    if (!worker.joinable()) return;
    if (worker.get_id() == std::this_thread::get_id()) {
        worker.detach();
    } else {
        worker.join();
    }
}

} // namespace modelnet

#endif // BITCOIN_MODELNET_THREAD_JOIN_H
