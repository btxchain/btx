// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/solver_runtime.h>

#include <util/time.h>

#include <algorithm>

namespace matmul {
namespace {

thread_local uint32_t g_solve_worker_limit{0};
thread_local bool g_solve_has_deadline{false};
thread_local int64_t g_solve_deadline_us{0};

} // namespace

ScopedSolveRuntime::ScopedSolveRuntime(const SolveRuntimeOptions& options)
    : m_previous_worker_limit{g_solve_worker_limit},
      m_previous_has_deadline{g_solve_has_deadline},
      m_previous_deadline_us{g_solve_deadline_us}
{
    g_solve_worker_limit = options.max_worker_threads;
    if (options.time_budget_ms > 0) {
        g_solve_has_deadline = true;
        g_solve_deadline_us =
            GetTime<std::chrono::microseconds>().count() + static_cast<int64_t>(options.time_budget_ms) * 1000;
    } else {
        g_solve_has_deadline = false;
        g_solve_deadline_us = 0;
    }
}

ScopedSolveRuntime::~ScopedSolveRuntime()
{
    g_solve_worker_limit = m_previous_worker_limit;
    g_solve_has_deadline = m_previous_has_deadline;
    g_solve_deadline_us = m_previous_deadline_us;
}

uint32_t ClampSolveWorkerThreads(uint32_t worker_count)
{
    if (g_solve_worker_limit == 0) {
        return worker_count;
    }
    return std::max<uint32_t>(1, std::min(worker_count, g_solve_worker_limit));
}

bool SolveTimeBudgetExpired()
{
    return g_solve_has_deadline &&
        GetTime<std::chrono::microseconds>().count() >= g_solve_deadline_us;
}

} // namespace matmul
