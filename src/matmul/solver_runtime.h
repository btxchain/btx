// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MATMUL_SOLVER_RUNTIME_H
#define BTX_MATMUL_SOLVER_RUNTIME_H

#include <cstdint>

namespace matmul {

struct SolveRuntimeOptions {
    uint64_t time_budget_ms{0};
    uint32_t max_worker_threads{0};
};

class ScopedSolveRuntime
{
public:
    explicit ScopedSolveRuntime(const SolveRuntimeOptions& options);
    ~ScopedSolveRuntime();

    ScopedSolveRuntime(const ScopedSolveRuntime&) = delete;
    ScopedSolveRuntime& operator=(const ScopedSolveRuntime&) = delete;

private:
    uint32_t m_previous_worker_limit{0};
    bool m_previous_has_deadline{false};
    int64_t m_previous_deadline_us{0};
};

uint32_t ClampSolveWorkerThreads(uint32_t worker_count);
bool SolveTimeBudgetExpired();

} // namespace matmul

#endif // BTX_MATMUL_SOLVER_RUNTIME_H
