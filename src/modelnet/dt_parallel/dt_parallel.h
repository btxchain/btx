// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_PARALLEL_DT_PARALLEL_H
#define BITCOIN_MODELNET_DT_PARALLEL_DT_PARALLEL_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Degree plan for one open step: data, tensor, pipeline, context, and expert.
 * ranks() is the product of those five degrees. physical_hosts() is 1.
 * This is a plan, not a second machine.
 *
 * Plan stores a feasible product when every degree is at least 1 and
 * memory_bytes is within capacity_bytes. A degree below 1 is RANK and
 * stores nothing. memory_bytes above capacity_bytes is MEMORY and stores
 * nothing. Freeze seals that rank set for the open step. A later Plan is
 * FROZEN and does not replace it. Shrink never changes ranks(). After
 * Freeze it returns FROZEN. Commit succeeds only for a frozen feasible
 * plan; otherwise PLAN.
 *
 * gpu() stays false. GpuCollective returns NIFDT_ENGINE_ABSENT and does
 * not change ranks(). launched() and broadcast() stay false.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 */
class DtParallel {
public:
    bool Plan(int64_t dp, int64_t tp, int64_t pp, int64_t cp, int64_t ep, int64_t memory_bytes, int64_t capacity_bytes, std::string& err);
    bool Freeze(std::string& err);
    bool Shrink(int64_t n, std::string& err);
    bool Commit(std::string& err);
    bool GpuCollective(std::string& err);

    int64_t ranks() const { return m_ranks; }
    bool feasible() const { return m_feasible; }
    int physical_hosts() const { return 1; }
    bool gpu() const { return false; }
    bool launched() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    int64_t m_ranks{0};
    bool m_feasible{false};
    bool m_frozen{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_PARALLEL_DT_PARALLEL_H
