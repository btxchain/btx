// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_QAT02_QAT02_H
#define BITCOIN_MODELNET_QAT02_QAT02_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Qat02 covers DT-Q04, DT-Q05, and DT-Q06 and does not qualify them.
 *
 * Pass calls FabricDispatch, PipelineOverlap, and ShardedOptimizer.
 * The first success latches. A later Pass clears err and returns true
 * without calling those methods again.
 *
 * FabricDispatch is the DT-Q04 fabric path. PipelineOverlap is the
 * DT-Q05 stage path. ShardedOptimizer is the DT-Q06 shard path.
 * A name that is not a linked engine returns NIFDT_ENGINE_ABSENT.
 * Every other name returns NIFDT_NO_ROUTE. Both return false and
 * move no bytes. bytes_moved() stays 0.
 *
 * hosts() and physical_hosts() stay 1. Hosts with n other than 1
 * returns HOSTS. passed(), gpu_passed(), release_qualified(),
 * hardware_qualified(), and qualified() stay false.
 * scenario_status() stays NOT_RUN. covered() is true for DT-Q04,
 * DT-Q05, and DT-Q06 only after Pass latches.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 * socket_opened() and device_present() stay false. This class opens
 * no socket and no device.
 */
class Qat02 {
public:
    bool Pass(std::string& err);
    bool FabricDispatch(const std::string& name, std::string& err);
    bool PipelineOverlap(const std::string& name, std::string& err);
    bool ShardedOptimizer(const std::string& name, std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);

    bool covered(const std::string& id) const;
    std::string scenario_status() const { return "NOT_RUN"; }

    bool passed() const { return false; }
    bool gpu_passed() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool qualified() const { return false; }
    bool socket_opened() const { return false; }
    bool device_present() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_done{false};
};

} // namespace modelnet

#endif
