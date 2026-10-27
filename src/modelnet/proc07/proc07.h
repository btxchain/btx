// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PROC07_PROC07_H
#define BITCOIN_MODELNET_PROC07_PROC07_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_discover/swarm_discover.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Proc07 implements P2P-SCN-Q.
 *
 * Optional cloud integration stays off for a local run. Local discovery,
 * local task assignment, and local integer inference still complete.
 * RunLocal(true) returns CLOUD and writes none of the three ok flags.
 * That path returns before any SwarmDiscover call.
 *
 * RunLocal(false) offers, grants, and uses peer local-worker, scope lan,
 * endpoint local, until_ms 100, now_ms 0. A failed Offer or Grant returns
 * that error and leaves discovery_ok false. The stored task id is task-1.
 * An empty id would be FIELD. Local inference stores 2 * 3 + 1. cloud_used()
 * stays false. A later RunLocal(false) returns true and skips another Offer.
 *
 * AskCloud refuses. An empty provider is FIELD. A non-empty provider is
 * ABSENT. AskCloud leaves an ok flag that is already true.
 *
 * passed(), release_qualified(), gpu_passed(), windows_passed(), and
 * hardware_qualified() stay false. automatic_spend() is
 * NIFDT_AUTOMATIC_SPEND. connected() on the discover object stays false.
 * The endpoint word is local. Scan stays uncalled.
 */
class Proc07 {
public:
    bool RunLocal(bool cloud_enabled, std::string& err);
    bool AskCloud(const std::string& provider, std::string& err);

    bool discovery_ok() const { return m_discovery_ok; }
    bool assignment_ok() const { return m_assignment_ok; }
    bool inference_ok() const { return m_inference_ok; }
    bool cloud_used() const { return m_cloud_used; }

    const std::string& task_id() const { return m_task_id; }
    int64_t output() const { return m_output; }
    const SwarmDiscover& discover() const { return m_discover; }

    bool passed() const { return false; }
    bool release_qualified() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool hardware_qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool DiscoverLocal(std::string& err);
    bool AssignTask(const std::string& task_id, std::string& err);

    bool m_discovery_ok{false};
    bool m_assignment_ok{false};
    bool m_inference_ok{false};
    bool m_cloud_used{false};
    bool m_local{false};
    std::string m_task_id;
    int64_t m_output{0};
    SwarmDiscover m_discover;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_PROC07_PROC07_H
