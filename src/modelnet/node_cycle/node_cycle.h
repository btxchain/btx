// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NODE_CYCLE_NODE_CYCLE_H
#define BITCOIN_MODELNET_NODE_CYCLE_NODE_CYCLE_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp25/grp25.h>
#include <modelnet/grp26/grp26.h>
#include <modelnet/grp27/grp27.h>
#include <modelnet/grp28/grp28.h>
#include <modelnet/grp29/grp29.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * One bounded pass over node behaviors 1 through 12.
 * Run calls Grp25, Grp26, Grp27, Grp28, and Grp29 in that order and records
 * a step name only after that step holds. A failed step returns that step's
 * error and records no later name.
 *
 * form: hosts() is 1 and launched() is false.
 * workload: Grp25 opens memory, prompts a public nine-character text, and
 * pulls until DONE with text size 8.
 * accelerate: Grp26 echoes a public prompt and stops at 8 bytes.
 * experience: Grp26 steps once and pairs() is 8.
 * compare: Grp27 compares 5 with 5 and agrees. gpu() stays false.
 * descendants: Grp27 grades one domain and returns NOT_QUORUM.
 * measure: Grp27 grades the same author and evaluator and returns SELF.
 * graduate: Grp28 promotes before qualification and returns NOT_GRADUATED.
 * stage: Grp28 stages that candidate and returns NOT_GRADUATED.
 * pay: Grp28 opens two different pools and PayWork stays HELD.
 * failure: Grp29 stores 40 and FailWorker keeps 40. monetary_ok() stays true.
 * generation: Grp29 Advance(false) is JOURNAL and generation() stays 0.
 *
 * Run does not call Advance(true). AcceptJournal() may advance once.
 * Run does not call Adopt.
 *
 * qualified(), release_qualified(), hardware_qualified(), launched(), gpu(),
 * and broadcast() stay false even when a called engine agrees.
 * hosts() and physical_hosts() are 1. bytes_moved() is 0.
 * Spend returns NIFDT_AUTOMATIC_SPEND. Vendor and Gpu return
 * NIFDT_ENGINE_ABSENT. passed() stays false.
 * No socket, no process, and no broadcast.
 */
class NodeCycle {
public:
    bool Run(std::string& err);
    bool AcceptJournal(std::string& err);

    const std::vector<std::string>& steps() const { return m_steps; }

    int64_t stored() const { return m_grp29.stored(); }
    bool worker_failed() const { return m_grp29.worker_failed(); }
    bool monetary_ok() const { return m_grp29.monetary_ok(); }
    int64_t generation() const { return m_grp29.generation(); }

    bool Vendor(std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Spend(std::string& err);

    bool passed() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int hosts() const { return 1; }
    int physical_hosts() const { return 1; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool Closed() const;
    bool Claim(const char* name, std::string& err);

    Grp25 m_grp25;
    Grp26 m_grp26;
    Grp27 m_grp27;
    Grp28 m_grp28;
    Grp29 m_grp29;
    std::vector<std::string> m_steps;
    bool m_started{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NODE_CYCLE_NODE_CYCLE_H
