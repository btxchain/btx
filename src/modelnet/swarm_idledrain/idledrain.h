// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_IDLEDRAIN_H
#define BITCOIN_MODELNET_SWARM_IDLEDRAIN_H

#include <modelnet/swarm_idledrain/mark.h>
#include <modelnet/swarm_idledrain/realm.h>
#include <modelnet/swarm_idledrain/seat.h>
#include <modelnet/swarm_idledrain/workers.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Idle-drain plane.
 *
 * Battery, thermal, or metered conditions drain workers to zero.
 * A later admit does not raise them.
 *
 * Open starts workers at 1. A second Open is REPLAY and leaves workers
 * at the current count.
 *
 * Admit before any drain increments workers by 1, capped at 64.
 * A request that would pass 64 is CAPPED and adds nothing.
 *
 * Drain takes a reason. The reason must be exactly battery, thermal,
 * or metered. Any other reason is REASON and changes nothing.
 * A matching reason sets workers to 0. A second drain of any matching
 * reason is REPLAY and leaves workers at 0.
 *
 * Admit after a drain returns DRAINED and leaves workers at 0.
 *
 * bytes_moved() is 0. gpu() is false. launched() is false.
 */
class SwarmIdleDrain {
public:
    bool Open(std::string& err);
    bool Admit(std::string& err);
    bool Drain(const std::string& reason, std::string& err);

    bool opened() const { return m_seat.opened(); }
    bool drained() const { return m_mark.set(); }
    int64_t workers() const { return m_workers.count(); }

    int64_t bytes_moved() const { return m_realm.bytes_moved(); }
    bool gpu() const { return m_realm.gpu(); }
    bool launched() const { return m_realm.launched(); }

private:
    SwarmIdleDrainSeat m_seat;
    SwarmIdleDrainMark m_mark;
    SwarmIdleDrainWorkers m_workers;
    SwarmIdleDrainRealm m_realm;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_IDLEDRAIN_H
