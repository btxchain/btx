// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NICHESLOTS_NICHESLOTS_H
#define BITCOIN_MODELNET_SWARM_NICHESLOTS_NICHESLOTS_H

#include <modelnet/swarm_nicheslots/quiet.h>
#include <modelnet/swarm_nicheslots/table.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Niche slot plane.
 *
 * Niches stay separate. Spending one niche does not change another
 * niche's remaining slots or recorded tasks. This plane does not
 * broadcast and it does not spend real atoms.
 *
 * Open stores a row only for the exact names general, coding, and
 * research. Any other name is NICHE and stores nothing. A first Open
 * with slots below 1 is SLOTS and stores nothing. A second Open of a
 * niche that is already open is REPLAY and leaves the first slot count.
 * Remaining returns the slots still held by that niche, or -1 when the
 * niche was not opened.
 * Spend of an unknown name, or of a name that was not opened, is NICHE
 * and stores nothing. An empty task is TASK and stores nothing. A task
 * already recorded in that niche is REPLAY and does not decrement again.
 * A new task when remaining is 0 is EXHAUSTED and stores nothing.
 * Otherwise that niche alone decrements and the task is recorded there.
 * The same task text may still be spent in a different niche.
 * Move returns NOT_MERGED and leaves both remainings. The task stays
 * where it was recorded.
 * bytes_moved() is 0. broadcast() is false.
 */
class SwarmNicheSlots {
public:
    bool Open(const std::string& niche, int64_t slots, std::string& err);
    int64_t Remaining(const std::string& niche) const;
    bool Spend(const std::string& niche, const std::string& task, std::string& err);
    bool Move(const std::string& task, const std::string& from, const std::string& to, std::string& err);

    std::vector<std::string> tasks(const std::string& niche) const;

    uint64_t bytes_moved() const { return m_quiet.bytes_moved(); }
    bool broadcast() const { return m_quiet.broadcast(); }

private:
    SwarmNicheSlotsTable m_table;
    SwarmNicheSlotsQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NICHESLOTS_NICHESLOTS_H
