// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputestay/settle.h>

#include <modelnet/swarm_disputestay/atoms.h>
#include <modelnet/swarm_disputestay/codes.h>
#include <modelnet/swarm_disputestay/hold.h>

namespace modelnet {

bool SwarmDisputeStaySettle::Apply(const SwarmDisputeStayBook& book,
                                    const std::string& dispute,
                                    int64_t atoms,
                                    std::string& err) const
{
    const SwarmDisputeStayHold hold;
    err = hold.refusal(dispute);
    if (dispute.empty()) return false;
    // Unknown ids are HELD and are not inserted. The book is const.
    if (!book.contains(dispute)) return false;

    const int64_t have = book.atoms_of(dispute);
    const int64_t next = SwarmDisputeStayAtoms{}.after(have, atoms);
    // next stays have. A known dispute with atoms below 1 adds nothing.
    // A known dispute with atoms at or above 1 is still held.
    if (next != have || hold.settled()) {
        err = std::string{kSwarmDisputeStayHeld};
        return false;
    }
    return false;
}

} // namespace modelnet
