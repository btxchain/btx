// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/claim.h>

#include <modelnet/swarm_natpub/codes.h>
#include <modelnet/swarm_natpub/gate.h>
#include <modelnet/swarm_natpub/hold.h>

namespace modelnet {

bool SwarmNatPubClaim::Apply(SwarmNatPubBook& book,
                             SwarmNatPubShelf& shelf,
                             const std::string& endpoint,
                             std::string& err) const
{
    const SwarmNatPubDecision decision = SwarmNatPubDecide(book, endpoint);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(endpoint) || !book.contains(endpoint)) {
        if (book.contains(endpoint)) {
            err = std::string{kSwarmNatPubReplay};
        } else {
            err = std::string{kSwarmNatPubEndpoint};
        }
        return false;
    }
    // Stored. A claimed endpoint is not published.
    (void)shelf.mark(endpoint);
    err = SwarmNatPubHold{}.code();
    return false;
}

} // namespace modelnet
