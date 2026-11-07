// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYLABEL_ACCEPT_H
#define BITCOIN_MODELNET_SWARM_PAYLABEL_ACCEPT_H

#include <modelnet/swarm_paylabel/book.h>

#include <string>

namespace modelnet {

/**
 * Accepts one payment label.
 * Exactly "profit-share" is REFUSED and the book stays as it was.
 * Any other label that is not exactly "work-payment", including empty,
 * is LABEL and the book stays as it was.
 * A second "work-payment" is REPLAY and leaves the first label.
 * Those checks run in that order. A success stores the label and clears err.
 * Nothing is spent.
 */
class SwarmPayLabelAccept {
public:
    bool Apply(SwarmPayLabelBook& book, const std::string& label, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYLABEL_ACCEPT_H
