// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYLABEL_GATE_H
#define BITCOIN_MODELNET_SWARM_PAYLABEL_GATE_H

#include <modelnet/swarm_paylabel/book.h>

#include <string>

namespace modelnet {

/**
 * Refusal code for an Accept that must not store, or empty when the
 * label may be stored.
 * Exactly "profit-share" is REFUSED. Any other label that is not exactly
 * "work-payment", including empty, is LABEL. A work-payment already
 * stored is REPLAY. REFUSED and LABEL are decided before REPLAY.
 * This function does not modify the book.
 */
std::string SwarmPayLabelRefusal(const SwarmPayLabelBook& book, const std::string& label);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYLABEL_GATE_H
