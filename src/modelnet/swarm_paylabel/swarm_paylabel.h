// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYLABEL_H
#define BITCOIN_MODELNET_SWARM_PAYLABEL_H

#include <modelnet/swarm_paylabel/book.h>
#include <modelnet/swarm_paylabel/quiet.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Payment-label plane.
 * work-payment is accepted. profit-share is refused. Nothing is spent.
 *
 * Accept stores a label only when it is exactly "work-payment".
 * That call returns true and clears err.
 * A label exactly "profit-share" is REFUSED and stores nothing.
 * Any other label, including empty, is LABEL and stores nothing.
 * A second Accept of "work-payment" is REPLAY and keeps the first.
 * REFUSED and LABEL are decided before REPLAY.
 *
 * atoms() stays 0. automatic_spend() stays "0".
 * broadcast() stays false. bytes_moved() stays 0.
 */
class SwarmPayLabel {
public:
    bool Accept(const std::string& label, std::string& err);

    /** True when "work-payment" has been stored. */
    bool accepted() const;

    /** The stored label, or empty when nothing has been stored. */
    std::string label() const;

    /** Stays 0. Nothing is spent. */
    int64_t atoms() const;

    /** Stays the string "0". */
    std::string automatic_spend() const;

    /** Always false. Nothing is broadcast. */
    bool broadcast() const;

    /** Always 0. Nothing is sent. */
    int64_t bytes_moved() const;

private:
    SwarmPayLabelBook m_book;
    SwarmPayLabelQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYLABEL_H
