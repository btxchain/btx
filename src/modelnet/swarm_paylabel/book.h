// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYLABEL_BOOK_H
#define BITCOIN_MODELNET_SWARM_PAYLABEL_BOOK_H

#include <modelnet/swarm_paylabel/record.h>

#include <string>

namespace modelnet {

/**
 * The one label stored by a successful Accept.
 * store refuses a label that is not exactly "work-payment" and refuses
 * a second store. A refused store leaves the first label in place.
 * There is no method that credits atoms or replaces the stored label.
 */
class SwarmPayLabelBook {
public:
    bool contains(const std::string& label) const;
    bool accepted() const;
    /** The stored label, or empty when nothing has been stored. */
    std::string label() const;

    /**
     * Store label when it is exactly "work-payment" and the book is empty.
     * On refusal the book is unchanged.
     */
    bool store(const std::string& label);

private:
    bool m_stored{false};
    SwarmPayLabelRecord m_record;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYLABEL_BOOK_H
