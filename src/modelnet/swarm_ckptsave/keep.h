// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CKPTSAVE_KEEP_H
#define BITCOIN_MODELNET_SWARM_CKPTSAVE_KEEP_H

#include <modelnet/swarm_ckptsave/book.h>

#include <string>

namespace modelnet {

/**
 * Reads the name already stored.
 * An unknown name reads as empty. This function does not write the book
 * and does not save the request.
 */
class SwarmCkptSaveKeep {
public:
    std::string first(const SwarmCkptSaveBook& book, const std::string& name) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CKPTSAVE_KEEP_H
