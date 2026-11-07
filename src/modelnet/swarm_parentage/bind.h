// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PARENTAGE_BIND_H
#define BITCOIN_MODELNET_SWARM_PARENTAGE_BIND_H

#include <modelnet/swarm_parentage/record.h>

#include <string>

namespace modelnet {

/**
 * Decide whether a bind may store a new row.
 * Any empty argument sets err to LINEAGE and leaves created unchanged.
 * When existing is non-null and the four fields match, err is REPLAY and created stays unchanged.
 * When existing is non-null and any field differs, err is CONFLICT and created stays unchanged.
 * existing is const, so the first binding cannot be replaced here.
 * When existing is null and the four fields are complete, created receives the four fields,
 * err is cleared, and the function returns true.
 * The decision does not mark trust, realm promotion, or ExactReplay admission.
 */
bool SwarmParentageDecideBind(const SwarmParentageBinding* existing,
                              const std::string& checkpoint,
                              const std::string& parent,
                              const std::string& recipe,
                              const std::string& dataset,
                              const std::string& license,
                              SwarmParentageBinding& created,
                              std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PARENTAGE_BIND_H
