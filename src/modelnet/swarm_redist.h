// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REDIST_H
#define BTX_MODELNET_SWARM_REDIST_H

#include <string>

namespace modelnet {

/**
 * A local note about one redistribution request. Publishing and
 * network fetches are not provided.
 */
struct SwarmRedistribute {
    std::string license_id;
    bool download_license{false};
    bool operator_grant{false};
    bool want_redistribute{false};
};

/**
 * A local redistribution note. redistribution_allowed stays false: a
 * note does not publish and does not fetch.
 */
struct SwarmRedistributeResult {
    bool redistribution_allowed{false};
    std::string code;
};

/**
 * Order, first match wins: an empty license_id is GRANT. A request
 * that wants redistribution without an operator grant is
 * NOT_REDISTRIBUTION, including when download_license is also true.
 * A download license alone is not a redistribution grant. A request
 * that wants redistribution is HELD and err is clear. An operator
 * grant in this note still does not allow redistribution. Otherwise
 * the note is NOTED and err is clear. redistribution_allowed stays
 * false on every path. This records a local note. It does not publish
 * and it does not fetch.
 */
SwarmRedistributeResult SwarmNoteRedistribute(const SwarmRedistribute& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REDIST_H
