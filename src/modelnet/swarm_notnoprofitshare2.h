// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPROFITSHARE2_H
#define BTX_MODELNET_SWARM_NOTNOPROFITSHARE2_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about one share. profit says the share is a profit share.
 * want_pay asks this note to pay.
 *
 * A profit share is refused and this note pays nothing.
 * paid stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoProfitShare2 {
    std::string share_id;
    bool profit{false};
    bool want_pay{false};
};

/**
 * Outcome of noting a share. paid stays false and atoms stays 0 on
 * every path: a profit share is refused and this note pays nothing.
 */
struct SwarmNotNoProfitShare2Result {
    std::string code;
    bool paid{false};
    int64_t atoms{0};
};

/**
 * Note a share without paying it.
 * Order, first match wins: an empty share_id is SHARE.
 * profit true is NOT_PAID even when want_pay is false.
 * want_pay is HELD. Otherwise the note is NOTED and err is cleared.
 * paid stays false and atoms stays 0 on every path. A profit share is
 * refused and this note pays nothing.
 */
SwarmNotNoProfitShare2Result SwarmNoteNotNoProfitShare2(const SwarmNotNoProfitShare2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPROFITSHARE2_H
