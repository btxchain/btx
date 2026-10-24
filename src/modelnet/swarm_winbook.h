// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_WINBOOK_H
#define BTX_MODELNET_SWARM_WINBOOK_H

#include <string>

namespace modelnet {

/**
 * A local record of one Windows lifecycle check.
 *
 * A Windows record can see a running VM and still does not pass the
 * lifecycle. passed and started stay false on every path.
 */
struct SwarmWinBook {
    std::string check_id;
    bool vm_running{false};
    bool guest_agent{false};
    bool passthrough{false};
    bool want_pass{false};
};

/**
 * Outcome of recording a Windows lifecycle check.
 * passed and started stay false on every path.
 */
struct SwarmWinBookResult {
    std::string code;
    bool passed{false};
    bool started{false};
};

/**
 * Record a Windows lifecycle check without passing it or starting it.
 * Order, first match wins: an empty check_id is CHECK. passthrough is
 * NOT_STARTED, even when want_pass is false. A missing guest agent is
 * NOT_PASSED. A VM that is not running is ABSENT. want_pass is HELD.
 * Otherwise the record is NOTED and err is cleared.
 * passed and started stay false on every path. A Windows record can see
 * a running VM and still does not pass the lifecycle.
 */
SwarmWinBookResult SwarmRecordWindows(const SwarmWinBook& book, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_WINBOOK_H
