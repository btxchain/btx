// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOOPENLICTAX2_H
#define BTX_MODELNET_SWARM_NOTNOOPENLICTAX2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one inference. license_id names the license.
 * open_local marks an open-license local inference. want_tax asks
 * this note to tax it.
 *
 * Open-license local inference is not taxed. This note moves no atoms.
 * taxed stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoOpenLicTax2 {
    std::string license_id;
    bool open_local{false};
    bool want_tax{false};
};

/**
 * Outcome of noting an open-license inference. taxed stays false and
 * atoms stays 0 on every path. Open-license local inference is not
 * taxed. This note moves no atoms.
 */
struct SwarmNotNoOpenLicTax2Result {
    std::string code;
    bool taxed{false};
    int64_t atoms{0};
};

/**
 * Note an open-license inference without taxing it.
 * Order, first match wins:
 * 1. An empty license_id is LICENSE. taxed stays false, atoms stays 0,
 *    and err is LICENSE.
 * 2. If open_local is true, the note is NOT_TAXED even when want_tax is
 *    false. taxed stays false, atoms stays 0, and err is NOT_TAXED.
 * 3. want_tax is HELD. taxed stays false, atoms stays 0, and err is HELD.
 * 4. Otherwise the note is NOTED and err is cleared. taxed stays false
 *    and atoms stays 0.
 * taxed stays false and atoms stays 0 on every path.
 * Open-license local inference is not taxed. This note moves no atoms.
 */
SwarmNotNoOpenLicTax2Result SwarmNoteNotNoOpenLicTax2(const SwarmNotNoOpenLicTax2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOOPENLICTAX2_H
