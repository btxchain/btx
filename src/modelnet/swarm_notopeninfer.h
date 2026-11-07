// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTOPENINFER_H
#define BTX_MODELNET_SWARM_NOTOPENINFER_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one inference. license_id names the license.
 * open_license marks an open-license local inference. want_tax asks
 * this note to tax it.
 *
 * Open-license local inference is not taxed. This note moves no atoms.
 * taxed stays false and atoms stays 0 on every path.
 */
struct SwarmNotOpenInfer {
    std::string license_id;
    bool open_license{false};
    bool want_tax{false};
};

/**
 * Outcome of noting an open-license inference. taxed stays false and
 * atoms stays 0 on every path. Open-license local inference is not
 * taxed. This note moves no atoms.
 */
struct SwarmNotOpenInferResult {
    std::string code;
    bool taxed{false};
    int64_t atoms{0};
};

/**
 * Note an open-license inference without taxing it.
 * Order, first match wins: an empty license_id is LICENSE.
 * open_license is NOT_TAXED even when want_tax is false. want_tax is
 * NOT_TAXED. Otherwise the note is NOTED and err is clear.
 * taxed stays false and atoms stays 0 on every path.
 * Open-license local inference is not taxed. This note moves no atoms.
 */
SwarmNotOpenInferResult SwarmNoteNotOpenInfer(const SwarmNotOpenInfer& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTOPENINFER_H
