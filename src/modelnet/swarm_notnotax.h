// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTAX_H
#define BTX_MODELNET_SWARM_NOTNOTAX_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one license. open_license marks an open-license
 * local inference. want_charge asks this note to charge it.
 *
 * Open-license local inference is not taxed. charged stays false and atoms
 * stays 0 on every path.
 */
struct SwarmNotNoTax {
    std::string license_id;
    bool open_license{false};
    bool want_charge{false};
};

/**
 * Outcome of noting a charge request. charged stays false and atoms stays 0
 * on every path. Open-license local inference is not taxed.
 */
struct SwarmNotNoTaxResult {
    std::string code;
    bool charged{false};
    int64_t atoms{0};
};

/**
 * Note a charge request without charging.
 * Order, first match wins: an empty license_id is LICENSE.
 * open_license is NOT_CHARGED even when want_charge is false.
 * want_charge is NOT_CHARGED. Otherwise the note is NOTED
 * and err is clear. charged stays false and atoms stays 0 on every path.
 * Open-license local inference is not taxed.
 */
SwarmNotNoTaxResult SwarmNoteNotNoTax(const SwarmNotNoTax& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTAX_H
