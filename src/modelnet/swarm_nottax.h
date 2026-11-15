// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTTAX_H
#define BTX_MODELNET_SWARM_NOTTAX_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one inference. open_license marks an open-license
 * local inference. want_tax asks this note to tax it.
 *
 * Open-license local inference is not taxed. taxed stays false and atoms
 * stays 0 on every path.
 */
struct SwarmNotTax {
    std::string inference_id;
    bool open_license{false};
    bool want_tax{false};
};

/**
 * Outcome of noting a tax request. taxed stays false and atoms stays 0
 * on every path. Open-license local inference is not taxed.
 */
struct SwarmNotTaxResult {
    std::string code;
    bool taxed{false};
    int64_t atoms{0};
};

/**
 * Note a tax request without taxing.
 * Order, first match wins: an empty inference_id is INFERENCE.
 * open_license or want_tax is NOT_TAXED. Otherwise the note is NOTED
 * and err is clear. taxed stays false and atoms stays 0 on every path.
 * Open-license local inference is not taxed.
 */
SwarmNotTaxResult SwarmNoteNotTax(const SwarmNotTax& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTTAX_H
