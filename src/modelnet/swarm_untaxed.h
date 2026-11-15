// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_UNTAXED_H
#define BTX_MODELNET_SWARM_UNTAXED_H

#include <string>

namespace modelnet {

/**
 * Local inputs for an inference-tax note.
 * open_license with local_inference is untaxed even when want_tax is true.
 */
struct SwarmInferenceTax {
    std::string license_id;
    bool open_license{false};
    bool local_inference{false};
    bool want_tax{false};
};

/**
 * Outcome of noting an inference tax. taxed is always false: this note
 * does not levy a tax, move atoms, or broadcast.
 */
struct SwarmInferenceTaxResult {
    bool taxed{false};
    std::string code;
};

/**
 * Note an inference tax without levying one.
 * An empty license_id yields LICENSE.
 * Open-license local inference yields UNTAXED and clears err, even when
 * want_tax is true.
 * A request to tax yields TAX_REFUSED.
 * Otherwise the note is NOTED and err is cleared.
 * taxed stays false on every return. This function does not levy a tax,
 * move atoms, or broadcast.
 */
SwarmInferenceTaxResult SwarmNoteInferenceTax(const SwarmInferenceTax& tax, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_UNTAXED_H
