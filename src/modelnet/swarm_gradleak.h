// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_GRADLEAK_H
#define BTX_MODELNET_SWARM_GRADLEAK_H

#include <string>

namespace modelnet {

/**
 * A decision about exporting a gradient note. This is not a gradient sync
 * and not a measured contribution. contribution and bytes_moved stay false:
 * the function does not move tensors and does not pay anyone.
 */
struct SwarmGradientExport {
    bool allowed{false};
    bool contribution{false};
    bool bytes_moved{false};
    std::string code;
};

/**
 * Order: a raw gradient is GRADIENT_PRIVATE even for a same-tenant authorized
 * caller. The design does not export raw gradients or require WAN gradient
 * synchronization. A claim of hours trained or that gradients were submitted
 * is CONTRIBUTION and is not a payment. A different tenant or an unauthorized
 * caller is TENANT. Otherwise a non-raw same-tenant authorized note is OK.
 * contribution stays false. This function does not move tensors and does not
 * pay anyone.
 */
SwarmGradientExport SwarmExportGradient(bool raw_gradient, bool same_tenant, bool authorized,
                                        bool claims_training_or_gradients, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_GRADLEAK_H
