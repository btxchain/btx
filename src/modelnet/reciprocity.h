// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_RECIPROCITY_H
#define BITCOIN_MODELNET_RECIPROCITY_H

#include <modelnet/policy.h>

namespace modelnet {

/** Spec §11.5 surface. ReciprocityLedger lives in policy.h; this header is the
 *  dedicated include for local useful-byte accounting. Third-party
 *  ServiceReceipts never mint credit. */

using ReciprocitySurface = ReciprocityLedger;

} // namespace modelnet

#endif // BITCOIN_MODELNET_RECIPROCITY_H
