// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ACCESS_POLICY_H
#define BITCOIN_MODELNET_ACCESS_POLICY_H

#include <modelnet/acl.h>

namespace modelnet {

/** Spec §11.5 surface. ModelAcl never writes BanMan / AddrMan / NoBan. */

using AccessPolicy = ModelAcl;

} // namespace modelnet

#endif // BITCOIN_MODELNET_ACCESS_POLICY_H
