// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PHYSICAL_DEDUP_H
#define BITCOIN_MODELNET_PHYSICAL_DEDUP_H

#include <modelnet/types.h>
#include <span.h>

#include <cstdint>

namespace modelnet {

/** Internal physical key: SHA-384 of payload bytes. Independent of PieceKey/ChunkLeaf. */
Digest48 PhysicalByteDigest(Span<const unsigned char> payload);
/** Content-defined chunking is a different identity scheme. Not shipped. */
bool ContentDefinedDedupShipped();
bool CrossTenantDedupAllowed();
/** Exact same payload at a different piece index may reuse physical bytes. */
bool SamePhysicalBytes(Span<const unsigned char> a, Span<const unsigned char> b);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PHYSICAL_DEDUP_H
