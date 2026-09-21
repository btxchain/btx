// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/physical_dedup.h>

#include <modelnet/crypto.h>

namespace modelnet {

Digest48 PhysicalByteDigest(Span<const unsigned char> payload)
{
    return DomainHash("BTX/PhysicalByte/v1", payload);
}

bool ContentDefinedDedupShipped()
{
    return false;
}

bool CrossTenantDedupAllowed()
{
    return false;
}

bool SamePhysicalBytes(Span<const unsigned char> a, Span<const unsigned char> b)
{
    if (a.size() != b.size()) return false;
    return PhysicalByteDigest(a) == PhysicalByteDigest(b);
}

} // namespace modelnet
