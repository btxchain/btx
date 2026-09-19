// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_BYTE_SOURCE_H
#define BITCOIN_MODELNET_BYTE_SOURCE_H

#include <cstdint>
#include <span.h>
#include <string>
#include <vector>

namespace modelnet {

struct ReadExtent {
    uint64_t offset{0};
    uint64_t length{0};
};

/** Untrusted origin of bytes. Verification lives above storage. */
class ByteSource {
public:
    virtual ~ByteSource() = default;
    virtual bool Pin(std::string& err) = 0;
    virtual bool Read(const ReadExtent& extent, std::vector<unsigned char>& out, uint64_t budget_bytes,
                      std::string& err) = 0;
    virtual std::string Kind() const = 0;
    virtual std::string Locator() const = 0;
    /** Source integrity (HF revision, torrent infohash). Not publisher authorship. */
    virtual std::string SourceIntegrity() const { return {}; }
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_BYTE_SOURCE_H
