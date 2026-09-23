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

/** One origin that was tried and failed. StatusJson emits these so a
 *  multi-origin miss is not reported as only the last origin's error. */
struct OriginError {
    std::string type;
    std::string error;
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
    /** Optional file selection for multi-file registry/torrent sources. */
    virtual void SelectFile(const std::string& relative, const std::string& sha384_hex = {})
    {
        (void)relative;
        (void)sha384_hex;
    }
    /**
     * Bind the declared file size and optional per-piece SHA-384 leaves
     * (ChunkLeaf). Whole-file sha384 is applied only when an extent covers the
     * entire file. Each piece Read may come from a different origin.
     */
    virtual void BindFileIdentity(uint64_t size_bytes, const std::vector<std::string>& piece_sha384_hex)
    {
        (void)size_bytes;
        (void)piece_sha384_hex;
    }
    /** Origin types that supplied pieces for the current file, in Read order. */
    virtual std::vector<std::string> PieceOrigins() const { return {}; }
    /** Origins that passed a leaf or whole-file hash check. */
    virtual std::vector<std::string> BoundPieceOrigins() const { return {}; }
    /** True if piece substitution happened without a bound identity. */
    virtual bool OriginsMixedWithoutIdentity() const { return false; }
    /** Per-origin failures from the last Read/Pin attempt, in try order. */
    virtual std::vector<OriginError> OriginErrors() const { return {}; }
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_BYTE_SOURCE_H
