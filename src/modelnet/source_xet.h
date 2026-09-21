// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SOURCE_XET_H
#define BITCOIN_MODELNET_SOURCE_XET_H

#include <modelnet/byte_source.h>

#include <map>
#include <string>
#include <vector>

namespace modelnet {

/** CAS reconstruction feeds the same ByteSource sink. It is not a second model identity. */
inline constexpr const char* XET_PROVENANCE_NOTE =
    "xet CAS reconstruction is source bytes, not a second model identity and not publisher authorship";

/** In-memory chunk id -> blob. Production wiring uses a packaged source worker. */
using XetChunkMap = std::map<std::string, std::vector<unsigned char>>;

/**
 * Reconstruct ordered Xet CAS blobs into one sequential byte stream.
 * SourceIntegrity is the CAS reconstruction token, never a fabricated model_id.
 */
class XetByteSource : public ByteSource {
    std::string m_locator;
    std::string m_cas_root;
    std::vector<std::string> m_order;
    XetChunkMap m_chunks;
    uint64_t m_size{0};
    bool m_pinned{false};

public:
    XetByteSource(std::string locator, std::string cas_root);
    void SetChunkMap(XetChunkMap chunks, std::vector<std::string> order);
    bool Pin(std::string& err) override;
    bool Read(const ReadExtent& extent, std::vector<unsigned char>& out, uint64_t budget_bytes,
              std::string& err) override;
    std::string Kind() const override { return "XET"; }
    std::string Locator() const override { return m_locator; }
    std::string SourceIntegrity() const override { return m_cas_root; }
    bool ClaimsModelIdentity() const { return false; }
    uint64_t Size() const { return m_size; }
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SOURCE_XET_H
