// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SOURCE_HUGGINGFACE_H
#define BITCOIN_MODELNET_SOURCE_HUGGINGFACE_H

#include <modelnet/byte_source.h>

#include <string>
#include <vector>

namespace modelnet {

/** Hugging Face snapshot pin. Snapshot/revision is source integrity, not authorship. */
inline constexpr const char* HUGGINGFACE_PROVENANCE_NOTE =
    "huggingface snapshot is source integrity, not publisher authorship";

/**
 * Bounded ByteSource for an HF locator. Pin() applies HuggingFaceLocatorAllowed
 * (no file:/unix:/gopher:, no localhost/127.0.0.1/169.254/192.168/[::1], never
 * follow redirects) and records snapshot_token. No live HTTP in this module.
 */
class HuggingFaceByteSource : public ByteSource {
    std::string m_locator;
    std::string m_snapshot_token;
    std::string m_recorded_snapshot;
    bool m_follow_redirects{false};
    bool m_pinned{false};
    bool m_has_injected{false};
    std::vector<unsigned char> m_injected;

public:
    HuggingFaceByteSource(std::string locator, std::string snapshot_token, bool follow_redirects = false);
    bool Pin(std::string& err) override;
    bool Read(const ReadExtent& extent, std::vector<unsigned char>& out, uint64_t budget_bytes,
              std::string& err) override;
    std::string Kind() const override { return "HUGGINGFACE"; }
    std::string Locator() const override { return m_locator; }
    std::string SourceIntegrity() const override { return m_recorded_snapshot; }
    bool FollowsRedirects() const { return false; }
    /** Test-only: supply bytes without a live HTTP client. */
    void InjectTestBytes(std::vector<unsigned char> bytes);
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SOURCE_HUGGINGFACE_H
