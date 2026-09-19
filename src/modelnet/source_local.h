// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SOURCE_LOCAL_H
#define BITCOIN_MODELNET_SOURCE_LOCAL_H

#include <modelnet/byte_source.h>
#include <util/fs.h>

namespace modelnet {

class LocalFileByteSource : public ByteSource {
    fs::path m_path;
    uint64_t m_size{0};
    bool m_pinned{false};

public:
    explicit LocalFileByteSource(fs::path path);
    bool Pin(std::string& err) override;
    bool Read(const ReadExtent& extent, std::vector<unsigned char>& out, uint64_t budget_bytes,
              std::string& err) override;
    std::string Kind() const override { return "LOCAL"; }
    std::string Locator() const override;
};

/** Hugging Face / HTTP locators: pin policy only. Never follow redirects. SSRF deny. */
bool HuggingFaceLocatorAllowed(const std::string& locator, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SOURCE_LOCAL_H
