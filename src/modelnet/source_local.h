// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SOURCE_LOCAL_H
#define BITCOIN_MODELNET_SOURCE_LOCAL_H

#include <modelnet/byte_source.h>
#include <util/fs.h>

#include <string>
#include <sys/socket.h>
#include <vector>

namespace modelnet {

class LocalFileByteSource : public ByteSource {
    fs::path m_path;
    uint64_t m_size{0};
    bool m_pinned{false};
    std::vector<std::string> m_piece_origins;

public:
    explicit LocalFileByteSource(fs::path path);
    bool Pin(std::string& err) override;
    bool Read(const ReadExtent& extent, std::vector<unsigned char>& out, uint64_t budget_bytes,
              std::string& err) override;
    std::string Kind() const override { return "LOCAL"; }
    std::string Locator() const override;
    std::vector<std::string> PieceOrigins() const override { return m_piece_origins; }
    std::vector<std::string> BoundPieceOrigins() const override { return m_piece_origins; }
};

/** HTTPS locator string gate: no file:/unix:/gopher:, no RFC1918/link-local hosts
 *  in the URL text. Live GET also re-runs AddressIsGlobalUnicast after DNS. */
bool HuggingFaceLocatorAllowed(const std::string& locator, std::string& err);
/** True when the resolved address is globally routable (not loopback/private/ULA/link-local/CGNAT). */
bool AddressIsGlobalUnicast(const sockaddr* sa, socklen_t len);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SOURCE_LOCAL_H
