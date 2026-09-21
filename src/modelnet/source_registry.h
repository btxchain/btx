// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SOURCE_REGISTRY_H
#define BITCOIN_MODELNET_SOURCE_REGISTRY_H

#include <modelnet/byte_source.h>
#include <modelnet/import_plan.h>

#include <functional>
#include <string>
#include <vector>

namespace modelnet {

inline constexpr const char* REGISTRY_PROVENANCE_NOTE =
    "registry snapshot is source integrity, not publisher authorship";

using RegistryGetFn = std::function<bool(const std::string& url, uint64_t offset, uint64_t length,
                                         std::vector<unsigned char>& out, std::string& err)>;

/** Test hook: intercept HTTPS. Does not disable SSRF on Pin. */
void SetRegistryGetForTests(RegistryGetFn fn);
void ClearRegistryGetForTests();
void InjectRegistryUrlBytes(const std::string& url, std::vector<unsigned char> bytes);
void InjectRegistryOriginBytes(const std::string& origin_type, std::vector<unsigned char> bytes);
void InjectRegistryOriginError(const std::string& origin_type);
void ClearRegistryInjections();
bool LiveRegistryWanEnabled();

/**
 * One registry origin. Pin/SSRF via HuggingFaceLocatorAllowed (generic HTTPS gate).
 * Read uses injected bytes, the test GET hook, or live HTTPS when live_wan is set.
 * Never follows redirects. A registry name is not the artifact identity.
 */
class RegistryByteSource : public ByteSource {
    ImportOrigin m_origin;
    std::string m_file;
    std::string m_sha384_hex;
    uint64_t m_size_bytes{0};
    std::vector<std::string> m_piece_hex;
    bool m_live_wan{false};
    bool m_pinned{false};
    std::string m_last_url;
    std::vector<std::string> m_piece_origins;

public:
    RegistryByteSource(ImportOrigin origin, bool live_wan);
    void SelectFile(const std::string& relative, const std::string& sha384_hex = {}) override;
    void BindFileIdentity(uint64_t size_bytes, const std::vector<std::string>& piece_sha384_hex) override;
    bool Pin(std::string& err) override;
    bool Read(const ReadExtent& extent, std::vector<unsigned char>& out, uint64_t budget_bytes,
              std::string& err) override;
    std::string Kind() const override;
    std::string Locator() const override { return m_origin.locator; }
    std::string SourceIntegrity() const override { return m_origin.snapshot_token; }
    std::string LastUrl() const { return m_last_url; }
    std::vector<std::string> PieceOrigins() const override { return m_piece_origins; }
};

/**
 * Acquisition as routing: each Read extent (typically one PIECE_SIZE piece) is
 * satisfied by the first origin that returns bytes matching optional sha384.
 * Origins are disposable. Name equality is never a substitute for hashes.
 */
class MultiOriginByteSource : public ByteSource {
    ImportPlan m_plan;
    std::string m_file;
    std::string m_sha384_hex;
    uint64_t m_size_bytes{0};
    std::vector<std::string> m_piece_hex;
    std::string m_last_origin;
    std::vector<std::string> m_conflicts;
    std::vector<std::string> m_piece_origins;

public:
    explicit MultiOriginByteSource(ImportPlan plan);
    void SelectFile(const std::string& relative, const std::string& sha384_hex = {}) override;
    void BindFileIdentity(uint64_t size_bytes, const std::vector<std::string>& piece_sha384_hex) override;
    bool Pin(std::string& err) override;
    bool Read(const ReadExtent& extent, std::vector<unsigned char>& out, uint64_t budget_bytes,
              std::string& err) override;
    std::string Kind() const override { return "MULTI_ORIGIN"; }
    std::string Locator() const override;
    std::string SourceIntegrity() const override;
    std::string LastOriginType() const { return m_last_origin; }
    const std::vector<std::string>& Conflicts() const { return m_conflicts; }
    std::vector<std::string> PieceOrigins() const override { return m_piece_origins; }
    int IndependentOriginCount() const;
};

class S3OriginByteSource : public ByteSource {
    ImportOrigin m_origin;
    std::vector<unsigned char> m_injected;
    bool m_has_injected{false};
    bool m_pinned{false};

public:
    explicit S3OriginByteSource(ImportOrigin origin);
    void InjectTestBytes(std::vector<unsigned char> bytes);
    bool Pin(std::string& err) override;
    bool Read(const ReadExtent& extent, std::vector<unsigned char>& out, uint64_t budget_bytes,
              std::string& err) override;
    std::string Kind() const override { return "S3"; }
    std::string Locator() const override { return m_origin.locator; }
    std::string SourceIntegrity() const override { return m_origin.snapshot_token; }
};

class BtxOriginByteSource : public ByteSource {
    ImportOrigin m_origin;
    std::vector<unsigned char> m_injected;
    bool m_has_injected{false};
    bool m_pinned{false};

public:
    explicit BtxOriginByteSource(ImportOrigin origin);
    void InjectTestBytes(std::vector<unsigned char> bytes);
    bool Pin(std::string& err) override;
    bool Read(const ReadExtent& extent, std::vector<unsigned char>& out, uint64_t budget_bytes,
              std::string& err) override;
    std::string Kind() const override { return "BTX"; }
    std::string Locator() const override { return m_origin.locator; }
    std::string SourceIntegrity() const override { return m_origin.snapshot_token; }
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SOURCE_REGISTRY_H
