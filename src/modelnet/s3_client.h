// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_S3_CLIENT_H
#define BITCOIN_MODELNET_S3_CLIENT_H

#include <span.h>
#include <univalue.h>
#include <util/fs.h>

#include <cstdint>
#include <istream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace modelnet {

constexpr size_t kCloudStreamChunkBytes = size_t{8} << 20;
constexpr int kS3PresignTtlMaxSeconds = 3600;

enum class CredentialRefKind : uint8_t {
    PATH = 0,
    ENV = 1,
};

struct CredentialRef {
    CredentialRefKind kind{CredentialRefKind::PATH};
    std::string value;
};

struct S3ClientConfig {
    std::string endpoint;
    std::string region{"us-east-1"};
    std::string bucket;
    std::string prefix;
    CredentialRef creds;
    std::optional<CredentialRef> write_creds;
    bool use_fake{true};
    bool allow_http_loopback{false};
    bool allow_link_local{false};
};

struct ParsedS3Endpoint {
    std::string scheme;
    std::string host;
    uint16_t port{0};
    bool has_userinfo{false};
};

struct SigV4Request {
    std::string method{"GET"};
    std::string canonical_uri{"/"};
    std::map<std::string, std::string> query;
    std::map<std::string, std::string> headers;
    std::string payload_sha256_hex;
    std::string access_key_id;
    std::string secret_access_key;
    std::string region{"us-east-1"};
    std::string service{"s3"};
    std::string amz_date;
};

std::string Sha256Hex(Span<const unsigned char> data);
std::string SigV4CanonicalRequest(const SigV4Request& req);
std::string SigV4SignatureHex(const SigV4Request& req);
std::string SigV4AuthorizationHeader(const SigV4Request& req);
std::string SigV4SignedHeaders(const SigV4Request& req);

std::string RedactCloudSecrets(std::string_view text, std::string_view extra_secret = {});

bool ParseS3Endpoint(std::string_view endpoint, ParsedS3Endpoint& out, std::string& err);
bool ValidateS3Endpoint(std::string_view endpoint, bool allow_http_loopback, bool allow_link_local, std::string& err);
bool S3HostBlockedAsMetadata(std::string_view host);
bool LoadS3Secrets(const CredentialRef& ref, std::string& access_key_id, std::string& secret_access_key,
                   std::string& err);

/** OpenSSL classical TLS client transport for S3/R2/MinIO is linked into bitcoin_modelnet. */
bool S3HttpsTransportAvailable();

/** True for 301/302/303/307/308. Callers must fail closed and must not follow Location. */
bool S3HttpRedirectRefused(int status);

/** True when the response must be failed closed (never followed): redirect status or any Location. */
bool S3HttpResponseForbiddenRedirect(int status, std::string_view location);

class FakeS3
{
    mutable std::mutex m_mu;
    std::map<std::string, std::vector<unsigned char>> m_objects;
    std::map<std::string, std::map<std::string, std::string>> m_meta;
    struct Multipart {
        std::string key;
        std::map<int, std::vector<unsigned char>> parts;
    };
    std::map<std::string, Multipart> m_uploads;
    struct Presign {
        std::string key;
        int64_t expires_unix{0};
        std::string signature;
    };
    std::vector<Presign> m_presigns;
    uint64_t m_get{0};
    uint64_t m_put{0};
    uint64_t m_head{0};
    uint64_t m_range{0};
    uint64_t m_multipart{0};
    uint64_t m_presign{0};
    std::string m_access_key_id;
    std::string m_secret_access_key;
    std::string m_region{"us-east-1"};
    std::string m_bucket;
    uint64_t m_upload_seq{0};

public:
    FakeS3();
    ~FakeS3();

    void SetSigningContext(std::string access_key_id, std::string secret_access_key, std::string region,
                           std::string bucket);

    uint64_t GetCount() const;
    uint64_t PutCount() const;
    uint64_t HeadCount() const;
    uint64_t RangeCount() const;
    uint64_t MultipartCount() const;
    uint64_t PresignCount() const;
    size_t ObjectCount() const;
    bool Contains(const std::string& key) const;
    uint64_t ObjectBytes(const std::string& key) const;
    std::vector<std::string> Keys() const;
    std::string Meta(const std::string& key, const std::string& name) const;
    void SetMeta(const std::string& key, const std::string& name, const std::string& value);

    bool Put(const std::string& key, Span<const unsigned char> body, const SigV4Request& signed_req,
             const std::string& signature, std::string& err);
    bool Get(const std::string& key, const SigV4Request& signed_req, const std::string& signature,
             std::vector<unsigned char>& out, std::string& err);
    bool Head(const std::string& key, const SigV4Request& signed_req, const std::string& signature, uint64_t& size,
              std::string& err);
    bool RangeGet(const std::string& key, uint64_t offset, uint64_t length, const SigV4Request& signed_req,
                  const std::string& signature, std::vector<unsigned char>& out, std::string& err);
    bool Delete(const std::string& key, const SigV4Request& signed_req, const std::string& signature, std::string& err);

    bool BeginMultipart(const std::string& key, std::string& upload_id, std::string& err);
    bool UploadPart(const std::string& upload_id, int part, Span<const unsigned char> body, std::string& err);
    bool CompleteMultipart(const std::string& upload_id, std::string& err);
    bool AbortMultipart(const std::string& upload_id, std::string& err);

    void NotePresign(const std::string& key, int64_t expires_unix, const std::string& signature);
    bool GetPresigned(const std::string& url, std::vector<unsigned char>& out, std::string& err);
};

class S3Client
{
    S3ClientConfig m_cfg;
    std::string m_access;
    std::string m_secret;
    std::string m_write_access;
    std::string m_write_secret;
    std::unique_ptr<FakeS3> m_fake;
    bool m_ready{false};
    mutable std::mutex m_mu;
    size_t m_last_put_max_buffer{0};
    uint64_t m_errors{0};
    int64_t m_latency_ms{0};
    bool m_saw_get{false};
    bool m_saw_put{false};

    void WipeSecrets();
    bool EnsureReady(std::string& err) const;
    SigV4Request BaseSigned(const std::string& method, const std::string& key, Span<const unsigned char> body,
                            const std::string& extra_header_name = {}, const std::string& extra_header_value = {},
                            bool write = false) const;
    std::string CanonicalUriFor(const std::string& key) const;
    std::string HostHeader() const;
    std::string AmzDateNow() const;

public:
    S3Client();
    ~S3Client();
    S3Client(const S3Client&) = delete;
    S3Client& operator=(const S3Client&) = delete;

    bool Init(const S3ClientConfig& cfg, std::string& err);

    bool Put(const std::string& key, Span<const unsigned char> body, std::string& err);
    bool PutStream(const std::string& key, std::istream& body, uint64_t content_length, std::string& err);
    bool Get(const std::string& key, std::vector<unsigned char>& out, std::string& err);
    bool Head(const std::string& key, uint64_t& size, std::string& err) const;
    bool RangeGet(const std::string& key, uint64_t offset, uint64_t length, std::vector<unsigned char>& out,
                  std::string& err);
    bool Delete(const std::string& key, std::string& err);
    bool PresignGet(const std::string& key, int ttl_seconds, std::string& url, std::string& err);
    bool FetchPresignedGet(const std::string& url, std::vector<unsigned char>& out, std::string& err);

    UniValue HealthJson() const;
    UniValue ConfigJson() const;

    FakeS3* Fake() { return m_fake.get(); }
    const FakeS3* Fake() const { return m_fake.get(); }
    bool UsesFake() const { return m_fake != nullptr; }
    size_t LastPutMaxBufferBytes() const;
    const std::string& Bucket() const { return m_cfg.bucket; }
    const std::string& Region() const { return m_cfg.region; }
    const std::string& Endpoint() const { return m_cfg.endpoint; }
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_S3_CLIENT_H
