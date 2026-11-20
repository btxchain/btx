// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// CLOUD-01   cloud_01_sigv4_put_get_fakes3
// CLOUD-02   cloud_02_head_range_path_style
// CLOUD-03   cloud_03_creds_0600_env_never_in_json
// CLOUD-04   cloud_04_reject_file_unix_gopher
// CLOUD-05   cloud_05_block_metadata_and_link_local
// CLOUD-06   cloud_06_redact_cloud_secrets
// CLOUD-07   cloud_07_cloud_object_store_source_files
// CLOUD-07b  cloud_07b_cloud_object_store_piece_objects
// CLOUD-07c  cloud_07c_piece_objects_hydrate_incomplete
// CLOUD-08   cloud_08_layout_not_in_identity
// CLOUD-09   cloud_09_presign_get_exact_object
// CLOUD-10   cloud_10_stream_put_over_8mib
// CLOUD-11   cloud_11_health_json_counters
// CLOUD-12   cloud_12_budget_refuse_when_exhausted
// FULLCLOUD-01  fullcloud_01_102400_pieces_one_source_object
// FULLCLOUD-02  fullcloud_02_object_bytes_equal_fileentry
// FULLCLOUD-03  fullcloud_03_layout_change_keys_not_hashes
// FULLCLOUD-10  fullcloud_10_r2_hostname_auto_source_files
// FULLCLOUD-11  fullcloud_11_explicit_r2_custom_domain
// FULLCLOUD-12  fullcloud_12_r2_piece_objects_rejected
// FULLCLOUD-13  fullcloud_13_estimated_gets
// FULLCLOUD-20  fullcloud_20_budget_remaining_in_health
// FULLCLOUD-23  fullcloud_23_source_files_object_key

#include <modelnet/catalog.h>
#include <modelnet/cloud_layout.h>
#include <modelnet/crypto.h>
#include <modelnet/file_stream.h>
#include <modelnet/helper.h>
#include <modelnet/piece_store.h>
#include <modelnet/s3_client.h>
#include <modelnet/s3_store.h>
#include <modelnet/store.h>
#include <crypto/common.h>
#include <crypto/sha384.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <test/modelnet_n02_idem.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/sock.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <boost/test/unit_test.hpp>
#include <test/util/environment.h>

#if !defined(_WIN32)
#include <csignal>
#include <exception>
#include <stdexcept>
#include <sys/resource.h>
#endif
#include <iterator>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <future>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
// Windows headers also define GetObject, which is a model-store method here.
#pragma push_macro("GetObject")
#undef GetObject
#endif

BOOST_FIXTURE_TEST_SUITE(modelnet_cloud_tests, BasicTestingSetup)

namespace {

constexpr char kAccess[] = "AKIATESTKEYNOTREAL00";
constexpr char kSecret[] = "super-secret-cloud-value-xyz";

void WriteCreds(const fs::path& path, const std::string& access, const std::string& secret, bool mode0600)
{
    {
        std::ofstream out(path);
        out << "aws_access_key_id=" << access << "\n";
        out << "aws_secret_access_key=" << secret << "\n";
    }
    auto perms = fs::perms::owner_read | fs::perms::owner_write;
    if (!mode0600) perms |= fs::perms::group_read | fs::perms::others_read;
    fs::permissions(path, perms, fs::perm_options::replace);
}

modelnet::CloudStoreConfig BaseCfg(const fs::path& creds, const std::string& endpoint = "https://acct.r2.cloudflarestorage.com")
{
    modelnet::CloudStoreConfig c;
    c.s3.endpoint = endpoint;
    c.s3.bucket = "btx-models";
    c.s3.prefix = "v1";
    c.s3.region = "auto";
    c.s3.use_fake = true;
    c.s3.creds.kind = modelnet::CredentialRefKind::PATH;
    c.s3.creds.value = fs::PathToString(creds);
    c.provider = modelnet::CloudProvider::AUTO;
    c.layout = modelnet::CloudObjectLayout::AUTO;
    return c;
}

// Positive Windows fixtures use the supported ENV source. Keep BaseCfg's PATH
// source available for permission-refusal checks; never relax product policy.
class ScopedCloudCredentials
{
#ifdef WIN32
    test::ScopedEnvVar m_credentials{"BTX_TEST_CLOUD_FIXTURE_CREDS",
        (std::string{"aws_access_key_id="} + kAccess +
         "\naws_secret_access_key=" + kSecret + "\n").c_str()};
#endif

public:
    modelnet::CloudStoreConfig Config(const fs::path& creds, const std::string& endpoint = "https://acct.r2.cloudflarestorage.com") const
    {
        auto cfg = BaseCfg(creds, endpoint);
#ifdef WIN32
        cfg.s3.creds = {modelnet::CredentialRefKind::ENV, "BTX_TEST_CLOUD_FIXTURE_CREDS"};
#endif
        return cfg;
    }

    std::string RpcRef(const fs::path& creds) const
    {
#ifdef WIN32
        return "env:BTX_TEST_CLOUD_FIXTURE_CREDS";
#else
        return fs::PathToString(creds);
#endif
    }
};

void NoSecrets(const UniValue& v, const std::string& access, const std::string& secret)
{
    const std::string dump = v.write();
    BOOST_CHECK(dump.find(secret) == std::string::npos);
    BOOST_CHECK(dump.find(access) == std::string::npos);
    BOOST_CHECK(dump.find("aws_secret_access_key") == std::string::npos);
    BOOST_CHECK(dump.find("AWS_SECRET_ACCESS_KEY") == std::string::npos);
}

modelnet::Digest48 ArtifactFill(unsigned char b)
{
    modelnet::Digest48 d;
    d.data.fill(b);
    return d;
}


// Exercise the real transport and wait for peer EOF, not just a successful
// response. The loopback server and all waits are bounded on both platforms.
void CheckS3SocketCleanup(bool reject_tls)
{
    const SOCKET handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BOOST_REQUIRE(handle != INVALID_SOCKET);
    Sock listener{handle};
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    BOOST_REQUIRE_EQUAL(listener.Bind(reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    BOOST_REQUIRE_EQUAL(listener.Listen(1), 0);
    socklen_t addr_len = sizeof(addr);
    BOOST_REQUIRE_EQUAL(listener.GetSockName(reinterpret_cast<sockaddr*>(&addr), &addr_len), 0);
    BOOST_REQUIRE(listener.SetNonBlocking());
    const std::vector<unsigned char> payload{'b', 't', 'x', 0, 255};
    auto server = std::async(std::launch::async, [&] {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
        auto ready = [&](const Sock& sock) {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
            Sock::Event occurred{0};
            return remaining.count() > 0 && sock.Wait(remaining, Sock::RECV, &occurred) && (occurred & Sock::RECV);
        };
        if (!ready(listener)) return false;
        auto peer = listener.Accept(nullptr, nullptr);
        if (!peer || !peer->SetNonBlocking()) return false;
        std::string request;
        char buf[4096];
        if (!reject_tls) {
            while (request.find("\r\n\r\n") == std::string::npos) {
                if (!ready(*peer)) return false;
                const auto n = peer->Recv(buf, sizeof(buf), 0);
                if (n <= 0) return false;
                request.append(buf, n);
                if (request.size() > 65536) return false;
            }
            if (request.find("GET /btx-models/loopback-object HTTP/1.1\r\n") != 0) return false;
        }
        CThreadInterrupt interrupt;
        std::string response = reject_tls ? "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" :
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n";
        if (!reject_tls) response.append(reinterpret_cast<const char*>(payload.data()), payload.size());
        peer->SendComplete(Span<const unsigned char>{reinterpret_cast<const unsigned char*>(response.data()), response.size()}, std::chrono::seconds{5}, interrupt);
        // Keep the server socket open: only the client's cleanup can yield EOF.
        size_t drained = 0;
        while (ready(*peer)) {
            const auto n = peer->Recv(buf, sizeof(buf), 0);
            if (n == 0) return true;
            if (n < 0) {
#ifdef WIN32
                const bool reset = WSAGetLastError() == WSAECONNRESET;
#else
                const bool reset = errno == ECONNRESET;
#endif
                // Failed TLS can close with unread plaintext. A reset still
                // proves peer teardown; successful HTTP must yield clean EOF.
                return reject_tls && reset;
            }
            if ((drained += n) > 65536) return false;
        }
        return false;
    });
    test::ScopedEnvVar credentials{"BTX_TEST_S3_SOCKET_CREDS", "aws_access_key_id=fixture-access\naws_secret_access_key=fixture-secret\n"};
    modelnet::S3ClientConfig cfg;
    cfg.endpoint = std::string{reject_tls ? "https://127.0.0.1:" : "http://127.0.0.1:"} + std::to_string(ntohs(addr.sin_port));
    cfg.bucket = "btx-models";
    cfg.region = "auto";
    cfg.use_fake = false;
    cfg.allow_http_loopback = !reject_tls;
    cfg.creds = {modelnet::CredentialRefKind::ENV, "BTX_TEST_S3_SOCKET_CREDS"};
    modelnet::S3Client client;
    std::string err;
    BOOST_REQUIRE_MESSAGE(client.Init(cfg, err), err);
    BOOST_CHECK(!client.UsesFake());
    std::vector<unsigned char> got;
    const bool ok = client.Get("loopback-object", got, err);
    if (reject_tls) {
        BOOST_CHECK(!ok);
        BOOST_CHECK_EQUAL(err, "https handshake failed");
    } else {
        BOOST_CHECK_MESSAGE(ok, err);
        BOOST_CHECK(got == payload);
    }
    BOOST_CHECK(server.get());
}

// A loopback listener for one connection; every wait on it is bounded.
std::unique_ptr<Sock> ListenLoopback(uint16_t& port, SOCKET* raw = nullptr)
{
    const SOCKET handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (handle == INVALID_SOCKET) return nullptr;
    if (raw) *raw = handle;
    auto listener = std::make_unique<Sock>(handle);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof(addr);
    if (listener->Bind(reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || listener->Listen(1) != 0 ||
        listener->GetSockName(reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        return nullptr;
    }
    port = ntohs(addr.sin_port);
    return listener;
}

std::unique_ptr<Sock> AcceptWithin(const Sock& listener, std::chrono::milliseconds wait)
{
    Sock::Event occurred{0};
    if (!listener.Wait(wait, Sock::RECV, &occurred) || !(occurred & Sock::RECV)) return nullptr;
    return listener.Accept(nullptr, nullptr);
}

// A self-signed certificate for 127.0.0.1, written as the only CA the client
// trusts, so the client's TLS checks pass against a loopback server.
struct LoopbackTlsIdentity {
    EVP_PKEY* key{nullptr};
    X509* cert{nullptr};
    ~LoopbackTlsIdentity()
    {
        X509_free(cert);
        EVP_PKEY_free(key);
    }
};

bool MakeLoopbackTlsIdentity(LoopbackTlsIdentity& id, const fs::path& ca_file)
{
    id.key = EVP_EC_gen("P-256");
    id.cert = X509_new();
    if (!id.key || !id.cert) return false;
    X509_set_version(id.cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(id.cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(id.cert), -60);
    X509_gmtime_adj(X509_getm_notAfter(id.cert), 3600);
    X509_set_pubkey(id.cert, id.key);
    X509_NAME* name = X509_get_subject_name(id.cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("127.0.0.1"), -1, -1, 0);
    X509_set_issuer_name(id.cert, name);
    X509V3_CTX v3;
    X509V3_set_ctx_nodb(&v3);
    X509V3_set_ctx(&v3, id.cert, id.cert, nullptr, nullptr, 0);
    for (const auto& [nid, value] : std::vector<std::pair<int, const char*>>{
             {NID_basic_constraints, "critical,CA:TRUE"}, {NID_subject_alt_name, "IP:127.0.0.1"}}) {
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &v3, nid, value);
        if (!ext) return false;
        X509_add_ext(id.cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    if (X509_sign(id.cert, id.key, EVP_sha256()) == 0) return false;
    BIO* out = BIO_new_file(fs::PathToString(ca_file).c_str(), "w");
    if (!out) return false;
    const bool ok = PEM_write_bio_X509(out, id.cert) == 1;
    BIO_free(out);
    return ok;
}

modelnet::S3ClientConfig LoopbackS3Config(const std::string& scheme, uint16_t port)
{
    modelnet::S3ClientConfig cfg;
    cfg.endpoint = scheme + "://127.0.0.1:" + std::to_string(port);
    cfg.bucket = "btx-models";
    cfg.region = "auto";
    cfg.use_fake = false;
    cfg.allow_http_loopback = scheme == "http";
    cfg.creds = {modelnet::CredentialRefKind::ENV, "BTX_TEST_S3_SOCKET_CREDS"};
    return cfg;
}

} // namespace

BOOST_AUTO_TEST_CASE(cloud_01_sigv4_put_get_fakes3)
{
    const ScopedCloudCredentials credentials;
    modelnet::SigV4Request req;
    req.method = "GET";
    req.canonical_uri = "/test.txt";
    req.payload_sha256_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    req.access_key_id = "AKIAIOSFODNN7EXAMPLE";
    req.secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    req.region = "us-east-1";
    req.service = "s3";
    req.amz_date = "20130524T000000Z";
    req.headers["host"] = "examplebucket.s3.amazonaws.com";
    req.headers["range"] = "bytes=0-9";
    req.headers["x-amz-content-sha256"] = req.payload_sha256_hex;
    req.headers["x-amz-date"] = req.amz_date;
    BOOST_CHECK_EQUAL(modelnet::SigV4SignatureHex(req),
                      "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");

    const fs::path creds = m_path_root / "cloud-01-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    modelnet::S3Client client;
    std::string err;
    BOOST_REQUIRE_MESSAGE(client.Init(credentials.Config(creds).s3, err), err);
    const std::vector<unsigned char> body{'b', 't', 'x'};
    BOOST_REQUIRE(client.Put("v1/artifacts/aa/files/0", body, err));
    std::vector<unsigned char> got;
    BOOST_REQUIRE(client.Get("v1/artifacts/aa/files/0", got, err));
    BOOST_CHECK(got == body);
    BOOST_REQUIRE(client.Fake());
    BOOST_CHECK_EQUAL(client.Fake()->PutCount(), 1);
    BOOST_CHECK_EQUAL(client.Fake()->GetCount(), 1);
    BOOST_CHECK(modelnet::S3HttpsTransportAvailable());
}

BOOST_AUTO_TEST_CASE(cloud_02_head_range_path_style)
{
    const ScopedCloudCredentials credentials;
    const fs::path creds = m_path_root / "cloud-02-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    modelnet::S3Client client;
    std::string err;
    BOOST_REQUIRE_MESSAGE(client.Init(credentials.Config(creds).s3, err), err);
    std::vector<unsigned char> body(32, 0x11);
    BOOST_REQUIRE(client.Put("obj", body, err));
    uint64_t size = 0;
    BOOST_REQUIRE(client.Head("obj", size, err));
    BOOST_CHECK_EQUAL(size, 32);
    std::vector<unsigned char> slice;
    BOOST_REQUIRE(client.RangeGet("obj", 4, 8, slice, err));
    BOOST_REQUIRE_EQUAL(slice.size(), 8U);
    BOOST_CHECK_EQUAL(slice[0], 0x11);
    BOOST_CHECK_EQUAL(client.Fake()->HeadCount(), 1);
    BOOST_CHECK_EQUAL(client.Fake()->RangeCount(), 1);
}

BOOST_AUTO_TEST_CASE(cloud_03_creds_0600_env_never_in_json)
{
    const fs::path bad = m_path_root / "cloud-03-bad";
    WriteCreds(bad, kAccess, kSecret, false);
    modelnet::S3Client client;
    std::string err;
    auto cfg = BaseCfg(bad).s3;
    BOOST_CHECK(!client.Init(cfg, err));
    BOOST_CHECK(err.find("0600") != std::string::npos);

    const fs::path good = m_path_root / "cloud-03-good";
    WriteCreds(good, kAccess, kSecret, true);
    cfg.creds.value = fs::PathToString(good);
#ifdef WIN32
    // Windows attributes cannot express owner-only POSIX file permissions.
    BOOST_CHECK(!client.Init(cfg, err));
    BOOST_CHECK_EQUAL(err, "credential file must be mode 0600");
#else
    BOOST_REQUIRE_MESSAGE(client.Init(cfg, err), err);
    NoSecrets(client.HealthJson(), kAccess, kSecret);
    NoSecrets(client.ConfigJson(), kAccess, kSecret);
#endif

    const char* env_name = "BTX_TEST_CLOUD_CREDS_C";
    const std::string body = std::string("aws_access_key_id=") + kAccess + "\naws_secret_access_key=" + kSecret + "\n";
    test::ScopedEnvVar credentials{env_name, body.c_str()};
    modelnet::S3Client env_client;
    auto env_cfg = cfg;
    env_cfg.creds.kind = modelnet::CredentialRefKind::ENV;
    env_cfg.creds.value = env_name;
    BOOST_REQUIRE_MESSAGE(env_client.Init(env_cfg, err), err);
    NoSecrets(env_client.HealthJson(), kAccess, kSecret);
    NoSecrets(env_client.ConfigJson(), kAccess, kSecret);
}

BOOST_AUTO_TEST_CASE(cloud_04_reject_file_unix_gopher)
{
    std::string err;
    BOOST_CHECK(!modelnet::ValidateS3Endpoint("file:///etc/passwd", false, false, err));
    BOOST_CHECK(!modelnet::ValidateS3Endpoint("unix:///tmp/s3.sock", false, false, err));
    BOOST_CHECK(!modelnet::ValidateS3Endpoint("gopher://example.com/1", false, false, err));
    BOOST_CHECK(!modelnet::ValidateS3Endpoint("s3://bucket", false, false, err));
    BOOST_CHECK(!modelnet::ValidateS3Endpoint("http://example.com", false, false, err));
    BOOST_CHECK(modelnet::ValidateS3Endpoint("http://127.0.0.1:9000", true, false, err));
    BOOST_CHECK(modelnet::ValidateS3Endpoint("https://acct.r2.cloudflarestorage.com", false, false, err));
    BOOST_CHECK(!modelnet::ValidateS3Endpoint("https://key:secret@acct.r2.cloudflarestorage.com", false, false, err));
}

BOOST_AUTO_TEST_CASE(cloud_05_block_metadata_and_link_local)
{
    BOOST_CHECK(modelnet::S3HostBlockedAsMetadata("169.254.169.254"));
    BOOST_CHECK(modelnet::S3HostBlockedAsMetadata("metadata.google.internal"));
    BOOST_CHECK(modelnet::S3HostBlockedAsMetadata("metadata"));
    BOOST_CHECK(modelnet::S3HostBlockedAsMetadata("instance-data.ec2.internal"));
    BOOST_CHECK(!modelnet::S3HostBlockedAsMetadata("127.0.0.1"));
    BOOST_CHECK(!modelnet::S3HostBlockedAsMetadata("localhost"));
    std::string err;
    BOOST_CHECK(!modelnet::ValidateS3Endpoint("https://169.254.169.254/latest/meta-data", false, false, err));
    BOOST_CHECK(!modelnet::ValidateS3Endpoint("http://169.254.169.254/", true, false, err));
    BOOST_CHECK(!modelnet::ValidateS3Endpoint("https://metadata.google.internal", false, false, err));
}

BOOST_AUTO_TEST_CASE(cloud_06_redact_cloud_secrets)
{
    const std::string messy = std::string("aws_secret_access_key=") + kSecret +
                              " AKIAIOSFODNN7EXAMPLE X-Amz-Signature=deadbeef";
    const std::string red = modelnet::RedactCloudSecrets(messy, kSecret);
    BOOST_CHECK(red.find(kSecret) == std::string::npos);
    BOOST_CHECK(red.find("AKIAIOSFODNN7EXAMPLE") == std::string::npos);
    BOOST_CHECK(red.find("deadbeef") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cloud_07_cloud_object_store_source_files)
{
    const ScopedCloudCredentials credentials;
    const fs::path creds = m_path_root / "cloud-07-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    modelnet::S3PieceStore store{credentials.Config(creds)};
    std::string err;
    BOOST_REQUIRE_MESSAGE(store.Init(err), err);
    BOOST_CHECK_EQUAL(modelnet::CloudObjectLayoutName(store.Layout()), "SOURCE_FILES");
    const auto art = ArtifactFill(0xab);
    const fs::path src = m_path_root / "cloud-07.bin";
    const std::string payload = "file-entry-bytes";
    {
        std::ofstream out(src, std::ios::binary);
        out << payload;
    }
    BOOST_REQUIRE(store.PutSourceFile(art, 0, src, payload.size(), /*logical_piece_count=*/1, err));
    std::vector<unsigned char> got;
    BOOST_REQUIRE(store.GetSourceFile(art, 0, got, err));
    BOOST_CHECK_EQUAL(std::string(got.begin(), got.end()), payload);
    BOOST_REQUIRE(store.FakeForTests());
    BOOST_CHECK_EQUAL(store.FakeForTests()->ObjectCount(), 1);
}

BOOST_AUTO_TEST_CASE(cloud_07b_cloud_object_store_piece_objects)
{
    const ScopedCloudCredentials credentials;
    const fs::path creds = m_path_root / "cloud-07b-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    auto cfg = credentials.Config(creds, "https://minio.example.test");
    cfg.provider = modelnet::CloudProvider::MINIO;
    cfg.layout = modelnet::CloudObjectLayout::PIECE_OBJECTS;
    modelnet::S3PieceStore store{cfg};
    std::string err;
    BOOST_REQUIRE_MESSAGE(store.Init(err), err);
    BOOST_CHECK_EQUAL(modelnet::CloudObjectLayoutName(store.Layout()), "PIECE_OBJECTS");
    const auto art = ArtifactFill(0xac);
    const fs::path src = m_path_root / "cloud-07b.bin";
    const std::string payload = "piece-object-bytes";
    {
        std::ofstream out(src, std::ios::binary);
        out << payload;
    }
    BOOST_CHECK(!store.PutSourceFile(art, 0, src, payload.size(), 1, err));
    BOOST_REQUIRE(store.PutPieceObjects(art, 0, src, payload.size(), err));
    BOOST_CHECK_EQUAL(store.PieceFileKey(art, 0, 0), modelnet::ObjectKeyPiece("v1", art.Hex(), 0, 0));
    std::vector<unsigned char> got;
    BOOST_REQUIRE(store.GetPieceObject(art, 0, 0, got, err));
    BOOST_CHECK_EQUAL(std::string(got.begin(), got.end()), payload);
    BOOST_REQUIRE(store.FakeForTests());
    BOOST_CHECK_EQUAL(store.FakeForTests()->ObjectCount(), 1);
    BOOST_CHECK(store.FakeForTests()->ObjectBytes(store.PieceFileKey(art, 0, 0)) == payload.size());
}

BOOST_AUTO_TEST_CASE(cloud_07c_piece_objects_hydrate_incomplete)
{
    const ScopedCloudCredentials credentials;
    using namespace modelnet;
    const fs::path dir = m_path_root / "cloud-07c";
    fs::create_directories(dir);
    const fs::path creds = dir / "creds";
    WriteCreds(creds, kAccess, kSecret, true);

    ModelCatalog cat{dir, 8 << 20};
    UniValue cfg(UniValue::VOBJ);
    cfg.pushKV("endpoint", "https://minio.example.test");
    cfg.pushKV("bucket", "btx-models");
    cfg.pushKV("prefix", "v1");
    cfg.pushKV("provider", "MINIO");
    cfg.pushKV("layout", "PIECE_OBJECTS");
    cfg.pushKV("credential_ref", credentials.RpcRef(creds));
    cfg.pushKV("use_fake", true);
    cfg.pushKV("idempotency_key", "cloud-07c-set");
    UniValue params(UniValue::VARR);
    params.push_back(cfg);
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "setcloudstorage");
    req.pushKV("params", params);
    UniValue applied;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, req, applied, code, err), err);
    BOOST_CHECK_EQUAL(applied["layout"].get_str(), "PIECE_OBJECTS");

    const fs::path model = dir / "hydrate-model";
    fs::create_directories(model);
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    {
        std::ofstream out(model / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    UniValue ip(UniValue::VARR);
    ip.push_back(fs::PathToString(model));
    UniValue ireq(UniValue::VOBJ);
    ireq.pushKV("method", "importmodel");
    ireq.pushKV("params", ip);
    UniValue imported;
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, ireq, imported, code, err), err);
    BOOST_REQUIRE(imported["cloud_uploaded"].get_bool());
    BOOST_CHECK_EQUAL(imported["cloud_layout"].get_str(), "PIECE_OBJECTS");
    const std::string uri = imported["uri"].get_str();
    Digest48 artifact, model_id;
    BOOST_REQUIRE(Digest48::FromHex(imported["artifact_id"].get_str(), artifact, err));
    BOOST_REQUIRE(Digest48::FromHex(imported["model_id"].get_str(), model_id, err));
    BOOST_REQUIRE(cat.Store().HasPiece(artifact, 0, 0));
    BOOST_REQUIRE(cat.Store().DeletePiece(artifact, 0, 0, err));
    BOOST_CHECK(!cat.Store().HasPiece(artifact, 0, 0));
    BOOST_REQUIRE_MESSAGE(cat.MarkIncomplete(model_id, true, err), err);
    CatalogEntry local;
    BOOST_REQUIRE(cat.Find(model_id, local));
    BOOST_CHECK(local.incomplete);

    UniValue gp(UniValue::VARR);
    gp.push_back(uri);
    UniValue greq(UniValue::VOBJ);
    greq.pushKV("method", "getmodel");
    greq.pushKV("params", gp);
    UniValue got;
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, greq, got, code, err), err);
    BOOST_REQUIRE(got.exists("cloud_hydrated"));
    BOOST_CHECK(got["cloud_hydrated"].get_bool());
    BOOST_CHECK_GE(got["origin_get_ops"].getInt<int>(), 1);
    BOOST_CHECK(cat.Store().HasPiece(artifact, 0, 0));
    BOOST_CHECK_EQUAL(got["automatic_spend_atoms"].getInt<int64_t>(), 0);
    NoSecrets(got, kAccess, kSecret);
}

BOOST_AUTO_TEST_CASE(cloud_08_layout_not_in_identity)
{
    const std::vector<unsigned char> bytes{'h', 'a', 's', 'h'};
    const auto a = modelnet::DomainHash("BTX/ModelFile/v1", bytes);
    const auto b = modelnet::DomainHash("BTX/ModelFile/v1", bytes);
    BOOST_CHECK(a == b);
    const std::string hex = ArtifactFill(0x11).Hex();
    const std::string k_file = modelnet::ObjectKeySourceFile("v1", hex, 0);
    const std::string k_piece = modelnet::ObjectKeyPiece("v1", hex, 0, 0);
    BOOST_CHECK(k_file != k_piece);
    BOOST_CHECK(k_file.find("r2") == std::string::npos);
    BOOST_CHECK(k_file.find("amazonaws") == std::string::npos);
    BOOST_CHECK(k_file.find("btx-models") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cloud_09_presign_get_exact_object)
{
    const ScopedCloudCredentials credentials;
    const fs::path creds = m_path_root / "cloud-09-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    modelnet::S3Client client;
    std::string err;
    BOOST_REQUIRE_MESSAGE(client.Init(credentials.Config(creds).s3, err), err);
    const std::vector<unsigned char> body{'z'};
    BOOST_REQUIRE(client.Put("exact/object", body, err));
    std::string url;
    BOOST_CHECK(!client.PresignGet("prefix/", 60, url, err));
    BOOST_CHECK(!client.PresignGet("obj?list-type=2", 60, url, err));
    BOOST_CHECK(!client.PresignGet("exact/object", 0, url, err));
    BOOST_REQUIRE(client.PresignGet("exact/object", 60, url, err));
    BOOST_CHECK(url.find("X-Amz-Signature=") != std::string::npos);
    BOOST_CHECK(url.find("list-type") == std::string::npos);
    BOOST_CHECK_EQUAL(client.Fake()->PresignCount(), 1);
    std::vector<unsigned char> got;
    BOOST_REQUIRE(client.FetchPresignedGet(url, got, err));
    BOOST_CHECK(got == body);
    const std::string dumped = client.HealthJson().write() + url;
    BOOST_CHECK(modelnet::RedactCloudSecrets(dumped, kSecret).find(kSecret) == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cloud_10_stream_put_over_8mib)
{
    const fs::path creds = m_path_root / "cloud-10-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    auto cfg = BaseCfg(creds);
    std::string err;
#ifdef WIN32
    // Windows file attributes cannot express owner-only POSIX permissions.
    // Keep the file-credential refusal, then exercise streaming with the
    // supported environment-credential path and synthetic signing keys.
    modelnet::S3PieceStore file_store{cfg};
    BOOST_CHECK(!file_store.Init(err));
    BOOST_CHECK_EQUAL(err, "credential file must be mode 0600");
    const std::string credential_body = std::string{"aws_access_key_id="} + kAccess +
                                        "\naws_secret_access_key=" + kSecret + "\n";
    test::ScopedEnvVar credentials{"BTX_CLOUD_STREAM_TEST_CREDS", credential_body.c_str()};
    cfg.s3.creds.kind = modelnet::CredentialRefKind::ENV;
    cfg.s3.creds.value = "BTX_CLOUD_STREAM_TEST_CREDS";
#endif
    modelnet::S3PieceStore store{cfg};
    err.clear();
    BOOST_REQUIRE_MESSAGE(store.Init(err), err);
    const fs::path src = m_path_root / "cloud-10.bin";
    const uint64_t sz = modelnet::kCloudStreamChunkBytes + 100;
    {
        std::ofstream out(src, std::ios::binary);
        std::vector<char> block(1024 * 256, 'x');
        uint64_t left = sz;
        while (left > 0) {
            const uint64_t n = std::min<uint64_t>(left, block.size());
            out.write(block.data(), static_cast<std::streamsize>(n));
            left -= n;
        }
    }
    const auto art = ArtifactFill(0x22);
    BOOST_REQUIRE(store.PutSourceFile(art, 0, src, sz, 3, err));
    BOOST_CHECK_LE(store.LastPutMaxBufferBytes(), modelnet::kCloudStreamChunkBytes);
    BOOST_REQUIRE(store.FakeForTests());
    BOOST_CHECK_EQUAL(store.FakeForTests()->ObjectBytes(modelnet::ObjectKeySourceFile("v1", art.Hex(), 0)), sz);
    BOOST_CHECK_GT(store.FakeForTests()->MultipartCount(), 0);
    BOOST_CHECK_EQUAL(store.FakeForTests()->ObjectCount(), 1);
    std::vector<unsigned char> head;
    BOOST_REQUIRE(store.GetObject(modelnet::ObjectKeySourceFile("v1", art.Hex(), 0), 0, 16, head, err));
    BOOST_REQUIRE_EQUAL(head.size(), 16U);
}

BOOST_AUTO_TEST_CASE(cloud_11_health_json_counters)
{
    const ScopedCloudCredentials credentials;
    const fs::path creds = m_path_root / "cloud-11-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    modelnet::S3PieceStore store{credentials.Config(creds)};
    std::string err;
    BOOST_REQUIRE_MESSAGE(store.Init(err), err);
    const auto art = ArtifactFill(0x33);
    const fs::path src = m_path_root / "cloud-11.bin";
    {
        std::ofstream out(src, std::ios::binary);
        out << "hello-health";
    }
    BOOST_REQUIRE(store.PutSourceFile(art, 0, src, 12, 1, err));
    std::vector<unsigned char> got;
    BOOST_REQUIRE(store.GetSourceFile(art, 0, got, err));
    uint64_t size = 0;
    BOOST_REQUIRE(store.HeadObject(modelnet::ObjectKeySourceFile("v1", art.Hex(), 0), size, err));
    const UniValue h = store.HealthJson();
    BOOST_CHECK(h["fake"].get_bool());
    BOOST_CHECK(h["https_enabled"].get_bool());
    BOOST_CHECK_GE(h["put_count"].getInt<int64_t>(), 1);
    BOOST_CHECK_GE(h["get_count"].getInt<int64_t>(), 1);
    BOOST_CHECK_GE(h["head_count"].getInt<int64_t>(), 1);
    BOOST_CHECK_EQUAL(h["layout"].get_str(), "SOURCE_FILES");
    NoSecrets(h, kAccess, kSecret);
    NoSecrets(store.ConfigJson(), kAccess, kSecret);
    BOOST_CHECK_EQUAL(store.Health().backend, "fake-s3");
    BOOST_CHECK(store.Health().ok);
}

BOOST_AUTO_TEST_CASE(cloud_12_budget_refuse_when_exhausted)
{
    const ScopedCloudCredentials credentials;
    const fs::path creds = m_path_root / "cloud-12-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    auto cfg = credentials.Config(creds);
    cfg.budget_gets = 1;
    modelnet::S3PieceStore store{cfg};
    std::string err;
    BOOST_REQUIRE_MESSAGE(store.Init(err), err);
    const auto art = ArtifactFill(0x44);
    const fs::path src = m_path_root / "cloud-12.bin";
    {
        std::ofstream out(src, std::ios::binary);
        out << "budget";
    }
    BOOST_REQUIRE(store.PutSourceFile(art, 0, src, 6, 1, err));
    std::vector<unsigned char> got;
    BOOST_REQUIRE(store.GetSourceFile(art, 0, got, err));
    BOOST_CHECK(!store.GetSourceFile(art, 0, got, err));
    BOOST_CHECK(err.find("budget") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(cloud_12f_calendar_rollback_preserves_exhausted_allowance)
{
    const ScopedCloudCredentials credentials;
    const fs::path creds = m_path_root / "cloud_12f_calendar_rollback_preserves_exhausted_allowance-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    // 2026-03-01 01:00 UTC; the preceding day is in the preceding month.
    constexpr int64_t day = 1772326800;
    constexpr int64_t next_month = 1775005200;
    for (int quota = 0; quota < 4; ++quota) {
        BOOST_TEST_CONTEXT("quota=" << quota) {
            auto cfg = credentials.Config(creds);
            const auto suffix = fs::PathFromString("cloud_12f_calendar_rollback_preserves_exhausted_allowance-" + std::to_string(quota));
            cfg.budget_state_path = m_path_root / suffix / "budget.json";
            cfg.s3.fake_store_dir = m_path_root / suffix / "origin";
            if (quota == 0) cfg.budget_gets_per_day = 1;
            if (quota == 1) cfg.budget_bytes_per_day = 6;
            if (quota == 2) cfg.budget_gets_per_month = 1;
            if (quota == 3) cfg.budget_bytes_per_month = 6;
            auto attempt = [&](int64_t clock, bool expected, bool seed = false) {
                // Reopen both the actual saved budget and the persistent fake origin.
                modelnet::S3PieceStore store{cfg};
                store.SetClockForTests(clock);
                std::string err;
                BOOST_REQUIRE_MESSAGE(store.Init(err), err);
                if (seed) {
                    std::istringstream input{"daycap"};
                    BOOST_REQUIRE_MESSAGE(store.PutObject("calendar", input, 6, err), err);
                }
                uint64_t size{0};
                BOOST_REQUIRE_MESSAGE(store.HeadObject("calendar", size, err), err);
                BOOST_REQUIRE_EQUAL(size, 6);
                const auto before = store.FakeForTests()->GetCount();
                std::vector<unsigned char> got;
                const bool allowed = store.GetObject("calendar", 0, 0, got, err);
                BOOST_CHECK_EQUAL(allowed, expected);
                BOOST_CHECK_EQUAL(store.FakeForTests()->GetCount() - before, expected ? 1 : 0);
                if (allowed) {
                    BOOST_CHECK_EQUAL(std::string(got.begin(), got.end()), "daycap");
                } else {
                    BOOST_CHECK(err.find("budget") != std::string::npos);
                }
            };
            attempt(day, true, true);
            attempt(day, false);
            attempt(day - 86400, false);
            attempt(day, false);
            attempt(day, false);
            attempt(quota < 2 ? day + 86400 : next_month, true);
            attempt(quota < 2 ? day + 86400 : next_month, false);
        }
    }
}

BOOST_AUTO_TEST_CASE(cloud_12g_calendar_rollback_preserves_remaining_allowance)
{
    const ScopedCloudCredentials credentials;
    const fs::path creds = m_path_root / "cloud_12g_calendar_rollback_preserves_remaining_allowance-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    // 2026-03-01 01:00 UTC; the preceding day is in the preceding month.
    constexpr int64_t day = 1772326800;
    constexpr int64_t next_month = 1775005200;
    for (int quota = 0; quota < 4; ++quota) {
        BOOST_TEST_CONTEXT("quota=" << quota) {
            auto cfg = credentials.Config(creds);
            const auto suffix = fs::PathFromString("cloud_12g_calendar_rollback_preserves_remaining_allowance-" + std::to_string(quota));
            cfg.budget_state_path = m_path_root / suffix / "budget.json";
            cfg.s3.fake_store_dir = m_path_root / suffix / "origin";
            if (quota == 0) cfg.budget_gets_per_day = 2;
            if (quota == 1) cfg.budget_bytes_per_day = 12;
            if (quota == 2) cfg.budget_gets_per_month = 2;
            if (quota == 3) cfg.budget_bytes_per_month = 12;
            auto attempt = [&](int64_t clock, bool expected, bool seed = false) {
                // Reopen both the actual saved budget and the persistent fake origin.
                modelnet::S3PieceStore store{cfg};
                store.SetClockForTests(clock);
                std::string err;
                BOOST_REQUIRE_MESSAGE(store.Init(err), err);
                if (seed) {
                    std::istringstream input{"daycap"};
                    BOOST_REQUIRE_MESSAGE(store.PutObject("calendar", input, 6, err), err);
                }
                uint64_t size{0};
                BOOST_REQUIRE_MESSAGE(store.HeadObject("calendar", size, err), err);
                BOOST_REQUIRE_EQUAL(size, 6);
                const auto before = store.FakeForTests()->GetCount();
                std::vector<unsigned char> got;
                const bool allowed = store.GetObject("calendar", 0, 0, got, err);
                BOOST_CHECK_EQUAL(allowed, expected);
                BOOST_CHECK_EQUAL(store.FakeForTests()->GetCount() - before, expected ? 1 : 0);
                if (allowed) {
                    BOOST_CHECK_EQUAL(std::string(got.begin(), got.end()), "daycap");
                } else {
                    BOOST_CHECK(err.find("budget") != std::string::npos);
                }
            };
            attempt(day, true, true);
            attempt(day - 86400, true); // The remaining allowance stays usable.
            attempt(day - 86400, false);
            attempt(day, false);
            const auto forward = quota < 2 ? day + 86400 : next_month;
            attempt(forward, true);
            attempt(forward, true);
            attempt(forward, false);
        }
    }
}

BOOST_AUTO_TEST_CASE(cloud_12b_calendar_day_budget_persists)
{
    const ScopedCloudCredentials credentials;
    const fs::path creds = m_path_root / "cloud-12b-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    auto cfg = credentials.Config(creds);
    cfg.budget_gets_per_day = 1;
    cfg.budget_state_path = m_path_root / "cloud-12b-budget.json";
    const int64_t day0 = 86400 * 20000 + 3600;
    {
        modelnet::S3PieceStore store{cfg};
        store.SetClockForTests(day0);
        std::string err;
        BOOST_REQUIRE_MESSAGE(store.Init(err), err);
        const auto art = ArtifactFill(0x45);
        const fs::path src = m_path_root / "cloud-12b.bin";
        {
            std::ofstream out(src, std::ios::binary);
            out << "daycap";
        }
        BOOST_REQUIRE(store.PutSourceFile(art, 0, src, 6, 1, err));
        std::vector<unsigned char> got;
        BOOST_REQUIRE(store.GetSourceFile(art, 0, got, err));
        BOOST_CHECK(!store.GetSourceFile(art, 0, got, err));
        BOOST_CHECK(err.find("budget") != std::string::npos);
        const UniValue h = store.HealthJson();
        BOOST_CHECK(h["budget_gets_per_day_limited"].get_bool());
        BOOST_CHECK_EQUAL(h["budget_gets_remaining_day"].getInt<int64_t>(), 0);
        store.SetClockForTests(day0 + 86400);
        BOOST_REQUIRE(store.GetSourceFile(art, 0, got, err));
        BOOST_CHECK_EQUAL(store.HealthJson()["budget_gets_remaining_day"].getInt<int64_t>(), 0);
    }
    {
        modelnet::S3PieceStore store{cfg};
        store.SetClockForTests(day0 + 86400);
        std::string err;
        BOOST_REQUIRE_MESSAGE(store.Init(err), err);
        const auto art = ArtifactFill(0x45);
        std::vector<unsigned char> got;
        BOOST_CHECK(!store.GetSourceFile(art, 0, got, err));
        BOOST_CHECK(err.find("budget") != std::string::npos);
    }
}

// Insert before fullcloud_01 in modelnet_cloud_tests.cpp. POSIX-only fault fixture.
// Requires <csignal>, <stdexcept>, <sys/resource.h> on POSIX.
#if !defined(_WIN32)
BOOST_AUTO_TEST_CASE(cloud_12c_startup_write_failure_preserves_budget)
{
    const ScopedCloudCredentials credentials;
    const auto creds = m_path_root / "cloud-12c-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    auto cfg = credentials.Config(creds);
    cfg.budget_gets_per_day = 1;
    cfg.budget_state_path = m_path_root / "cloud-12c-budget.json";
    const int64_t day0 = 86400 * 20000 + 3600;
    const auto art = ArtifactFill(0x46);
    const auto src = m_path_root / "cloud-12c.bin";
    { std::ofstream out(src, std::ios::binary); out << "daycap"; }
    const auto read_budget = [&] {
        std::ifstream in(cfg.budget_state_path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(in), {});
    };
    const auto read_json = [&] {
        UniValue v;
        BOOST_REQUIRE(v.read(read_budget()) && v.isObject());
        return v;
    };
    const auto put = [&](modelnet::S3PieceStore& store) {
        std::string err;
        BOOST_REQUIRE_MESSAGE(store.PutSourceFile(art, 0, src, 6, 1, err), err);
    };
    const auto refuse = [&](modelnet::S3PieceStore& store) {
        std::string err;
        std::vector<unsigned char> got;
        const bool ok = store.GetSourceFile(art, 0, got, err);
        BOOST_CHECK_MESSAGE(!ok && err.find("budget") != std::string::npos,
                            "expected budget refusal; actual ok=" << ok << " err=" << err);
    };
    const auto fetch = [&](modelnet::S3PieceStore& store) {
        std::string err;
        std::vector<unsigned char> got;
        BOOST_REQUIRE_MESSAGE(store.GetSourceFile(art, 0, got, err), err);
        BOOST_CHECK_EQUAL(std::string(got.begin(), got.end()), "daycap");
    };
    {
        modelnet::S3PieceStore store{cfg};
        store.SetClockForTests(day0);
        std::string err;
        BOOST_REQUIRE_MESSAGE(store.Init(err), err);
        put(store); fetch(store); refuse(store);
    }
    const std::string committed = read_budget();
    BOOST_REQUIRE(committed.size() > 32);
    const auto seeded = read_json();
    for (const auto* k : {"day_gets", "month_gets", "used_gets"})
        BOOST_REQUIRE_EQUAL(seeded[k].getInt<int64_t>(), 1);
    for (const auto* k : {"day_bytes", "month_bytes", "used_bytes"})
        BOOST_REQUIRE_EQUAL(seeded[k].getInt<int64_t>(), 6);
    {
        // Each Init creates a fresh FakeS3. Re-PUT prevents missing data from
        // masquerading as a preserved budget on the next GET.
        modelnet::S3PieceStore store{cfg};
        store.SetClockForTests(day0);
        std::string err;
        BOOST_REQUIRE_MESSAGE(store.Init(err), err);
        put(store); refuse(store);
    }
    bool init_ok = true, ready = true;
    std::string startup_error;
    {
        // Run only this case in its own test process. The soft limit is restored
        // before any Boost reporting or observation output. Half the file, not
        // size-1: dropping only the trailing newline still leaves valid JSON.
        class ScopedFileLimit {
            struct rlimit saved{};
            using Handler = void (*)(int);
            Handler previous{SIG_ERR};
        public:
            explicit ScopedFileLimit(rlim_t bytes) {
                if (getrlimit(RLIMIT_FSIZE, &saved) != 0)
                    throw std::runtime_error("getrlimit failed");
                previous = std::signal(SIGXFSZ, SIG_IGN);
                if (previous == SIG_ERR) throw std::runtime_error("signal failed");
                struct rlimit limited = saved;
                limited.rlim_cur = bytes;
                if (setrlimit(RLIMIT_FSIZE, &limited) != 0) {
                    std::signal(SIGXFSZ, previous);
                    throw std::runtime_error("setrlimit failed");
                }
            }
            ~ScopedFileLimit() {
                // An unrecoverable restore must not let the remaining test run
                // under a hidden process-wide limit.
                if (setrlimit(RLIMIT_FSIZE, &saved) != 0) std::terminate();
                std::signal(SIGXFSZ, previous);
            }
        } limit(committed.size() / 2);
        modelnet::S3PieceStore store{cfg};
        store.SetClockForTests(day0);
        init_ok = store.Init(startup_error);
        ready = store.IsReady();
    }
    const auto after_fault = read_budget();
    BOOST_TEST_MESSAGE("startup result=" << init_ok << " ready=" << ready
                       << " err=" << startup_error << " old_bytes=" << committed.size()
                       << " after_bytes=" << after_fault.size());
    BOOST_CHECK(!init_ok);
    BOOST_CHECK(!ready);
    BOOST_CHECK(!startup_error.empty());
    BOOST_CHECK_EQUAL(after_fault, committed);
    {
        modelnet::S3PieceStore store{cfg};
        store.SetClockForTests(day0);
        std::string err;
        BOOST_REQUIRE_MESSAGE(store.Init(err), err);
        put(store); refuse(store);
    }
    const auto reopened = read_json();
    for (const auto* k : {"day_gets", "month_gets", "used_gets", "day_bytes", "month_bytes", "used_bytes"})
        BOOST_CHECK_EQUAL(reopened[k].getInt<int64_t>(), seeded[k].getInt<int64_t>());
    {
        modelnet::S3PieceStore store{cfg};
        store.SetClockForTests(day0 + 86400);
        std::string err;
        BOOST_REQUIRE_MESSAGE(store.Init(err), err);
        put(store); fetch(store); refuse(store);
    }
    const auto rolled = read_json();
    BOOST_CHECK_EQUAL(rolled["day_utc"].getInt<int64_t>(), seeded["day_utc"].getInt<int64_t>() + 1);
    BOOST_CHECK_EQUAL(rolled["month_utc"].getInt<int64_t>(), seeded["month_utc"].getInt<int64_t>());
    BOOST_CHECK_EQUAL(rolled["day_gets"].getInt<int64_t>(), 1);
    BOOST_CHECK_EQUAL(rolled["day_bytes"].getInt<int64_t>(), 6);
    BOOST_CHECK_EQUAL(rolled["month_gets"].getInt<int64_t>(), 2);
    BOOST_CHECK_EQUAL(rolled["used_gets"].getInt<int64_t>(), 2);
    BOOST_CHECK_EQUAL(rolled["month_bytes"].getInt<int64_t>(), 12);
    BOOST_CHECK_EQUAL(rolled["used_bytes"].getInt<int64_t>(), 12);
    cfg.budget_state_path.clear();
    {
        modelnet::S3PieceStore store{cfg};
        store.SetClockForTests(day0);
        std::string err;
        BOOST_REQUIRE_MESSAGE(store.Init(err), err);
        put(store); fetch(store); refuse(store);
        store.SetClockForTests(day0 + 86400);
        fetch(store); refuse(store);
    }
}

BOOST_AUTO_TEST_CASE(cloud_12d_post_read_save_failure_retains_charge)
{
    const ScopedCloudCredentials credentials;
    const auto creds = m_path_root / "cloud-12d-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    auto cfg = credentials.Config(creds);
    cfg.budget_gets_per_day = 1;
    cfg.budget_state_path = m_path_root / "cloud-12d-budget.json";
    modelnet::S3PieceStore store{cfg};
    store.SetClockForTests(86400LL * 20000 + 3600);
    std::string err;
    BOOST_REQUIRE_MESSAGE(store.Init(err), err);
    const auto src = m_path_root / "cloud-12d.bin";
    { std::ofstream out(src, std::ios::binary); out << "daycap"; }
    const auto art = ArtifactFill(0x47);
    BOOST_REQUIRE(store.PutSourceFile(art, 0, src, 6, 1, err));
    const auto read = [&] {
        std::ifstream in(cfg.budget_state_path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(in), {});
    };
    const auto committed = read();
    struct rlimit saved{};
    BOOST_REQUIRE_EQUAL(getrlimit(RLIMIT_FSIZE, &saved), 0);
    const auto handler = std::signal(SIGXFSZ, SIG_IGN);
    BOOST_REQUIRE(handler != SIG_ERR);
    auto limited = saved;
    limited.rlim_cur = committed.size() / 2;
    if (setrlimit(RLIMIT_FSIZE, &limited) != 0) {
        std::signal(SIGXFSZ, handler);
        BOOST_FAIL("setrlimit failed");
    }
    std::vector<unsigned char> got;
    bool ok;
    try { ok = store.GetSourceFile(art, 0, got, err); }
    catch (...) {
        if (setrlimit(RLIMIT_FSIZE, &saved) != 0) std::terminate();
        std::signal(SIGXFSZ, handler);
        throw;
    }
    if (setrlimit(RLIMIT_FSIZE, &saved) != 0) std::terminate();
    std::signal(SIGXFSZ, handler);
    BOOST_CHECK(!ok);
    BOOST_CHECK(got.empty());
    BOOST_CHECK(err.find("budget") != std::string::npos);
    BOOST_CHECK_EQUAL(read(), committed);
    const auto health = store.HealthJson();
    BOOST_CHECK_EQUAL(health["budget_used_gets"].getInt<int64_t>(), 1);
    BOOST_CHECK_EQUAL(health["origin_bytes"].getInt<int64_t>(), 6);
    BOOST_CHECK(!store.GetSourceFile(art, 0, got, err));
    BOOST_CHECK(err.find("budget") != std::string::npos);
}
#endif

// A budget file that exists but does not parse is not a fresh budget. Starting
// from zero would admit reads past a cap that was already used up, and the
// zeros written at Init would replace the damaged file for good.
BOOST_AUTO_TEST_CASE(cloud_12e_damaged_budget_state_refuses_init)
{
    const ScopedCloudCredentials credentials;
    const auto creds = m_path_root / "cloud-12e-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    auto cfg = credentials.Config(creds);
    cfg.budget_gets_per_day = 1;
    cfg.budget_state_path = m_path_root / "cloud-12e-budget.json";
    const int64_t now = 86400LL * 20000 + 3600;
    const auto art = ArtifactFill(0x49);
    {
        modelnet::S3PieceStore store{cfg};
        store.SetClockForTests(now);
        std::string err;
        BOOST_REQUIRE_MESSAGE(store.Init(err), err);
        const auto src = m_path_root / "cloud-12e.bin";
        { std::ofstream out(src, std::ios::binary); out << "daycap"; }
        BOOST_REQUIRE(store.PutSourceFile(art, 0, src, 6, 1, err));
        std::vector<unsigned char> got;
        BOOST_REQUIRE_MESSAGE(store.GetSourceFile(art, 0, got, err), err);
        BOOST_CHECK(!store.GetSourceFile(art, 0, got, err));
    }
    std::string committed;
    {
        std::ifstream in(cfg.budget_state_path, std::ios::binary);
        committed.assign(std::istreambuf_iterator<char>(in), {});
    }
    BOOST_REQUIRE_GT(committed.size(), 2U);
    const std::string damaged = committed.substr(0, committed.size() / 2);
    for (const std::string& text : {damaged, std::string{"[]\n"}, std::string{"{\"day_gets\":\"1\"}\n"},
                                    std::string{"{\"used_gets\":-1}\n"}, std::string{"{\"day_bytes\":1.5}\n"}}) {
        { std::ofstream out(cfg.budget_state_path, std::ios::binary | std::ios::trunc); out << text; }
        modelnet::S3PieceStore store{cfg};
        store.SetClockForTests(now);
        std::string err;
        BOOST_CHECK(!store.Init(err));
        BOOST_CHECK_MESSAGE(err.find("budget") != std::string::npos, err);
        BOOST_CHECK(!store.IsReady());
        std::ifstream in(cfg.budget_state_path, std::ios::binary);
        BOOST_CHECK_EQUAL(std::string(std::istreambuf_iterator<char>(in), {}), text);
    }
    // A missing file is a fresh budget.
    fs::remove(cfg.budget_state_path);
    modelnet::S3PieceStore store{cfg};
    store.SetClockForTests(now);
    std::string err;
    BOOST_CHECK_MESSAGE(store.Init(err), err);
}

BOOST_AUTO_TEST_CASE(fullcloud_01_102400_pieces_one_source_object)
{
    const ScopedCloudCredentials credentials;
    const fs::path creds = m_path_root / "fc-01-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    modelnet::S3PieceStore store{credentials.Config(creds)};
    std::string err;
    BOOST_REQUIRE_MESSAGE(store.Init(err), err);
    const auto art = ArtifactFill(0x55);
    const fs::path src = m_path_root / "fc-01.bin";
    const std::string payload = "tiny-logical-400gib";
    {
        std::ofstream out(src, std::ios::binary);
        out << payload;
    }
    constexpr uint64_t logical_pieces = 102400;
    BOOST_REQUIRE(store.PutSourceFile(art, 0, src, payload.size(), logical_pieces, err));
    BOOST_REQUIRE(store.FakeForTests());
    BOOST_CHECK_EQUAL(store.FakeForTests()->ObjectCount(), 1);
    const std::string key = modelnet::ObjectKeySourceFile("v1", art.Hex(), 0);
    BOOST_CHECK_EQUAL(store.FakeForTests()->Meta(key, "logical_piece_count"), "102400");
    BOOST_CHECK_EQUAL(modelnet::EstimatedGetsPerColdRetrieval(modelnet::CloudObjectLayout::SOURCE_FILES, 1,
                                                             logical_pieces),
                      1);
}

BOOST_AUTO_TEST_CASE(fullcloud_02_object_bytes_equal_fileentry)
{
    const ScopedCloudCredentials credentials;
    const fs::path creds = m_path_root / "fc-02-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    modelnet::S3PieceStore store{credentials.Config(creds)};
    std::string err;
    BOOST_REQUIRE_MESSAGE(store.Init(err), err);
    const auto art = ArtifactFill(0x66);
    const fs::path src = m_path_root / "fc-02.bin";
    const std::string payload = "FileEntry-bytes-exact";
    {
        std::ofstream out(src, std::ios::binary);
        out << payload;
    }
    BOOST_CHECK(!store.PutSourceFile(art, 0, src, payload.size() + 1, 1, err));
    BOOST_REQUIRE(store.PutSourceFile(art, 0, src, payload.size(), 1, err));
    const std::string key = modelnet::ObjectKeySourceFile("v1", art.Hex(), 0);
    BOOST_CHECK_EQUAL(store.FakeForTests()->ObjectBytes(key), payload.size());
    BOOST_CHECK_EQUAL(store.FakeForTests()->Meta(key, "file_entry_bytes"), std::to_string(payload.size()));
    std::vector<unsigned char> got;
    BOOST_REQUIRE(store.GetSourceFile(art, 0, got, err));
    BOOST_CHECK_EQUAL(got.size(), payload.size());
}

BOOST_AUTO_TEST_CASE(fullcloud_03_layout_change_keys_not_hashes)
{
    const auto art = ArtifactFill(0x77);
    const std::vector<unsigned char> file{'a', 'b', 'c'};
    const auto id1 = modelnet::DomainHash("BTX/ModelFile/v1", file);
    const auto id2 = modelnet::DomainHash("BTX/ModelFile/v1", file);
    BOOST_CHECK(id1 == id2);
    const std::string sf = modelnet::ObjectKeySourceFile("p", art.Hex(), 0);
    const std::string po = modelnet::ObjectKeyPiece("p", art.Hex(), 0, 0);
    BOOST_CHECK(sf != po);
    BOOST_CHECK_EQUAL(po, modelnet::PieceObjectKey(art, 0, 0, "p"));
    BOOST_CHECK(sf.find("/files/0") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(fullcloud_10_r2_hostname_auto_source_files)
{
    BOOST_CHECK(modelnet::EndpointLooksLikeCloudflareR2("https://acct.r2.cloudflarestorage.com"));
    BOOST_CHECK(modelnet::EndpointLooksLikeCloudflareR2("https://ACCT.R2.CLOUDFLARESTORAGE.COM/bucket"));
    BOOST_CHECK(!modelnet::EndpointLooksLikeCloudflareR2("https://cdn.example.com"));
    BOOST_CHECK(!modelnet::EndpointLooksLikeCloudflareR2("https://acct.r2.cloudflarestorage.com.evil.com"));
    BOOST_CHECK(!modelnet::EndpointLooksLikeCloudflareR2("https://evil.com/acct.r2.cloudflarestorage.com"));
    modelnet::CloudObjectLayout layout;
    modelnet::CloudReadStrategy strategy;
    std::string reject;
    BOOST_REQUIRE(modelnet::ResolveCloudLayout(modelnet::CloudProvider::AUTO,
                                               "https://acct.r2.cloudflarestorage.com",
                                               modelnet::CloudObjectLayout::AUTO, false, 102400, layout, strategy,
                                               reject));
    BOOST_CHECK_EQUAL(modelnet::CloudObjectLayoutName(layout), "SOURCE_FILES");
    BOOST_CHECK_EQUAL(modelnet::CloudReadStrategyName(strategy), "STREAM_FILE");
}

BOOST_AUTO_TEST_CASE(fullcloud_11_explicit_r2_custom_domain)
{
    BOOST_CHECK(!modelnet::EndpointLooksLikeCloudflareR2("https://models.example.com"));
    modelnet::CloudObjectLayout layout;
    modelnet::CloudReadStrategy strategy;
    std::string reject;
    BOOST_REQUIRE(modelnet::ResolveCloudLayout(modelnet::CloudProvider::CLOUDFLARE_R2, "https://models.example.com",
                                               modelnet::CloudObjectLayout::AUTO, false, 102400, layout, strategy,
                                               reject));
    BOOST_CHECK_EQUAL(modelnet::CloudObjectLayoutName(layout), "SOURCE_FILES");
    BOOST_CHECK_EQUAL(modelnet::CloudReadStrategyName(strategy), "STREAM_FILE");
    BOOST_REQUIRE(modelnet::ResolveCloudLayout(modelnet::CloudProvider::AUTO, "https://models.example.com",
                                               modelnet::CloudObjectLayout::PIECE_OBJECTS, false, 102400, layout,
                                               strategy, reject));
    BOOST_CHECK_EQUAL(modelnet::CloudObjectLayoutName(layout), "PIECE_OBJECTS");
}

BOOST_AUTO_TEST_CASE(fullcloud_12_r2_piece_objects_rejected)
{
    modelnet::CloudObjectLayout layout;
    modelnet::CloudReadStrategy strategy;
    std::string reject;
    BOOST_CHECK(!modelnet::ResolveCloudLayout(modelnet::CloudProvider::AUTO,
                                              "https://acct.r2.cloudflarestorage.com",
                                              modelnet::CloudObjectLayout::PIECE_OBJECTS, false, 102400, layout,
                                              strategy, reject));
    BOOST_CHECK(reject.find("allow_request_heavy") != std::string::npos);
    BOOST_CHECK(reject.find("102400") != std::string::npos);
    BOOST_REQUIRE(modelnet::ResolveCloudLayout(modelnet::CloudProvider::CLOUDFLARE_R2, "https://models.example.com",
                                               modelnet::CloudObjectLayout::PIECE_OBJECTS, true, 102400, layout,
                                               strategy, reject));
    BOOST_CHECK_EQUAL(modelnet::CloudObjectLayoutName(layout), "PIECE_OBJECTS");

    const fs::path creds = m_path_root / "fc-12-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    auto cfg = BaseCfg(creds);
    cfg.layout = modelnet::CloudObjectLayout::PIECE_OBJECTS;
    cfg.projected_piece_objects = 102400;
    cfg.allow_request_heavy_cloud_layout = false;
    modelnet::S3PieceStore store{cfg};
    std::string err;
    BOOST_CHECK(!store.Init(err));
    BOOST_CHECK(err.find("allow_request_heavy") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(fullcloud_13_estimated_gets)
{
    BOOST_CHECK_EQUAL(modelnet::EstimatedGetsPerColdRetrieval(modelnet::CloudObjectLayout::SOURCE_FILES, 1, 102400),
                      1);
    BOOST_CHECK_EQUAL(modelnet::EstimatedGetsPerColdRetrieval(modelnet::CloudObjectLayout::PIECE_OBJECTS, 1, 102400),
                      102400);
    BOOST_CHECK_EQUAL(modelnet::EstimatedGetsPerColdRetrieval(modelnet::CloudObjectLayout::AUTO, 3, 102400), 3);
    modelnet::CloudObjectLayout layout;
    modelnet::CloudReadStrategy strategy;
    std::string reject;
    BOOST_CHECK(!modelnet::ResolveCloudLayout(modelnet::CloudProvider::CLOUDFLARE_R2,
                                              "https://acct.r2.cloudflarestorage.com",
                                              modelnet::CloudObjectLayout::PIECE_OBJECTS, false, 65, layout, strategy,
                                              reject));
    BOOST_CHECK(reject.find("65") != std::string::npos);
    BOOST_REQUIRE(modelnet::ResolveCloudLayout(modelnet::CloudProvider::CLOUDFLARE_R2,
                                               "https://acct.r2.cloudflarestorage.com",
                                               modelnet::CloudObjectLayout::PIECE_OBJECTS, false, 64, layout, strategy,
                                               reject));
}

BOOST_AUTO_TEST_CASE(fullcloud_20_budget_remaining_in_health)
{
    const ScopedCloudCredentials credentials;
    const fs::path creds = m_path_root / "fc-20-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    auto cfg = credentials.Config(creds);
    cfg.budget_gets = 10;
    cfg.budget_origin_bytes = 1000;
    modelnet::S3PieceStore store{cfg};
    std::string err;
    BOOST_REQUIRE_MESSAGE(store.Init(err), err);
    const auto art = ArtifactFill(0x88);
    const fs::path src = m_path_root / "fc-20.bin";
    {
        std::ofstream out(src, std::ios::binary);
        out << "remaining";
    }
    BOOST_REQUIRE(store.PutSourceFile(art, 0, src, 9, 1, err));
    std::vector<unsigned char> got;
    BOOST_REQUIRE(store.GetSourceFile(art, 0, got, err));
    const UniValue h = store.HealthJson();
    BOOST_CHECK(h["budget_gets_limited"].get_bool());
    BOOST_CHECK(h["budget_bytes_limited"].get_bool());
    BOOST_CHECK_EQUAL(h["budget_gets_remaining"].getInt<int64_t>(), 9);
    BOOST_CHECK_EQUAL(h["budget_bytes_remaining"].getInt<int64_t>(), 991);
    BOOST_CHECK_EQUAL(h["origin_bytes"].getInt<int64_t>(), 9);
    NoSecrets(h, kAccess, kSecret);
}

BOOST_AUTO_TEST_CASE(fullcloud_23_source_files_object_key)
{
    const auto art = ArtifactFill(0x99);
    BOOST_CHECK_EQUAL(modelnet::ObjectKeySourceFile("v1", art.Hex(), 2),
                      "v1/artifacts/" + art.Hex() + "/files/2");
    BOOST_CHECK_EQUAL(modelnet::ObjectKeyPiece("", art.Hex(), 2, 7),
                      "artifacts/" + art.Hex() + "/2/7.piece");
    BOOST_CHECK_EQUAL(modelnet::ObjectKeyPiece("v1/", art.Hex(), 2, 7),
                      modelnet::PieceObjectKey(art, 2, 7, "v1"));
}

BOOST_AUTO_TEST_CASE(fullcloud_05_fakes3_stream_hydrates_one_get)
{
    const ScopedCloudCredentials credentials;
    using namespace modelnet;
    const fs::path creds = m_path_root / "cloud-stream-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    S3PieceStore store{credentials.Config(creds)};
    std::string err;
    BOOST_REQUIRE_MESSAGE(store.Init(err), err);
    const fs::path src = m_path_root / "stream.bin";
    std::vector<unsigned char> file(256, 0x5a);
    file[0] = 0x11;
    file.back() = 0x22;
    {
        std::ofstream out(src, std::ios::binary);
        out.write(reinterpret_cast<const char*>(file.data()), static_cast<std::streamsize>(file.size()));
    }
    const Digest48 art = ArtifactFill(0x44);
    BOOST_REQUIRE(store.PutSourceFile(art, 0, src, file.size(), 1, err));
    BOOST_CHECK_EQUAL(store.FakeForTests()->ObjectCount(), 1U);

    std::vector<unsigned char> body;
    BOOST_REQUIRE(store.GetSourceFile(art, 0, body, err));
    BOOST_CHECK(body == file);

    const fs::path live_dir = m_path_root / "hyd-live";
    const fs::path q_dir = m_path_root / "hyd-q";
    fs::create_directories(live_dir);
    fs::create_directories(q_dir);
    ModelStore live(live_dir, 64 << 20);
    ModelStore q(q_dir, 64 << 20);
    FileStreamHydration hyd(art, 0, file.size(), live, q);
    Digest48 sha;
    CSHA384 hasher;
    hasher.Write(file.data(), file.size());
    hasher.Finalize(sha.data.data());
    hyd.SetExpectedSha384(sha);
    BOOST_REQUIRE(hyd.Feed(Span<const unsigned char>{body.data(), body.size()}, err));
    BOOST_REQUIRE(hyd.Finish(err));
    BOOST_CHECK(hyd.IsAdvertisable());
    BOOST_CHECK_EQUAL(store.FakeForTests()->GetCount(), 1);
    NoSecrets(store.HealthJson(), kAccess, kSecret);
}

BOOST_AUTO_TEST_CASE(cloud_rpc_set_hostmodel_events_no_secrets)
{
    const ScopedCloudCredentials credentials;
    using namespace modelnet;
    const fs::path dir = m_path_root / "cloud-rpc";
    fs::create_directories(dir);
    const fs::path creds = dir / "creds";
    WriteCreds(creds, kAccess, kSecret, true);

    ModelCatalog cat{dir, 8 << 20};
    UniValue cfg(UniValue::VOBJ);
    cfg.pushKV("endpoint", "https://acct.r2.cloudflarestorage.com");
    cfg.pushKV("bucket", "btx-models");
    cfg.pushKV("prefix", "v1");
    cfg.pushKV("provider", "AUTO");
    cfg.pushKV("layout", "AUTO");
    cfg.pushKV("credential_ref", credentials.RpcRef(creds));
    cfg.pushKV("use_fake", true);
    cfg.pushKV("idempotency_key", "cloud-rpc-set");
    UniValue params(UniValue::VARR);
    params.push_back(cfg);
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "setcloudstorage");
    req.pushKV("params", params);
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, req, result, code, err), err);
    NoSecrets(result, kAccess, kSecret);
    BOOST_CHECK(result["applied"].get_bool());
    BOOST_CHECK_EQUAL(result["layout"].get_str(), "SOURCE_FILES");
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int64_t>(), 0);

    UniValue bad(UniValue::VOBJ);
    cfg.pushKV("aws_secret_access_key", kSecret);
    cfg.pushKV("idempotency_key", "cloud-rpc-secret-reject");
    UniValue badp(UniValue::VARR);
    badp.push_back(cfg);
    UniValue badreq(UniValue::VOBJ);
    badreq.pushKV("method", "setcloudstorage");
    badreq.pushKV("params", badp);
    UniValue badres;
    BOOST_CHECK(!DispatchHelperRpc(cat, badreq, badres, code, err));
    BOOST_CHECK(err.find("credential_ref") != std::string::npos);

    const fs::path model = dir / "Qwen3-8B-IQ4_XS";
    fs::create_directories(model);
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    {
        std::ofstream out(model / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    UniValue ip(UniValue::VARR);
    ip.push_back(fs::PathToString(model));
    UniValue ireq(UniValue::VOBJ);
    ireq.pushKV("method", "importmodel");
    ireq.pushKV("params", ip);
    UniValue imported;
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, ireq, imported, code, err), err);
    BOOST_CHECK(imported["cloud_uploaded"].get_bool());
    Digest48 uploaded_model;
    BOOST_REQUIRE(Digest48::FromHex(imported["model_id"].get_str(), uploaded_model, err));
    BOOST_CHECK(!cat.TransferActive(uploaded_model));
    BOOST_CHECK_EQUAL(imported["cloud_layout"].get_str(), "SOURCE_FILES");
    BOOST_REQUIRE(imported["cloud_files"].isArray());
    BOOST_REQUIRE_GE(imported["cloud_files"].size(), 1U);
    NoSecrets(imported, kAccess, kSecret);

    UniValue info;
    UniValue ireq2(UniValue::VOBJ);
    ireq2.pushKV("method", "getcloudstorageinfo");
    ireq2.pushKV("params", UniValue(UniValue::VARR));
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, ireq2, info, code, err), err);
    BOOST_CHECK(info["object_count"].getInt<int64_t>() >= 1);
    BOOST_CHECK(info["put_count"].getInt<int64_t>() >= 1);
    NoSecrets(info, kAccess, kSecret);

    UniValue caps;
    UniValue nreq(UniValue::VOBJ);
    nreq.pushKV("method", "getmodelnetworkinfo");
    nreq.pushKV("params", UniValue(UniValue::VARR));
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, nreq, caps, code, err), err);
    BOOST_CHECK(caps["delivery"]["sequential_file_stream"].get_bool());
    BOOST_CHECK(caps["capabilities"]["cloud_attached_storage"].get_bool());
    BOOST_CHECK_EQUAL(caps["automatic_spend_atoms"].getInt<int64_t>(), 0);
    NoSecrets(caps, kAccess, kSecret);

    UniValue evs;
    UniValue ereq(UniValue::VOBJ);
    ereq.pushKV("method", "getmodelevents");
    UniValue ep(UniValue::VARR);
    ep.push_back(0);
    ereq.pushKV("params", ep);
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, ereq, evs, code, err), err);
    BOOST_REQUIRE(evs["events"].isArray());
    BOOST_REQUIRE_GE(evs["events"].size(), 1U);
    NoSecrets(evs, kAccess, kSecret);

    UniValue probe;
    UniValue treq(UniValue::VOBJ);
    treq.pushKV("method", "testcloudstorage");
    treq.pushKV("params", UniValue(UniValue::VARR));
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, treq, probe, code, err), err);
    BOOST_CHECK(probe["probe_ok"].get_bool());
    NoSecrets(probe, kAccess, kSecret);
}

BOOST_AUTO_TEST_CASE(cloud_rpc_damaged_budget_reports_init_error)
{
    // The helper loads the stored origin at the start of every call. When the
    // budget file is damaged, the origin must stay off and say why, in
    // setcloudstorage and in getcloudstorageinfo, and the other calls must
    // keep working.
    const ScopedCloudCredentials credentials;
    using namespace modelnet;
    const fs::path dir = m_path_root / "cloud-rpc-damaged";
    fs::create_directories(dir);
    const fs::path creds = dir / "creds";
    WriteCreds(creds, kAccess, kSecret, true);
    ModelCatalog cat{dir, 8 << 20};
    const auto call = [&](const std::string& method, const UniValue& params, UniValue& result) {
        UniValue req(UniValue::VOBJ);
        req.pushKV("method", method);
        req.pushKV("params", params);
        std::string code, err;
        const bool ok = DispatchHelperRpc(cat, req, result, code, err);
        BOOST_CHECK_MESSAGE(ok, method + " " + code + " " + err);
        return ok;
    };
    UniValue cfg(UniValue::VOBJ);
    cfg.pushKV("endpoint", "https://acct.r2.cloudflarestorage.com");
    cfg.pushKV("bucket", "btx-models");
    cfg.pushKV("prefix", "v1");
    cfg.pushKV("credential_ref", credentials.RpcRef(creds));
    cfg.pushKV("use_fake", true);
    cfg.pushKV("idempotency_key", "cloud-rpc-damaged-1");
    UniValue params(UniValue::VARR);
    params.push_back(cfg);
    UniValue result;
    BOOST_REQUIRE(call("setcloudstorage", params, result));
    BOOST_REQUIRE(result["applied"].get_bool());

    fs::path budget;
    for (const auto& entry : fs::recursive_directory_iterator(dir)) {
        if (entry.path().filename() == "cloud-budget.json") budget = entry.path();
    }
    BOOST_REQUIRE(!budget.empty());
    {
        std::ofstream out(budget, std::ios::binary | std::ios::trunc);
        out << "{\"used_gets\":-1}\n";
    }
    cfg.pushKV("idempotency_key", "cloud-rpc-damaged-2");
    UniValue again(UniValue::VARR);
    again.push_back(cfg);
    if (call("setcloudstorage", again, result)) {
        BOOST_CHECK(!result["applied"].get_bool());
        BOOST_CHECK(result["init_error"].get_str().find("cloud budget state") != std::string::npos);
    }

    UniValue info;
    if (call("getcloudstorageinfo", UniValue(UniValue::VARR), info)) {
        BOOST_CHECK(!info["configured"].get_bool());
        BOOST_CHECK(info.exists("init_error") &&
                    info["init_error"].get_str().find("cloud budget state") != std::string::npos);
        NoSecrets(info, kAccess, kSecret);
    }
    // Every helper call loads the stored origin first: the others keep working.
    UniValue listed;
    BOOST_CHECK(call("listmodels", UniValue(UniValue::VARR), listed));
}

BOOST_AUTO_TEST_CASE(cloud_https_transport_available)
{
    BOOST_CHECK(modelnet::S3HttpsTransportAvailable());
}

BOOST_AUTO_TEST_CASE(cloud_https_use_fake_false_error_is_not_stubbed)
{
    const ScopedCloudCredentials credentials;
    const fs::path creds = m_path_root / "cloud-https-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    modelnet::S3ClientConfig cfg;
    cfg.endpoint = "https://127.0.0.1:1";
    cfg.bucket = "btx-models";
    cfg.region = "auto";
    cfg.use_fake = false;
    cfg.creds = credentials.Config(creds).s3.creds;
    modelnet::S3Client client;
    std::string err;
    BOOST_REQUIRE_MESSAGE(client.Init(cfg, err), err);
    BOOST_CHECK(!client.UsesFake());
    const UniValue health = client.HealthJson();
    BOOST_CHECK(health["reachable"].get_bool());
    BOOST_CHECK(health["https_enabled"].get_bool());
    BOOST_CHECK(!health["fake"].get_bool());
    NoSecrets(health, kAccess, kSecret);
    std::vector<unsigned char> out;
    BOOST_CHECK(!client.Get("v1/artifacts/aa/files/0", out, err));
    BOOST_CHECK(err.find("stubbed") == std::string::npos);
    err.clear();
    const std::vector<unsigned char> body{'x'};
    BOOST_CHECK(!client.Put("k", body, err));
    BOOST_CHECK(err.find("stubbed") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cloud_https_redirect_refused)
{
    BOOST_CHECK(modelnet::S3HttpRedirectRefused(301));
    BOOST_CHECK(modelnet::S3HttpRedirectRefused(302));
    BOOST_CHECK(modelnet::S3HttpRedirectRefused(303));
    BOOST_CHECK(modelnet::S3HttpRedirectRefused(307));
    BOOST_CHECK(modelnet::S3HttpRedirectRefused(308));
    BOOST_CHECK(!modelnet::S3HttpRedirectRefused(200));
    BOOST_CHECK(!modelnet::S3HttpRedirectRefused(404));
    BOOST_CHECK(modelnet::S3HttpResponseForbiddenRedirect(301, {}));
    BOOST_CHECK(modelnet::S3HttpResponseForbiddenRedirect(200, "https://evil.example/"));
    BOOST_CHECK(!modelnet::S3HttpResponseForbiddenRedirect(200, {}));
}

BOOST_AUTO_TEST_CASE(cloud_https_refuses_redirect)
{
    BOOST_CHECK(modelnet::S3HttpResponseForbiddenRedirect(302, "https://evil.example/obj"));
    BOOST_CHECK(modelnet::S3HttpResponseForbiddenRedirect(301, "https://evil.example/"));
    BOOST_CHECK(modelnet::S3HttpResponseForbiddenRedirect(303, {}));
    BOOST_CHECK(modelnet::S3HttpResponseForbiddenRedirect(307, "https://x"));
    BOOST_CHECK(modelnet::S3HttpResponseForbiddenRedirect(308, {}));
    BOOST_CHECK(modelnet::S3HttpResponseForbiddenRedirect(200, "https://evil.example/"));
    BOOST_CHECK(!modelnet::S3HttpResponseForbiddenRedirect(200, {}));
    BOOST_CHECK(!modelnet::S3HttpResponseForbiddenRedirect(404, {}));
    BOOST_CHECK(!modelnet::S3HttpResponseForbiddenRedirect(206, {}));
}

// Without Content-Length the body ends at EOF. A body longer than the range
// asked for was cut to the length of the range and returned as that range.
BOOST_AUTO_TEST_CASE(cloud_unchunked_body_past_its_limit_is_refused)
{
    test::ScopedEnvVar credentials{"BTX_TEST_S3_SOCKET_CREDS", "aws_access_key_id=fixture-access\naws_secret_access_key=fixture-secret\n"};
    for (const std::string body : {"0123456789", "0123"}) {
        uint16_t port = 0;
        auto listener = ListenLoopback(port);
        BOOST_REQUIRE(listener);
        auto server = std::async(std::launch::async, [&] {
            auto peer = AcceptWithin(*listener, std::chrono::seconds{5});
            if (!peer) return false;
            std::string request;
            char buf[4096];
            while (request.find("\r\n\r\n") == std::string::npos) {
                Sock::Event occurred{0};
                if (!peer->Wait(std::chrono::seconds{5}, Sock::RECV, &occurred) || !(occurred & Sock::RECV)) return false;
                const auto n = peer->Recv(buf, sizeof(buf), 0);
                if (n <= 0) return false;
                request.append(buf, n);
            }
            // The body comes after the head, as from a real server: the bytes
            // that arrive with the head were already checked.
            CThreadInterrupt interrupt;
            for (const std::string part : {std::string{"HTTP/1.1 206 Partial Content\r\nConnection: close\r\n\r\n"}, body}) {
                peer->SendComplete(Span<const unsigned char>{reinterpret_cast<const unsigned char*>(part.data()), part.size()},
                                   std::chrono::seconds{5}, interrupt);
                std::this_thread::sleep_for(std::chrono::milliseconds{300});
            }
            return true;
        });
        modelnet::S3Client client;
        std::string err;
        BOOST_REQUIRE_MESSAGE(client.Init(LoopbackS3Config("http", port), err), err);
        std::vector<unsigned char> got;
        const bool ok = client.RangeGet("loopback-object", 0, 4, got, err);
        if (body.size() > 4) {
            BOOST_CHECK(!ok);
            BOOST_CHECK_EQUAL(err, "s3 https object too large for unchunked GET");
        } else {
            BOOST_CHECK_MESSAGE(ok, err);
            BOOST_CHECK(got == std::vector<unsigned char>(body.begin(), body.end()));
        }
        BOOST_CHECK(server.get());
    }
}

// The client's socket blocks with a 5 s timeout. A TLS read or write that
// hits it comes back as SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE: the write
// retried it forever while the server read nothing, and the read took it for
// the end of a body without Content-Length.
BOOST_AUTO_TEST_CASE(cloud_tls_read_and_write_end_at_the_socket_timeout)
{
    LoopbackTlsIdentity id;
    const fs::path ca_file = m_path_root / "loopback-ca.pem";
    BOOST_REQUIRE(MakeLoopbackTlsIdentity(id, ca_file));
    const std::string ca_path = fs::PathToString(ca_file);
    test::ScopedEnvVar ca{"SSL_CERT_FILE", ca_path.c_str()};
    test::ScopedEnvVar credentials{"BTX_TEST_S3_SOCKET_CREDS", "aws_access_key_id=fixture-access\naws_secret_access_key=fixture-secret\n"};
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> server_ctx{SSL_CTX_new(TLS_server_method()), SSL_CTX_free};
    BOOST_REQUIRE(server_ctx);
    BOOST_REQUIRE_EQUAL(SSL_CTX_use_certificate(server_ctx.get(), id.cert), 1);
    BOOST_REQUIRE_EQUAL(SSL_CTX_use_PrivateKey(server_ctx.get(), id.key), 1);
#ifndef WIN32
    // Without the fix the stalled write only ends when the server closes.
    struct IgnorePipe {
        void (*previous)(int){std::signal(SIGPIPE, SIG_IGN)};
        ~IgnorePipe() { std::signal(SIGPIPE, previous); }
    } ignore_pipe;
#endif
    for (const bool write_stalls : {false, true}) {
        uint16_t port = 0;
        SOCKET listen_handle = INVALID_SOCKET;
        auto listener = ListenLoopback(port, &listen_handle);
        BOOST_REQUIRE(listener);
        std::promise<void> client_returned;
        std::shared_future<void> returned = client_returned.get_future().share();
        // Release the server however this iteration ends.
        struct Release {
            std::promise<void>& p;
            bool done{false};
            void operator()()
            {
                if (!done) p.set_value();
                done = true;
            }
            ~Release() { (*this)(); }
        } release_server{client_returned};
        auto server = std::async(std::launch::async, [&, returned] {
            Sock::Event occurred{0};
            if (!listener->Wait(std::chrono::seconds{5}, Sock::RECV, &occurred) || !(occurred & Sock::RECV)) return false;
            const SOCKET fd = ::accept(listen_handle, nullptr, nullptr);
            if (fd == INVALID_SOCKET) return false;
            Sock peer{fd};
            std::unique_ptr<SSL, decltype(&SSL_free)> ssl{SSL_new(server_ctx.get()), SSL_free};
            if (!ssl || SSL_set_fd(ssl.get(), static_cast<int>(fd)) != 1 || SSL_accept(ssl.get()) != 1) return false;
            if (!write_stalls) {
                std::string request;
                char buf[4096];
                while (request.find("\r\n\r\n") == std::string::npos) {
                    const int n = SSL_read(ssl.get(), buf, sizeof(buf));
                    if (n <= 0) return false;
                    request.append(buf, n);
                }
                const std::string head = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabc";
                if (SSL_write(ssl.get(), head.data(), static_cast<int>(head.size())) <= 0) return false;
            }
            // Neither read on nor close until the client has returned.
            return returned.wait_for(std::chrono::seconds{90}) == std::future_status::ready;
        });
        modelnet::S3Client client;
        std::string err;
        BOOST_REQUIRE_MESSAGE(client.Init(LoopbackS3Config("https", port), err), err);
        const auto start = std::chrono::steady_clock::now();
        auto call = std::async(std::launch::async, [&] {
            if (write_stalls) {
                // More than the socket buffers of both ends hold.
                const std::vector<unsigned char> body(size_t{64} << 20, 'x');
                return client.Put("loopback-object", body, err);
            }
            std::vector<unsigned char> got;
            return client.Get("loopback-object", got, err);
        });
        // A few socket timeouts at most; without the fix the write never ends.
        BOOST_CHECK_MESSAGE(call.wait_for(std::chrono::seconds{60}) == std::future_status::ready,
                            (write_stalls ? "write" : "read") << " still waiting on a stalled server");
        BOOST_TEST_MESSAGE((write_stalls ? "write" : "read") << " returned after "
                           << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count() << " ms");
        release_server();
        BOOST_CHECK(!call.get());
#ifndef WIN32
        BOOST_CHECK_EQUAL(err, write_stalls ? "s3 https write timed out" : "s3 https read timed out");
#else
        // Winsock reports the timeout as an error of its own, which OpenSSL
        // passes on as SSL_ERROR_SYSCALL: the call fails, under another name.
        BOOST_CHECK(!err.empty());
#endif
        BOOST_CHECK(server.get());
    }
}

// The cloud client and the source registry set a socket timeout as a timeval.
// Winsock reads SO_RCVTIMEO and SO_SNDTIMEO as a DWORD of milliseconds, so on
// Windows 5 s became 5 ms (and the registry's 15 s became 15 ms): a remote
// endpoint timed out on its first reply.
BOOST_AUTO_TEST_CASE(cloud_socket_timeouts_read_back_as_set)
{
    const SOCKET handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BOOST_REQUIRE(handle != INVALID_SOCKET);
    Sock sock{handle};
    modelnet::SetSocketTimeoutsMs(static_cast<int>(handle), 5000);
    for (const int option : {SO_RCVTIMEO, SO_SNDTIMEO}) {
#ifdef WIN32
        DWORD ms = 0;
        int length = sizeof(ms);
        BOOST_REQUIRE_EQUAL(::getsockopt(handle, SOL_SOCKET, option, reinterpret_cast<char*>(&ms), &length), 0);
        BOOST_CHECK_EQUAL(ms, 5000U);
#else
        timeval tv{};
        socklen_t length = sizeof(tv);
        BOOST_REQUIRE_EQUAL(::getsockopt(handle, SOL_SOCKET, option, &tv, &length), 0);
        BOOST_CHECK_EQUAL(tv.tv_sec, 5);
        BOOST_CHECK_EQUAL(tv.tv_usec, 0);
#endif
    }
}

BOOST_AUTO_TEST_CASE(cloud_https_not_stub_error)
{
    const ScopedCloudCredentials credentials;
    const fs::path creds = m_path_root / "cloud-https-not-stub-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    modelnet::S3ClientConfig cfg = credentials.Config(creds, "http://127.0.0.1:1").s3;
    cfg.use_fake = false;
    cfg.allow_http_loopback = true;
    modelnet::S3Client client;
    std::string err;
    BOOST_REQUIRE_MESSAGE(client.Init(cfg, err), err);
    BOOST_CHECK(!client.UsesFake());
    const std::vector<unsigned char> body{'x'};
    BOOST_CHECK(!client.Put("k", body, err));
    BOOST_CHECK(err.find("stubbed") == std::string::npos);
    BOOST_CHECK(err.find("OpenSSL HTTPS transport is stubbed") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cloud_fixture_credentials_restore_environment)
{
#ifdef WIN32
    const char* name = "BTX_TEST_CLOUD_FIXTURE_CREDS";
    test::ScopedEnvVar previous{name, "preexisting-fixture-value"};
    {
        const ScopedCloudCredentials credentials;
        const auto cfg = credentials.Config(fs::PathFromString("unused-credential-file"));
        BOOST_CHECK(cfg.s3.creds.kind == modelnet::CredentialRefKind::ENV);
        BOOST_REQUIRE(std::getenv(name));
        BOOST_CHECK(std::string{std::getenv(name)}.find(kSecret) != std::string::npos);
    }
    BOOST_REQUIRE(std::getenv(name));
    BOOST_CHECK_EQUAL(std::getenv(name), "preexisting-fixture-value");
    previous.Set(nullptr);
    {
        const ScopedCloudCredentials credentials;
        BOOST_REQUIRE(std::getenv(name));
    }
    BOOST_CHECK(std::getenv(name) == nullptr);
#else
    const ScopedCloudCredentials credentials;
    const auto path = fs::PathFromString("unchanged-posix-credential-file");
    const auto cfg = credentials.Config(path);
    BOOST_CHECK(cfg.s3.creds.kind == modelnet::CredentialRefKind::PATH);
    BOOST_CHECK_EQUAL(cfg.s3.creds.value, fs::PathToString(path));
#endif
}

BOOST_AUTO_TEST_CASE(cloud_real_http_socket_cleanup)
{
    CheckS3SocketCleanup(false);
}

BOOST_AUTO_TEST_CASE(cloud_tls_handshake_socket_cleanup)
{
    CheckS3SocketCleanup(true);
}

BOOST_AUTO_TEST_CASE(s3_multipart_completion_requires_success_envelope)
{
    using modelnet::S3MultipartCompletionSucceeded;
    const char* valid[] = {
        "<CompleteMultipartUploadResult><ETag>ok</ETag></CompleteMultipartUploadResult>",
        " \r\n\t<?xml version=\"1.0\"?>\n<CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><ETag>ok</ETag></CompleteMultipartUploadResult>\n",
        "<s3:CompleteMultipartUploadResult xmlns:s3=\"http://s3.amazonaws.com/doc/2006-03-01/\"><s3:ETag>ok</s3:ETag></s3:CompleteMultipartUploadResult>",
        "\xef\xbb\xbf<?xml version=\"1.0\"?><!-- progress --><CompleteMultipartUploadResult><ETag>ok</ETag></CompleteMultipartUploadResult><!-- done -->",
    };
    for (const auto* xml : valid) BOOST_CHECK_MESSAGE(S3MultipartCompletionSucceeded(xml), xml);
    const char* refused[] = {
        "<Error><Code>InternalError</Code></Error>",
        "<s3:Error xmlns:s3=\"http://s3.amazonaws.com/doc/2006-03-01/\"><s3:Code>InternalError</s3:Code></s3:Error>",
        "<Error><Message><![CDATA[<CompleteMultipartUploadResult></CompleteMultipartUploadResult>]]></Message></Error>",
        "", " \r\n", "<Unknown></Unknown>", "<CompleteMultipartUploadResult>",
        "<CompleteMultipartUploadResult/>", "<CompleteMultipartUploadResultOther></CompleteMultipartUploadResultOther>",
        "<CompleteMultipartUploadResult></other:CompleteMultipartUploadResult>",
        "<CompleteMultipartUploadResult></CompleteMultipartUploadResultExtra>",
        "<CompleteMultipartUploadResult></CompleteMultipartUploadResult><Error></Error>",
        "<!-- incomplete", "<?xml version=\"1.0\"",
    };
    for (const auto* xml : refused) BOOST_CHECK_MESSAGE(!S3MultipartCompletionSucceeded(xml), xml);
}


BOOST_AUTO_TEST_CASE(cloud_rpc_detach_removal_failure_preserves_origin_and_retry)
{
    const ScopedCloudCredentials credentials;
    using namespace modelnet;
    const fs::path dir = m_path_root / "cloud-detach-failure";
    fs::create_directories(dir);
    const fs::path creds = dir / "creds";
    WriteCreds(creds, kAccess, kSecret, true);
    ModelCatalog cat{dir, 8 << 20};
    auto call = [&](const char* method, const UniValue& options, UniValue& result,
                    std::string& code, std::string& err) {
        UniValue params(UniValue::VARR), req(UniValue::VOBJ);
        params.push_back(options);
        req.pushKV("method", method);
        req.pushKV("params", params);
        code.clear();
        err.clear();
        return DispatchHelperRpc(cat, req, result, code, err);
    };
    UniValue cfg(UniValue::VOBJ), result;
    cfg.pushKV("endpoint", "https://detach-fixture.invalid");
    cfg.pushKV("bucket", "models");
    cfg.pushKV("provider", "GENERIC_S3");
    cfg.pushKV("credential_ref", credentials.RpcRef(creds));
    cfg.pushKV("use_fake", true);
    cfg.pushKV("idempotency_key", "detach-failure-config");
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(call("setcloudstorage", cfg, result, code, err), err);
    BOOST_REQUIRE(result["applied"].get_bool());
    const fs::path cloud = dir / "cloud.json", saved = dir / "cloud-fixture-backup.json";
    // Real portable remove failure: an occupied directory cannot be removed.
    // Preserve the original file and restore it even if a later assertion throws.
    fs::rename(cloud, saved);
    struct RestoreConfig {
        fs::path cloud, saved;
        void Restore() {
            std::error_code ec;
            if (!std::filesystem::exists(saved, ec)) return;
            fs::remove(cloud / "fixture-blocker", ec);
            fs::remove(cloud, ec);
            fs::rename(saved, cloud, ec);
        }
        ~RestoreConfig() { Restore(); }
    } restore{cloud, saved};
    BOOST_REQUIRE(fs::create_directory(cloud));
    { std::ofstream out(cloud / "fixture-blocker"); out << "keep"; BOOST_REQUIRE(out.good()); }
    UniValue detach(UniValue::VOBJ);
    detach.pushKV("mode", "DETACH");
    BOOST_CHECK(!call("removemodelstorage", detach, result, code, err));
    BOOST_CHECK_EQUAL(code, "IO_ERROR");
    BOOST_CHECK(!err.empty());
    BOOST_CHECK(fs::exists(saved));
    // A refused detach must not clear the current origin. The obstacle remains
    // while this status is queried, so reload cannot mask a cleared live handle.
    UniValue empty(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(call("getcloudstorageinfo", empty, result, code, err), err);
    BOOST_CHECK(result["configured"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int64_t>(), 0);
    restore.Restore();
    BOOST_REQUIRE(fs::is_regular_file(cloud));
    BOOST_REQUIRE_MESSAGE(call("removemodelstorage", detach, result, code, err), err);
    BOOST_CHECK(result["detached"].get_bool());
    BOOST_CHECK(!result["remote_objects_deleted"].get_bool());
    BOOST_CHECK(!fs::exists(cloud));
    BOOST_REQUIRE_MESSAGE(call("getcloudstorageinfo", empty, result, code, err), err);
    BOOST_CHECK(!result["configured"].get_bool());
    BOOST_REQUIRE_MESSAGE(call("removemodelstorage", detach, result, code, err), err);
    BOOST_CHECK(result["detached"].get_bool());
    BOOST_CHECK(!result["remote_objects_deleted"].get_bool());
}

namespace {
std::vector<unsigned char> UploadModelBytes(size_t size)
{
    const size_t data_bytes = size - 128;
    const std::string header = "{\"w\":{\"dtype\":\"U8\",\"shape\":[" + std::to_string(data_bytes) +
        "],\"data_offsets\":[0," + std::to_string(data_bytes) + "]}}";
    std::vector<unsigned char> bytes(size, 'A');
    WriteLE64(bytes.data(), 120);
    std::fill(bytes.begin() + 8, bytes.begin() + 128, ' ');
    std::copy(header.begin(), header.end(), bytes.begin() + 8);
    return bytes;
}
void WriteUploadBytes(const fs::path& path, const std::vector<unsigned char>& bytes)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    BOOST_REQUIRE(out.good());
}
}

BOOST_AUTO_TEST_CASE(cloud_verified_upload_ignores_external_source_changes)
{
    using namespace modelnet;
    const ScopedCloudCredentials credentials;
    const fs::path dir = m_path_root / "verified-upload";
    fs::create_directories(dir);
    const fs::path creds = dir / "creds";
    WriteCreds(creds, kAccess, kSecret, true);
    const auto original = UploadModelBytes(2 * PIECE_SIZE + 137);
    const fs::path source = dir / "model.safetensors";
    WriteUploadBytes(source, original);
    ModelCatalog cat{dir / "catalog", 32 << 20};
    CatalogEntry entry;
    std::string err;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(source), false, entry, err), err);
    auto changed = original;
    changed.back() ^= 1;
    WriteUploadBytes(source, changed);
    for (const auto layout : {CloudObjectLayout::SOURCE_FILES, CloudObjectLayout::PIECE_OBJECTS}) {
        auto cfg = credentials.Config(creds, "https://s3.example.invalid");
        cfg.provider = CloudProvider::GENERIC_S3;
        cfg.layout = layout;
        S3PieceStore cloud{cfg};
        BOOST_REQUIRE_MESSAGE(cloud.Init(err), err);
        CatalogFileStream input{cat, entry.artifact_id, 0, entry.core.files[0]};
        BOOST_REQUIRE(input.Error().empty());
        if (layout == CloudObjectLayout::SOURCE_FILES) {
            BOOST_REQUIRE_MESSAGE(cloud.PutSourceFile(entry.artifact_id, 0, input, original.size(), 3, err), err);
        } else {
            BOOST_REQUIRE_MESSAGE(cloud.PutPieceObjects(entry.artifact_id, 0, input, original.size(), err), err);
        }
        BOOST_CHECK(input.Error().empty());
        BOOST_CHECK_LE(input.MaxBufferBytes(), PIECE_SIZE);
        BOOST_CHECK_LE(cloud.LastPutMaxBufferBytes(), kCloudStreamChunkBytes);
        std::vector<unsigned char> got;
        if (layout == CloudObjectLayout::SOURCE_FILES) {
            BOOST_REQUIRE_MESSAGE(cloud.GetSourceFile(entry.artifact_id, 0, got, err), err);
        } else {
            for (uint32_t i = 0; i < 3; ++i) {
                std::vector<unsigned char> piece;
                BOOST_REQUIRE_MESSAGE(cloud.GetPieceObject(entry.artifact_id, 0, i, piece, err), err);
                got.insert(got.end(), piece.begin(), piece.end());
            }
        }
        BOOST_CHECK(got == original);
    }
}

BOOST_AUTO_TEST_CASE(cloud_verified_reader_withholds_invalid_last_piece_and_retries)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "verified-read-errors";
    fs::create_directories(dir);
    const auto bytes = UploadModelBytes(PIECE_SIZE + 137);
    const fs::path source = dir / "model.safetensors";
    WriteUploadBytes(source, bytes);
    ModelCatalog cat{dir / "catalog", 16 << 20};
    CatalogEntry entry;
    std::string err;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(source), false, entry, err), err);
    auto wrong = entry.core.files[0];
    wrong.sha384.data[0] ^= 1;
    CatalogFileStream invalid{cat, entry.artifact_id, 0, wrong};
    std::vector<char> out(bytes.size());
    invalid.read(out.data(), out.size());
    BOOST_CHECK_EQUAL(invalid.gcount(), PIECE_SIZE);
    BOOST_CHECK_EQUAL(invalid.Error(), "upload file sha384 mismatch");
    for (const bool wrong_root : {false, true}) {
        wrong = entry.core.files[0];
        if (wrong_root) wrong.pieces_root.data[0] ^= 1;
        else ++wrong.size;
        CatalogFileStream mismatch{cat, entry.artifact_id, 0, wrong};
        char first;
        mismatch.read(&first, 1);
        BOOST_CHECK_EQUAL(mismatch.gcount(), 0);
        BOOST_CHECK(!mismatch.Error().empty());
    }
    BOOST_REQUIRE(cat.Store().DeletePiece(entry.artifact_id, 0, 1, err));
    CatalogFileStream missing{cat, entry.artifact_id, 0, entry.core.files[0]};
    missing.read(out.data(), out.size());
    BOOST_CHECK_EQUAL(missing.gcount(), PIECE_SIZE);
    BOOST_CHECK(!missing.Error().empty());
    const Span<const unsigned char> last{bytes.data() + PIECE_SIZE, bytes.size() - PIECE_SIZE};
    BOOST_REQUIRE_MESSAGE(cat.Store().PutVerifiedPiece(entry.artifact_id, 0, 1, last, ChunkLeaf(1, last), err), err);
    CatalogFileStream retry{cat, entry.artifact_id, 0, entry.core.files[0]};
    retry.read(out.data(), out.size());
    BOOST_CHECK_EQUAL(retry.gcount(), bytes.size());
    BOOST_CHECK(retry.Error().empty());
    BOOST_CHECK(std::equal(bytes.begin(), bytes.end(), reinterpret_cast<unsigned char*>(out.data())));
    BOOST_CHECK_LE(retry.MaxBufferBytes(), PIECE_SIZE);
}

BOOST_AUTO_TEST_CASE(cloud_verified_reader_exact_lengths_and_corrupt_piece)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "verified-lengths";
    fs::create_directories(dir);
    for (const size_t size : {size_t{4096}, size_t{PIECE_SIZE}, size_t{PIECE_SIZE + 137}}) {
        const auto bytes = UploadModelBytes(size);
        const fs::path source = dir / "model.safetensors";
        WriteUploadBytes(source, bytes);
        ModelCatalog cat{dir / fs::PathFromString(std::to_string(size)), 16 << 20};
        CatalogEntry entry;
        std::string err;
        BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(source), false, entry, err), err);
        CatalogFileStream good{cat, entry.artifact_id, 0, entry.core.files[0]};
        std::vector<char> got(size);
        good.read(got.data(), got.size());
        BOOST_CHECK_EQUAL(good.gcount(), size);
        BOOST_CHECK(good.Error().empty()); // No extra EOF read is needed.
        BOOST_CHECK(std::equal(bytes.begin(), bytes.end(), reinterpret_cast<unsigned char*>(got.data())));
        // Only this disposable catalog's payload is changed for the integrity control.
        auto corrupt = bytes;
        corrupt.resize(std::min<size_t>(size, PIECE_SIZE));
        corrupt[0] ^= 1;
        const fs::path piece = cat.Store().Root() / "artifacts" / fs::PathFromString(entry.artifact_id.Hex()) / "0" / "0.piece";
        WriteUploadBytes(piece, corrupt);
        CatalogFileStream bad{cat, entry.artifact_id, 0, entry.core.files[0]};
        char first;
        bad.read(&first, 1);
        BOOST_CHECK_EQUAL(bad.gcount(), 0);
        BOOST_CHECK(!bad.Error().empty());
    }
}

BOOST_AUTO_TEST_CASE(cloud_verified_reader_empty_identity)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "verified-empty";
    ModelCatalog cat{dir, 8 << 20};
    CoreFile empty;
    empty.pieces_root = EmptyFileRoot();
    CSHA384().Finalize(empty.sha384.data.data());
    const auto artifact = ArtifactFill(0x73);
    CatalogFileStream good{cat, artifact, 0, empty};
    BOOST_CHECK(good.Error().empty());
    BOOST_CHECK_EQUAL(good.peek(), std::char_traits<char>::eof());
    auto wrong_root = empty;
    wrong_root.pieces_root.data[0] ^= 1;
    CatalogFileStream bad_root{cat, artifact, 0, wrong_root};
    BOOST_CHECK(!bad_root.Error().empty());
    empty.sha384.data[0] ^= 1;
    CatalogFileStream bad{cat, artifact, 0, empty};
    BOOST_CHECK(!bad.Error().empty());

}

BOOST_AUTO_TEST_SUITE_END()

#if defined(_WIN32)
#pragma pop_macro("GetObject")
#endif
