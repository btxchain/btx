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

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

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

} // namespace

BOOST_AUTO_TEST_CASE(cloud_01_sigv4_put_get_fakes3)
{
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
    BOOST_REQUIRE(client.Init(BaseCfg(creds).s3, err));
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
    const fs::path creds = m_path_root / "cloud-02-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    modelnet::S3Client client;
    std::string err;
    BOOST_REQUIRE(client.Init(BaseCfg(creds).s3, err));
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
    BOOST_REQUIRE(client.Init(cfg, err));
    NoSecrets(client.HealthJson(), kAccess, kSecret);
    NoSecrets(client.ConfigJson(), kAccess, kSecret);

    const char* env_name = "BTX_TEST_CLOUD_CREDS_C";
    const std::string body = std::string("aws_access_key_id=") + kAccess + "\naws_secret_access_key=" + kSecret + "\n";
    BOOST_REQUIRE_EQUAL(setenv(env_name, body.c_str(), 1), 0);
    modelnet::S3Client env_client;
    auto env_cfg = cfg;
    env_cfg.creds.kind = modelnet::CredentialRefKind::ENV;
    env_cfg.creds.value = env_name;
    BOOST_REQUIRE(env_client.Init(env_cfg, err));
    NoSecrets(env_client.HealthJson(), kAccess, kSecret);
    unsetenv(env_name);
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
    const fs::path creds = m_path_root / "cloud-07-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    modelnet::S3PieceStore store{BaseCfg(creds)};
    std::string err;
    BOOST_REQUIRE(store.Init(err));
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
    const fs::path creds = m_path_root / "cloud-07b-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    auto cfg = BaseCfg(creds, "https://minio.example.test");
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
    cfg.pushKV("credential_ref", fs::PathToString(creds));
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
    const fs::path creds = m_path_root / "cloud-09-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    modelnet::S3Client client;
    std::string err;
    BOOST_REQUIRE(client.Init(BaseCfg(creds).s3, err));
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
    modelnet::S3PieceStore store{BaseCfg(creds)};
    std::string err;
    BOOST_REQUIRE(store.Init(err));
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
    const fs::path creds = m_path_root / "cloud-11-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    modelnet::S3PieceStore store{BaseCfg(creds)};
    std::string err;
    BOOST_REQUIRE(store.Init(err));
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
    const fs::path creds = m_path_root / "cloud-12-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    auto cfg = BaseCfg(creds);
    cfg.budget_gets = 1;
    modelnet::S3PieceStore store{cfg};
    std::string err;
    BOOST_REQUIRE(store.Init(err));
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

BOOST_AUTO_TEST_CASE(cloud_12b_calendar_day_budget_persists)
{
    const fs::path creds = m_path_root / "cloud-12b-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    auto cfg = BaseCfg(creds);
    cfg.budget_gets_per_day = 1;
    cfg.budget_state_path = m_path_root / "cloud-12b-budget.json";
    const int64_t day0 = 86400 * 20000 + 3600;
    {
        modelnet::S3PieceStore store{cfg};
        store.SetClockForTests(day0);
        std::string err;
        BOOST_REQUIRE(store.Init(err));
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
        BOOST_REQUIRE(store.Init(err));
        const auto art = ArtifactFill(0x45);
        std::vector<unsigned char> got;
        BOOST_CHECK(!store.GetSourceFile(art, 0, got, err));
        BOOST_CHECK(err.find("budget") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(fullcloud_01_102400_pieces_one_source_object)
{
    const fs::path creds = m_path_root / "fc-01-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    modelnet::S3PieceStore store{BaseCfg(creds)};
    std::string err;
    BOOST_REQUIRE(store.Init(err));
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
    const fs::path creds = m_path_root / "fc-02-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    modelnet::S3PieceStore store{BaseCfg(creds)};
    std::string err;
    BOOST_REQUIRE(store.Init(err));
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
    const fs::path creds = m_path_root / "fc-20-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    auto cfg = BaseCfg(creds);
    cfg.budget_gets = 10;
    cfg.budget_origin_bytes = 1000;
    modelnet::S3PieceStore store{cfg};
    std::string err;
    BOOST_REQUIRE(store.Init(err));
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
    using namespace modelnet;
    const fs::path creds = m_path_root / "cloud-stream-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    S3PieceStore store{BaseCfg(creds)};
    std::string err;
    BOOST_REQUIRE(store.Init(err));
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
    cfg.pushKV("credential_ref", fs::PathToString(creds));
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

BOOST_AUTO_TEST_CASE(cloud_https_transport_available)
{
    BOOST_CHECK(modelnet::S3HttpsTransportAvailable());
}

BOOST_AUTO_TEST_CASE(cloud_https_use_fake_false_error_is_not_stubbed)
{
    const fs::path creds = m_path_root / "cloud-https-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    modelnet::S3ClientConfig cfg;
    cfg.endpoint = "https://127.0.0.1:1";
    cfg.bucket = "btx-models";
    cfg.region = "auto";
    cfg.use_fake = false;
    cfg.creds.kind = modelnet::CredentialRefKind::PATH;
    cfg.creds.value = fs::PathToString(creds);
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

BOOST_AUTO_TEST_CASE(cloud_https_not_stub_error)
{
    const fs::path creds = m_path_root / "cloud-https-not-stub-creds";
    WriteCreds(creds, kAccess, kSecret, true);
    modelnet::S3ClientConfig cfg = BaseCfg(creds, "http://127.0.0.1:1").s3;
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

BOOST_AUTO_TEST_SUITE_END()
