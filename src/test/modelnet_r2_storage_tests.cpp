// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Independent review lane R2 (Storage/Cloud). Findings and rationale live in
// audit/r2-storage.md; each case below names the finding it pins.
//
// R2S-01  r2s_01_layout_identity_invariant_across_key_families
// R2S-03  r2s_02_multipart_part_size_planner_vs_client            (tripwire)
// R2S-01  r2s_03_source_files_cold_get_estimate_is_per_object     (tripwire)
// R2S-04  r2s_04_over_budget_get_transfers_bytes_and_records_none (tripwire)
// R2S-05  r2s_05_put_path_is_not_metered                          (tripwire)
// R2S-11  r2s_06_non_aws_access_key_ids_are_masked_by_field_name  (fixed)
// §1.1    r2s_07_minio_is_config_only_not_run
// R2S-09  r2s_08_write_creds_break_fake_signing                   (tripwire)
//
// A tripwire asserts today's behaviour, which audit/r2-storage.md classifies as
// REAL. When the fix lands the tripwire fails: change the case and the audit row
// together, never the case alone.
//
// FakeS3 only. No live AWS, R2 or MinIO endpoint is contacted.

#include <modelnet/cloud_layout.h>
#include <modelnet/object_layout.h>
#include <modelnet/s3_client.h>
#include <modelnet/s3_store.h>
#include <modelnet/types.h>
#include <crypto/sha384.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_r2_storage_tests, BasicTestingSetup)

namespace {

// Fixture credentials. Deliberately not the shared sentinel identifiers: this
// lane must not reproduce any sentinel value in its own outputs.
constexpr char kFixtureAccess[] = "AKIAR2LANETESTKEY000";
constexpr char kFixtureSecret[] = "r2-lane-fixture-secret-not-real";
constexpr char kPrefix[] = "v1";

// Mirrors the read granularity of FileStreamHydration::Ingest, which allocates
// std::vector<unsigned char> tmp(1 << 16) and issues one origin read per pass.
constexpr uint64_t kHydrationReadBytes = uint64_t{1} << 16;

// Mirrors kS3HttpsMaxParts in s3_client.cpp, which is file-local and so cannot
// be referenced here.
constexpr uint64_t kClientMaxMultipartParts = 10000;

void WriteCreds(const fs::path& path, const std::string& access, const std::string& secret)
{
    {
        std::ofstream out(path);
        out << "aws_access_key_id=" << access << "\n";
        out << "aws_secret_access_key=" << secret << "\n";
    }
    fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
}

modelnet::CloudStoreConfig BaseCfg(const fs::path& creds)
{
    modelnet::CloudStoreConfig c;
    c.s3.endpoint = "https://acct.r2.cloudflarestorage.com";
    c.s3.bucket = "btx-models";
    c.s3.prefix = kPrefix;
    c.s3.region = "auto";
    c.s3.use_fake = true;
    c.s3.creds.kind = modelnet::CredentialRefKind::PATH;
    c.s3.creds.value = fs::PathToString(creds);
    c.provider = modelnet::CloudProvider::AUTO;
    c.layout = modelnet::CloudObjectLayout::AUTO;
    return c;
}

modelnet::Digest48 ArtifactFill(unsigned char b)
{
    modelnet::Digest48 d;
    d.data.fill(b);
    return d;
}

std::vector<unsigned char> Payload(size_t n)
{
    std::vector<unsigned char> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<unsigned char>((i * 31 + 7) & 0xff);
    return v;
}

std::string Sha384Hex(const std::vector<unsigned char>& body)
{
    unsigned char h[CSHA384::OUTPUT_SIZE];
    CSHA384 hasher;
    if (!body.empty()) hasher.Write(body.data(), body.size());
    hasher.Finalize(h);
    std::string hex;
    hex.reserve(sizeof(h) * 2);
    for (unsigned char c : h) {
        static const char* d = "0123456789abcdef";
        hex.push_back(d[c >> 4]);
        hex.push_back(d[c & 0x0f]);
    }
    return hex;
}

} // namespace

// R2S-01. The canonical commitment must not depend on which object-key family
// served the bytes. Existing coverage (cloud_08, fullcloud_03) hashes one buffer
// twice with one function, which is a tautology. This stores one payload twice —
// once as a whole source-file object, once split across per-piece keys — in the
// same bucket, reads both back, and compares SHA-384 across both families and
// the original. The split size is illustrative and kept small; the invariant
// under test is served-bytes identity, not the 4 MiB piece boundary.
//
// It also counts what each family costs at the backend, so the request-count
// difference between the two is measured rather than asserted from arithmetic:
// identical bytes, four times the requests.
BOOST_AUTO_TEST_CASE(r2s_01_layout_identity_invariant_across_key_families)
{
    const fs::path creds = m_path_root / "r2s-01-creds";
    WriteCreds(creds, kFixtureAccess, kFixtureSecret);
    modelnet::S3PieceStore store{BaseCfg(creds)};
    std::string err;
    BOOST_REQUIRE_MESSAGE(store.Init(err), err);
    BOOST_REQUIRE_EQUAL(modelnet::CloudObjectLayoutName(store.Layout()), "SOURCE_FILES");

    const auto art = ArtifactFill(0x5a);
    const size_t chunk = 1024;
    const auto payload = Payload(chunk * 4);
    const std::string want_hex = Sha384Hex(payload);

    const fs::path src = m_path_root / "r2s-01.bin";
    {
        std::ofstream out(src, std::ios::binary);
        out.write(reinterpret_cast<const char*>(payload.data()), static_cast<std::streamsize>(payload.size()));
    }
    BOOST_REQUIRE_MESSAGE(store.PutSourceFile(art, 0, src, payload.size(),
                                              modelnet::CanonicalPieceCount(payload.size()), err),
                          err);
    BOOST_REQUIRE(store.FakeForTests());
    const modelnet::FakeS3* fake = store.FakeForTests();
    const uint64_t source_file_puts = fake->PutCount();

    for (uint32_t i = 0; i < 4; ++i) {
        const std::string part(reinterpret_cast<const char*>(payload.data()) + i * chunk, chunk);
        std::istringstream body(part);
        const std::string key = modelnet::ObjectKeyPiece(kPrefix, art.Hex(), 0, i);
        BOOST_REQUIRE_MESSAGE(store.PutObject(key, body, part.size(), err), err);
    }
    const uint64_t piece_puts = fake->PutCount() - source_file_puts;

    const uint64_t gets_before_whole = fake->GetCount();
    std::vector<unsigned char> whole;
    BOOST_REQUIRE_MESSAGE(store.GetSourceFile(art, 0, whole, err), err);
    const uint64_t whole_gets = fake->GetCount() - gets_before_whole;

    const uint64_t gets_before_pieces = fake->GetCount();
    std::vector<unsigned char> reassembled;
    for (uint32_t i = 0; i < 4; ++i) {
        std::vector<unsigned char> part;
        const std::string key = modelnet::ObjectKeyPiece(kPrefix, art.Hex(), 0, i);
        BOOST_REQUIRE_MESSAGE(store.GetObject(key, 0, 0, part, err), err);
        reassembled.insert(reassembled.end(), part.begin(), part.end());
    }
    const uint64_t piece_gets = fake->GetCount() - gets_before_pieces;

    BOOST_CHECK(whole == payload);
    BOOST_CHECK(reassembled == payload);
    BOOST_CHECK_EQUAL(Sha384Hex(whole), want_hex);
    BOOST_CHECK_EQUAL(Sha384Hex(reassembled), want_hex);

    // Identical bytes, different request cost, measured at the backend rather
    // than derived from the planner. One object per file costs one Class A
    // operation to write and one Class B to read; four piece objects cost four
    // of each for the same payload.
    BOOST_CHECK_EQUAL(source_file_puts, 1U);
    BOOST_CHECK_EQUAL(piece_puts, 4U);
    BOOST_CHECK_EQUAL(whole_gets, 1U);
    BOOST_CHECK_EQUAL(piece_gets, 4U);
    BOOST_CHECK_GT(piece_gets, whole_gets);

    // The published per-object model agrees with the backend here only because
    // each object is served in a single request; r2s_03 pins what happens once
    // a file is large enough to be streamed.
    BOOST_CHECK_EQUAL(modelnet::EstimatedGetsPerColdRetrieval(modelnet::CloudObjectLayout::SOURCE_FILES,
                                                              /*n_files=*/1, /*n_pieces=*/4),
                      whole_gets);
    BOOST_CHECK_EQUAL(modelnet::EstimatedGetsPerColdRetrieval(modelnet::CloudObjectLayout::PIECE_OBJECTS,
                                                              /*n_files=*/1, /*n_pieces=*/4),
                      piece_gets);

    // Keys carry no provider, bucket or layout identity.
    const std::string sf = modelnet::ObjectKeySourceFile(kPrefix, art.Hex(), 0);
    const std::string po = modelnet::ObjectKeyPiece(kPrefix, art.Hex(), 0, 0);
    BOOST_CHECK(sf != po);
    for (const std::string& k : {sf, po}) {
        BOOST_CHECK(k.find("btx-models") == std::string::npos);
        BOOST_CHECK(k.find("cloudflarestorage") == std::string::npos);
        BOOST_CHECK(k.find("SOURCE_FILES") == std::string::npos);
        BOOST_CHECK(k.find("PIECE_OBJECTS") == std::string::npos);
    }

    // Canonical piece arithmetic does not move with the requested layout.
    const uint64_t pieces = modelnet::CanonicalPieceCount(payload.size());
    for (auto req : {modelnet::PhysicalObjectLayout::AUTO, modelnet::PhysicalObjectLayout::PIECE_OBJECTS,
                     modelnet::PhysicalObjectLayout::WHOLE_FILE, modelnet::PhysicalObjectLayout::LARGE_EXTENTS}) {
        BOOST_CHECK_EQUAL(modelnet::PlanObjectLayout(payload.size(), req).piece_objects, pieces);
    }
}

// R2S-03 tripwire. getmodelobjectlayout publishes 64 MiB parts, but
// S3Client::PutStream uploads kCloudStreamChunkBytes parts, and a 400 GiB object
// at that part size exceeds the client's own part ceiling — so the planned
// upload cannot complete and the published Class A count is 8x low.
BOOST_AUTO_TEST_CASE(r2s_02_multipart_part_size_planner_vs_client)
{
    using namespace modelnet;
    const uint64_t planned = MultipartPartCount(OBJECT_LAYOUT_EXAMPLE_BYTES, MULTIPART_PART_BYTES);
    const uint64_t actual = MultipartPartCount(OBJECT_LAYOUT_EXAMPLE_BYTES, kCloudStreamChunkBytes);
    BOOST_CHECK_EQUAL(planned, 6400U);
    BOOST_CHECK_EQUAL(actual, 51200U);
    BOOST_CHECK_EQUAL(PlanObjectLayout(OBJECT_LAYOUT_EXAMPLE_BYTES).multipart_parts, planned);
    BOOST_CHECK_GT(actual, planned);
    BOOST_CHECK_GT(actual, kClientMaxMultipartParts);
    // The largest object the client can finish at its current part size is well
    // short of the illustration, and the ceiling is only noticed mid-upload.
    BOOST_CHECK_LT(kClientMaxMultipartParts * uint64_t{kCloudStreamChunkBytes}, OBJECT_LAYOUT_EXAMPLE_BYTES);
}

// R2S-01 / R2S-02 tripwire. The planning model reports one origin GET per file
// for SOURCE_FILES. The streaming read path issues one request per 64 KiB, so
// the real Class B count for the 400 GiB illustration is six orders of magnitude
// larger. Both numbers are asserted so the gap cannot be quietly restated.
BOOST_AUTO_TEST_CASE(r2s_03_source_files_cold_get_estimate_is_per_object)
{
    using namespace modelnet;
    const uint64_t pieces = CanonicalPieceCount(OBJECT_LAYOUT_EXAMPLE_BYTES);
    BOOST_CHECK_EQUAL(pieces, 102400U);

    const uint64_t modelled = EstimatedGetsPerColdRetrieval(CloudObjectLayout::SOURCE_FILES, /*n_files=*/1, pieces);
    BOOST_CHECK_EQUAL(modelled, 1U);

    const uint64_t streamed = (OBJECT_LAYOUT_EXAMPLE_BYTES + kHydrationReadBytes - 1) / kHydrationReadBytes;
    BOOST_CHECK_EQUAL(streamed, 6553600U);
    BOOST_CHECK_GT(streamed, modelled);
    // Buffering reads at the upload chunk size would cost 128x fewer requests.
    BOOST_CHECK_EQUAL(streamed / MultipartPartCount(OBJECT_LAYOUT_EXAMPLE_BYTES, kCloudStreamChunkBytes), 128U);
}

// R2S-04 tripwire. S3PieceStore::GetObject prechecks only the GET count, then
// transfers, then charges. A response larger than the remaining byte budget is
// fetched (and billed by the provider), discarded, and never recorded — so a
// retrying caller burns real egress while the ledger stays frozen.
BOOST_AUTO_TEST_CASE(r2s_04_over_budget_get_transfers_bytes_and_records_none)
{
    const fs::path creds = m_path_root / "r2s-04-creds";
    WriteCreds(creds, kFixtureAccess, kFixtureSecret);
    modelnet::CloudStoreConfig cfg = BaseCfg(creds);
    cfg.budget_origin_bytes = 8;
    modelnet::S3PieceStore store{cfg};
    std::string err;
    BOOST_REQUIRE_MESSAGE(store.Init(err), err);

    const auto art = ArtifactFill(0x64);
    const auto payload = Payload(64);
    const fs::path src = m_path_root / "r2s-04.bin";
    {
        std::ofstream out(src, std::ios::binary);
        out.write(reinterpret_cast<const char*>(payload.data()), static_cast<std::streamsize>(payload.size()));
    }
    BOOST_REQUIRE_MESSAGE(store.PutSourceFile(art, 0, src, payload.size(), 1, err), err);
    BOOST_REQUIRE(store.FakeForTests());
    const uint64_t gets_before = store.FakeForTests()->GetCount();

    std::vector<unsigned char> got;
    BOOST_CHECK(!store.GetSourceFile(art, 0, got, err));
    BOOST_CHECK(err.find("budget") != std::string::npos);
    BOOST_CHECK(got.empty());

    // The object really was fetched from the backend before being discarded.
    BOOST_CHECK_EQUAL(store.FakeForTests()->GetCount(), gets_before + 1);

    // ...yet nothing about that transfer is recorded as exposure.
    const UniValue h = store.HealthJson();
    BOOST_CHECK_EQUAL(h["origin_bytes"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(h["budget_used_gets"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(h["budget_bytes_remaining"].getInt<int64_t>(), 8);
}

// R2S-05 tripwire. Uploads never touch the ledger, so an exhausted GET budget
// does not bound Class A operations or written bytes.
BOOST_AUTO_TEST_CASE(r2s_05_put_path_is_not_metered)
{
    const fs::path creds = m_path_root / "r2s-05-creds";
    WriteCreds(creds, kFixtureAccess, kFixtureSecret);
    modelnet::CloudStoreConfig cfg = BaseCfg(creds);
    cfg.budget_gets = 0;
    cfg.budget_origin_bytes = 0;
    modelnet::S3PieceStore store{cfg};
    std::string err;
    BOOST_REQUIRE_MESSAGE(store.Init(err), err);

    const auto art = ArtifactFill(0x77);
    const auto payload = Payload(4096);
    const fs::path src = m_path_root / "r2s-05.bin";
    {
        std::ofstream out(src, std::ios::binary);
        out.write(reinterpret_cast<const char*>(payload.data()), static_cast<std::streamsize>(payload.size()));
    }

    // Writes proceed with the budget already at zero.
    BOOST_CHECK_MESSAGE(store.PutSourceFile(art, 0, src, payload.size(), 1, err), err);
    BOOST_REQUIRE(store.FakeForTests());
    BOOST_CHECK_GE(store.FakeForTests()->PutCount(), 1U);
    BOOST_CHECK_EQUAL(store.FakeForTests()->ObjectBytes(modelnet::ObjectKeySourceFile(kPrefix, art.Hex(), 0)),
                      payload.size());

    // Reads are refused, and the ledger shows no upload at all.
    std::vector<unsigned char> got;
    BOOST_CHECK(!store.GetSourceFile(art, 0, got, err));
    const UniValue h = store.HealthJson();
    BOOST_CHECK_EQUAL(h["budget_used_gets"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(h["origin_bytes"].getInt<int64_t>(), 0);
}

// R2S-11. An access key id is only self-identifying for AWS, whose ids start
// with AKIA. A Cloudflare R2 id is 32 hex characters and a MinIO id is an
// arbitrary string, so neither can be masked by shape without also masking
// digests. RedactCloudSecrets masks them by the field name that introduces
// them, and leaves that field name readable.
BOOST_AUTO_TEST_CASE(r2s_06_non_aws_access_key_ids_are_masked_by_field_name)
{
    const std::string aws_key = "AKIAIOSFODNN7EXAMPLE";
    const std::string r2_key = "0123456789abcdef0123456789abcdef";
    const std::string line = "access_key_id=" + r2_key + " and " + aws_key;

    const std::string by_pattern = modelnet::RedactCloudSecrets(line, {});
    BOOST_CHECK(by_pattern.find(aws_key) == std::string::npos);
    BOOST_CHECK(by_pattern.find(r2_key) == std::string::npos);
    BOOST_CHECK(by_pattern.find("access_key_id=") != std::string::npos);

    // A MinIO id has no shape at all, and survives neither spelling of the field.
    const std::string minio = "aws_access_key_id=minioadmin-primary";
    BOOST_CHECK(modelnet::RedactCloudSecrets(minio, {}).find("minioadmin-primary") == std::string::npos);
    BOOST_CHECK(modelnet::RedactCloudSecrets(minio, {}).find("aws_access_key_id=") != std::string::npos);
    const std::string spaced = "access_key = minioadmin-primary";
    BOOST_CHECK(modelnet::RedactCloudSecrets(spaced, {}).find("minioadmin-primary") == std::string::npos);

    // Deliberate boundary: a bare 32-hex token with no credential field around
    // it is a digest or an ETag as often as it is a key id, so it is left alone
    // and the caller must pass it as extra_secret.
    const std::string bare = "etag " + r2_key;
    BOOST_CHECK(modelnet::RedactCloudSecrets(bare, {}).find(r2_key) != std::string::npos);
    BOOST_CHECK(modelnet::RedactCloudSecrets(bare, r2_key).find(r2_key) == std::string::npos);

    // The fixture secret is masked either way, by needle and by extra_secret.
    const std::string secret_line = std::string("aws_secret_access_key=") + kFixtureSecret;
    BOOST_CHECK(modelnet::RedactCloudSecrets(secret_line, {}).find(kFixtureSecret) == std::string::npos);
    BOOST_CHECK(modelnet::RedactCloudSecrets(secret_line, kFixtureSecret).find(kFixtureSecret) == std::string::npos);
    BOOST_CHECK(modelnet::RedactCloudSecrets(secret_line, {}).find("aws_secret_access_key=") != std::string::npos);
}

// MinIO status is NOT_RUN. Nothing here starts, reaches or proves a MinIO
// server: it covers provider-name plumbing and the loopback-only http rule.
// SigV4 over http against a live S3-compatible server, real multipart, real
// Range responses and real ETag handling all remain unproven.
BOOST_AUTO_TEST_CASE(r2s_07_minio_is_config_only_not_run)
{
    using namespace modelnet;
    CloudProvider p = CloudProvider::AUTO;
    BOOST_REQUIRE(CloudProviderFromName("minio", p));
    BOOST_CHECK(p == CloudProvider::MINIO);
    BOOST_CHECK_EQUAL(CloudProviderName(p), "MINIO");
    // MINIO is never inferred from an endpoint; only R2 has hostname detection.
    BOOST_CHECK(!CloudProviderIsR2(CloudProvider::MINIO, "https://acct.r2.cloudflarestorage.com"));

    std::string err;
    BOOST_CHECK(!ValidateS3Endpoint("http://127.0.0.1:9000", /*allow_http_loopback=*/false,
                                    /*allow_link_local=*/false, err));
    BOOST_CHECK(ValidateS3Endpoint("http://127.0.0.1:9000", true, false, err));
    BOOST_CHECK(ValidateS3Endpoint("http://localhost:9000", true, false, err));
    // Non-loopback http stays refused even with the loopback allowance on.
    BOOST_CHECK(!ValidateS3Endpoint("http://minio.internal.example:9000", true, false, err));
    BOOST_CHECK(!ValidateS3Endpoint("http://169.254.169.254:9000", true, false, err));
}

// R2S-09 tripwire. A distinct upload capability cannot be signed against FakeS3:
// Init seeds the fake with the read key only, so every write-credential PUT
// fails SigV4 verification. write_creds is also unreachable from
// setcloudstorage, so this shape is only constructible in-process.
BOOST_AUTO_TEST_CASE(r2s_08_write_creds_break_fake_signing)
{
    const fs::path read_creds = m_path_root / "r2s-08-read-creds";
    const fs::path write_creds = m_path_root / "r2s-08-write-creds";
    WriteCreds(read_creds, kFixtureAccess, kFixtureSecret);
    WriteCreds(write_creds, "AKIAR2LANEWRITEKEY00", "r2-lane-write-secret-not-real");

    modelnet::S3ClientConfig cfg = BaseCfg(read_creds).s3;
    cfg.write_creds = modelnet::CredentialRef{modelnet::CredentialRefKind::PATH, fs::PathToString(write_creds)};

    modelnet::S3Client client;
    std::string err;
    BOOST_REQUIRE_MESSAGE(client.Init(cfg, err), err);
    BOOST_CHECK(client.ConfigJson()["write_creds_distinct"].get_bool());

    const std::vector<unsigned char> body{'w'};
    BOOST_CHECK(!client.Put("r2s-08/object", body, err));
    BOOST_CHECK(err.find("sigv4") != std::string::npos);

    // The refused write stored nothing.
    BOOST_REQUIRE(client.Fake());
    BOOST_CHECK_EQUAL(client.Fake()->ObjectCount(), 0U);
}

BOOST_AUTO_TEST_CASE(r2s_09_physical_whole_file_and_large_extents_fakes3)
{
    const fs::path creds = m_path_root / "r2s-09-creds";
    WriteCreds(creds, kFixtureAccess, kFixtureSecret);
    modelnet::CloudStoreConfig cfg = BaseCfg(creds);
    modelnet::S3PieceStore store{cfg};
    std::string err;
    BOOST_REQUIRE_MESSAGE(store.Init(err), err);

    modelnet::Digest48 artifact;
    artifact.data.fill(0x42);
    const std::vector<unsigned char> whole{'w', 'h', 'o', 'l', 'e'};
    BOOST_REQUIRE(store.PutWholeFile(artifact, 0, Span<const unsigned char>{whole}, err));
    std::vector<unsigned char> got;
    BOOST_REQUIRE(store.GetWholeFile(artifact, 0, got, err));
    BOOST_CHECK_EQUAL_COLLECTIONS(got.begin(), got.end(), whole.begin(), whole.end());

    const std::vector<unsigned char> ext0{'e', '0'};
    const std::vector<unsigned char> ext1{'e', '1'};
    BOOST_REQUIRE(store.PutLargeExtent(artifact, 0, 0, Span<const unsigned char>{ext0}, err));
    BOOST_REQUIRE(store.PutLargeExtent(artifact, 0, 1, Span<const unsigned char>{ext1}, err));
    got.clear();
    BOOST_REQUIRE(store.GetLargeExtent(artifact, 0, 0, got, err));
    BOOST_CHECK_EQUAL_COLLECTIONS(got.begin(), got.end(), ext0.begin(), ext0.end());
    got.clear();
    BOOST_REQUIRE(store.GetLargeExtent(artifact, 0, 1, got, err));
    BOOST_CHECK_EQUAL_COLLECTIONS(got.begin(), got.end(), ext1.begin(), ext1.end());

    const auto plan = modelnet::PlanObjectLayout(whole.size() + ext0.size() + ext1.size(),
                                                 modelnet::PhysicalObjectLayout::WHOLE_FILE);
    BOOST_CHECK(!plan.replaces_source_files);
}

BOOST_AUTO_TEST_SUITE_END()
