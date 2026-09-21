// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/util/setup_common.h>
#include <crypto/sha384.h>
#include <modelnet/direct_seed.h>
#include <modelnet/file_stream.h>
#include <modelnet/store.h>
#include <modelnet/types.h>
#include <span.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/readwritefile.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_file_stream_tests, BasicTestingSetup)

namespace {

modelnet::Digest48 DigestOf(const std::vector<unsigned char>& bytes)
{
    modelnet::Digest48 d;
    CSHA384 hasher;
    if (!bytes.empty()) hasher.Write(bytes.data(), bytes.size());
    hasher.Finalize(d.data.data());
    return d;
}

fs::path Scratch(const fs::path& root, const std::string& name)
{
    const fs::path p = root / name.c_str();
    fs::create_directories(p);
    return p;
}

} // namespace

BOOST_AUTO_TEST_CASE(fullcloud_04_05_stream_segments_and_verifies)
{
    using namespace modelnet;
    std::vector<unsigned char> file(PIECE_SIZE + 123, 0x5a);
    file[0] = 0x11;
    file.back() = 0x22;
    Digest48 artifact{};
    artifact.data[0] = 0xab;

    ModelStore live(Scratch(m_path_root, "live"), 64 << 20);
    ModelStore q(Scratch(m_path_root, "q"), 64 << 20);
    FileStreamHydration hyd(artifact, 0, file.size(), live, q);
    hyd.SetExpectedSha384(DigestOf(file));

    size_t pos = 0;
    auto read = [&](size_t want, unsigned char* buf, size_t& got, std::string& err) {
        (void)err;
        got = std::min(want, file.size() - pos);
        if (got) std::memcpy(buf, file.data() + pos, got);
        pos += got;
        return true;
    };
    std::string err;
    BOOST_REQUIRE_MESSAGE(hyd.Ingest(read, false, err), err);
    BOOST_CHECK(hyd.IsAdvertisable());
    BOOST_CHECK_EQUAL(hyd.Progress().origin_get_ops, 1);
    BOOST_CHECK_EQUAL(hyd.Progress().pieces_verified, 2);
    BOOST_CHECK(live.HasPiece(artifact, 0, 0));
    BOOST_CHECK(live.HasPiece(artifact, 0, 1));
    PieceIndex idx;
    BOOST_REQUIRE(live.LoadPieceIndex(artifact, 0, idx, err));
    std::vector<unsigned char> p0;
    BOOST_REQUIRE(live.GetPiece(artifact, 0, 0, p0, err));
    BOOST_CHECK(VerifyPiece(idx.pieces_root, file.size(), 0, p0, PieceProof(BuildChunkTreeFromLeaves(idx.leaves), 0)));
}

BOOST_AUTO_TEST_CASE(fullcloud_06_mid_file_corruption_fails)
{
    using namespace modelnet;
    std::vector<unsigned char> file(PIECE_SIZE * 2, 0x33);
    Digest48 artifact{};
    artifact.data[0] = 0xcd;
    ModelStore live(Scratch(m_path_root, "live2"), 64 << 20);
    ModelStore q(Scratch(m_path_root, "q2"), 64 << 20);
    FileStreamHydration hyd(artifact, 0, file.size(), live, q);
    hyd.SetExpectedSha384(DigestOf(file));
    file[PIECE_SIZE + 4] ^= 0xff;
    size_t pos = 0;
    auto read = [&](size_t want, unsigned char* buf, size_t& got, std::string& err) {
        (void)err;
        got = std::min(want, file.size() - pos);
        if (got) std::memcpy(buf, file.data() + pos, got);
        pos += got;
        return true;
    };
    std::string err;
    BOOST_CHECK(!hyd.Ingest(read, false, err));
    BOOST_CHECK(err.find("SHA-384") != std::string::npos);
    BOOST_CHECK(!hyd.IsAdvertisable());
}

BOOST_AUTO_TEST_CASE(fullcloud_07_unverified_not_advertised)
{
    using namespace modelnet;
    std::vector<unsigned char> file(100, 0x01);
    Digest48 artifact{};
    artifact.data[0] = 0xee;
    ModelStore live(Scratch(m_path_root, "live3"), 64 << 20);
    ModelStore q(Scratch(m_path_root, "q3"), 64 << 20);
    FileStreamHydration hyd(artifact, 0, file.size(), live, q);
    std::string err;
    BOOST_REQUIRE(hyd.Feed(Span<const unsigned char>{file.data(), file.size()}, err));
    BOOST_CHECK(!hyd.IsAdvertisable());
    BOOST_CHECK(hyd.Progress().quarantined);
    BOOST_REQUIRE(hyd.Finish(err));
    BOOST_CHECK(hyd.IsAdvertisable());
}

BOOST_AUTO_TEST_CASE(fullcloud_08_resume_is_one_range_not_per_piece)
{
    using namespace modelnet;
    std::vector<unsigned char> file(PIECE_SIZE * 3, 0x44);
    Digest48 artifact{};
    artifact.data[0] = 0x11;
    ModelStore live(Scratch(m_path_root, "live4"), 64 << 20);
    ModelStore q(Scratch(m_path_root, "q4"), 64 << 20);
    FileStreamHydration hyd(artifact, 0, file.size(), live, q);
    hyd.SetExpectedSha384(DigestOf(file));
    std::string err;
    BOOST_REQUIRE(hyd.Feed(Span<const unsigned char>{file.data(), PIECE_SIZE}, err));
    BOOST_CHECK_EQUAL(hyd.ResumeOffset(), PIECE_SIZE);
    size_t pos = PIECE_SIZE;
    auto read = [&](size_t want, unsigned char* buf, size_t& got, std::string& err) {
        (void)err;
        got = std::min(want, file.size() - pos);
        if (got) std::memcpy(buf, file.data() + pos, got);
        pos += got;
        return true;
    };
    BOOST_REQUIRE_MESSAGE(hyd.Ingest(read, true, err), err);
    BOOST_CHECK_EQUAL(hyd.Progress().origin_get_ops, 0);
    BOOST_CHECK_EQUAL(hyd.Progress().origin_range_ops, 1);
    BOOST_CHECK_EQUAL(hyd.Progress().pieces_verified, 3);
}

BOOST_AUTO_TEST_CASE(fullcloud_08_resume_offset_is_n_times_piece_size)
{
    using namespace modelnet;
    std::vector<unsigned char> file(PIECE_SIZE * 3 + 50, 0x71);
    Digest48 artifact{};
    artifact.data[0] = 0x08;
    ModelStore live(Scratch(m_path_root, "live08n"), 64 << 20);
    ModelStore q(Scratch(m_path_root, "q08n"), 64 << 20);
    FileStreamHydration hyd(artifact, 0, file.size(), live, q);
    std::string err;
    BOOST_CHECK_EQUAL(hyd.ResumeOffset(), uint64_t{0});
    BOOST_REQUIRE(hyd.Feed(Span<const unsigned char>{file.data(), PIECE_SIZE}, err));
    BOOST_CHECK_EQUAL(hyd.ResumeOffset(), uint64_t{1} * PIECE_SIZE);
    BOOST_REQUIRE(hyd.Feed(Span<const unsigned char>{file.data() + PIECE_SIZE, PIECE_SIZE}, err));
    BOOST_CHECK_EQUAL(hyd.ResumeOffset(), uint64_t{2} * PIECE_SIZE);
    BOOST_CHECK_EQUAL(hyd.ResumeOffset() % PIECE_SIZE, uint64_t{0});
    BOOST_CHECK_EQUAL(hyd.Progress().next_piece, 2U);
    const FileStreamJobRecord rec = hyd.ToRecord();
    BOOST_CHECK_EQUAL(rec.next_piece, 2U);
    BOOST_CHECK_EQUAL(rec.resume_offset, uint64_t{2} * PIECE_SIZE);
    BOOST_CHECK_EQUAL(rec.resume_offset, uint64_t{rec.next_piece} * PIECE_SIZE);
}

BOOST_AUTO_TEST_CASE(fullcloud_01_18_amplification_and_diversity)
{
    using namespace modelnet;
    const auto amp = CloudAmplificationJson(1, 102400, true);
    BOOST_CHECK_EQUAL(amp["cloud_source_objects"].getInt<int64_t>(), 1);
    BOOST_CHECK_EQUAL(amp["estimated_cloud_gets_per_cold_full_retrieval"].getInt<int64_t>(), 1);
    BOOST_CHECK_EQUAL(amp["piece_object_equivalent_gets"].getInt<int64_t>(), 102400);
    const auto d = SummarizeOriginDiversity(5, 0, 2, {"r2:bucket-a", "r2:bucket-a", "r2:bucket-a"}, false);
    BOOST_CHECK_EQUAL(d.p2p_complete_providers, 5);
    BOOST_CHECK_EQUAL(d.cloud_origins, 1);
    BOOST_CHECK(!d.reconstructable_without_origin);
}

BOOST_AUTO_TEST_CASE(fullcloud_19_hydration_coalesce)
{
    using namespace modelnet;
    Digest48 a{};
    a.data[0] = 1;
    HydrationCoalescer c;
    std::string err;
    BOOST_REQUIRE(c.TryBegin(a, 0, err));
    BOOST_CHECK(!c.TryBegin(a, 0, err));
    BOOST_CHECK_EQUAL(c.InFlight(a, 0), 1);
    c.End(a, 0);
    BOOST_REQUIRE(c.TryBegin(a, 0, err));
    c.End(a, 0);
}

BOOST_AUTO_TEST_CASE(webseed_ssrf_and_redact)
{
    using namespace modelnet;
    DirectSeedPolicy pol;
    pol.enabled = true;
    pol.allowed_https_host = "example.r2.cloudflarestorage.com";
    std::string err;
    BOOST_CHECK(!DirectSeedUrlAllowed("file:///etc/passwd", pol, err));
    BOOST_CHECK(!DirectSeedUrlAllowed("https://169.254.169.254/latest", pol, err));
    BOOST_CHECK(!DirectSeedUrlAllowed("https://evil.example/obj", pol, err));
    BOOST_CHECK(DirectSeedUrlAllowed("https://example.r2.cloudflarestorage.com/obj", pol, err));
    const std::string red = RedactPresignedUrl("https://example.r2.cloudflarestorage.com/obj?X-Amz-Signature=SECRET");
    BOOST_CHECK(red.find("SECRET") == std::string::npos);
    DirectSeedOffer o;
    o.presigned_get = "https://example.r2.cloudflarestorage.com/obj?X-Amz-Signature=SECRET";
    o.expires_at_ms = 1;
    const UniValue pub = DirectSeedOfferPublicJson(o);
    BOOST_CHECK(pub.write().find("SECRET") == std::string::npos);
    BOOST_CHECK(DirectSeedExpired(2, o));
}

BOOST_AUTO_TEST_CASE(fullcloud_21_22_r2_no_piece_get)
{
    using namespace modelnet;
    BOOST_CHECK(PlanSourceFilesPieceRequest(true, false, false, false, false) == SourceFilesPiecePlan::LOCAL_CACHE);
    BOOST_CHECK(PlanSourceFilesPieceRequest(false, true, false, false, false) == SourceFilesPiecePlan::P2P);
    BOOST_CHECK(PlanSourceFilesPieceRequest(false, false, true, false, false) == SourceFilesPiecePlan::JOIN_HYDRATION);
    BOOST_CHECK(PlanSourceFilesPieceRequest(false, false, false, false, false) == SourceFilesPiecePlan::START_FILE_STREAM);
    BOOST_CHECK(PlanSourceFilesPieceRequest(false, false, false, false, false) != SourceFilesPiecePlan::ORIGIN_RANGE_PIECE);
    BOOST_CHECK(PlanSourceFilesPieceRequest(false, false, false, true, false) == SourceFilesPiecePlan::ORIGIN_RANGE_PIECE);
}

BOOST_AUTO_TEST_CASE(h_t2_sparse_400gib_receipt)
{
    using namespace modelnet;
    constexpr uint64_t logical = 400ull * 1024ull * 1024ull * 1024ull;
    BOOST_CHECK_EQUAL(logical / PIECE_SIZE, uint64_t{102400});
    const UniValue rec = SparseOriginScaleReceiptJson(logical, /*stored=*/19, /*gets=*/1, /*files=*/1);
    BOOST_CHECK_EQUAL(rec["origin_get_ops"].getInt<int64_t>(), 1);
    BOOST_CHECK_EQUAL(rec["logical_btx_pieces"].getInt<int64_t>(), 102400);
    BOOST_CHECK_EQUAL(rec["piece_object_equivalent_gets"].getInt<int64_t>(), 102400);
    BOOST_CHECK(rec["sparse"].get_bool());
    BOOST_CHECK_EQUAL(rec["layout"].get_str(), "SOURCE_FILES");
}

BOOST_AUTO_TEST_CASE(h_t3_origin_stampede_caps_and_breaker)
{
    using namespace modelnet;
    OriginStampedeState s;
    s.window_ms = 1000;
    s.max_per_peer = 2;
    s.max_per_netgroup = 3;
    s.errors_to_open = 2;
    s.open_ms = 50;
    OriginStampedeGuard g(s);
    std::string err;
    BOOST_REQUIRE(g.Allow("p1", "ng1", 10, err));
    BOOST_REQUIRE(g.Allow("p1", "ng1", 11, err));
    BOOST_CHECK(!g.Allow("p1", "ng1", 12, err));
    BOOST_CHECK(err.find("per-peer") != std::string::npos);
    BOOST_REQUIRE(g.Allow("p2", "ng1", 13, err));
    BOOST_CHECK(!g.Allow("p3", "ng1", 14, err));
    BOOST_CHECK(err.find("per-netgroup") != std::string::npos);
    g.NoteError("p4", 20);
    BOOST_CHECK(!g.CircuitOpen("p4", 20));
    g.NoteError("p4", 21);
    BOOST_CHECK(g.CircuitOpen("p4", 21));
    BOOST_CHECK(!g.Allow("p4", "ng2", 22, err));
    BOOST_CHECK(err.find("circuit") != std::string::npos);
    BOOST_CHECK(g.Json(22)["circuits_open"].getInt<int>() >= 1);
}

BOOST_AUTO_TEST_CASE(fullcloud_09_file_stream_job_roundtrip)
{
    using namespace modelnet;
    Digest48 artifact{};
    artifact.data[0] = 0x09;
    Digest48 sha{};
    sha.data[0] = 0x38;
    Digest48 root{};
    root.data[0] = 0x72;
    FileStreamJob j;
    j.artifact = artifact;
    j.file_index = 3;
    j.expected_size = uint64_t{5} * PIECE_SIZE + 99;
    j.resume_offset = uint64_t{4} * PIECE_SIZE;
    j.expected_sha384 = sha;
    j.expected_root = root;
    j.have_sha = true;
    j.have_root = true;

    const fs::path dir = Scratch(m_path_root, "jobs-roundtrip");
    std::string err;
    BOOST_REQUIRE_MESSAGE(SaveFileStreamJob(dir, j, err), err);
    FileStreamJob loaded;
    BOOST_REQUIRE_MESSAGE(LoadFileStreamJob(dir, artifact, 3, loaded, err), err);
    BOOST_CHECK(loaded.artifact == artifact);
    BOOST_CHECK_EQUAL(loaded.file_index, 3U);
    BOOST_CHECK_EQUAL(loaded.expected_size, j.expected_size);
    BOOST_CHECK_EQUAL(loaded.resume_offset, j.resume_offset);
    BOOST_CHECK_EQUAL(loaded.resume_offset % PIECE_SIZE, uint64_t{0});
    BOOST_CHECK(loaded.have_sha);
    BOOST_CHECK(loaded.have_root);
    BOOST_CHECK(loaded.expected_sha384 == sha);
    BOOST_CHECK(loaded.expected_root == root);
}

BOOST_AUTO_TEST_CASE(fullcloud_09_resume_offset_must_be_piece_aligned)
{
    using namespace modelnet;
    Digest48 artifact{};
    artifact.data[0] = 0x0a;
    FileStreamJob j;
    j.artifact = artifact;
    j.file_index = 0;
    j.expected_size = PIECE_SIZE * 2;
    j.resume_offset = PIECE_SIZE + 1;
    const fs::path dir = Scratch(m_path_root, "jobs-unaligned");
    std::string err;
    BOOST_CHECK(!SaveFileStreamJob(dir, j, err));
    BOOST_CHECK(err.find("PIECE_SIZE") != std::string::npos);

    j.resume_offset = PIECE_SIZE;
    BOOST_REQUIRE_MESSAGE(SaveFileStreamJob(dir, j, err), err);
    const auto [ok, raw] = ReadBinaryFile(FileStreamJobPath(dir, artifact, 0));
    BOOST_REQUIRE(ok);
    UniValue obj;
    BOOST_REQUIRE(obj.read(raw));
    obj.pushKV("resume_offset", static_cast<int64_t>(PIECE_SIZE / 2));
    BOOST_REQUIRE(WriteBinaryFile(FileStreamJobPath(dir, artifact, 0), obj.write() + "\n"));
    FileStreamJob loaded;
    BOOST_CHECK(!LoadFileStreamJob(dir, artifact, 0, loaded, err));
    BOOST_CHECK(err.find("PIECE_SIZE") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(fullcloud_09_helper_restart_one_range)
{
    using namespace modelnet;
    std::vector<unsigned char> file(PIECE_SIZE * 3, 0x46);
    file[0] = 0x01;
    file[PIECE_SIZE] = 0x02;
    file.back() = 0x03;
    Digest48 artifact{};
    artifact.data[0] = 0x34;
    const fs::path jobs = Scratch(m_path_root, "jobs-restart");
    ModelStore live(Scratch(m_path_root, "live-restart"), 64 << 20);
    ModelStore q(Scratch(m_path_root, "q-restart"), 64 << 20);
    std::string err;
    {
        FileStreamHydration hyd(artifact, 0, file.size(), live, q);
        hyd.SetJobDir(jobs);
        hyd.SetExpectedSha384(DigestOf(file));
        BOOST_REQUIRE_MESSAGE(hyd.Feed(Span<const unsigned char>{file.data(), PIECE_SIZE}, err), err);
        BOOST_CHECK_EQUAL(hyd.ResumeOffset(), PIECE_SIZE);
        BOOST_CHECK_EQUAL(hyd.ResumeOffset() % PIECE_SIZE, uint64_t{0});
        BOOST_CHECK(fs::exists(FileStreamJobPath(jobs, artifact, 0)));
    }

    FileStreamJob job;
    BOOST_REQUIRE_MESSAGE(LoadFileStreamJob(jobs, artifact, 0, job, err), err);
    BOOST_CHECK_EQUAL(job.resume_offset, PIECE_SIZE);
    BOOST_CHECK_EQUAL(job.resume_offset % PIECE_SIZE, uint64_t{0});
    BOOST_CHECK_EQUAL(job.expected_size, file.size());

    FileStreamHydration hyd2(artifact, 0, file.size(), live, q);
    hyd2.SetJobDir(jobs);
    BOOST_REQUIRE_MESSAGE(hyd2.ApplyJob(job, err), err);
    BOOST_CHECK_EQUAL(hyd2.ResumeOffset(), job.resume_offset);
    BOOST_CHECK_EQUAL(hyd2.ResumeOffset(), PIECE_SIZE);

    size_t pos = hyd2.ResumeOffset();
    auto read = [&](size_t want, unsigned char* buf, size_t& got, std::string& rerr) {
        (void)rerr;
        got = std::min(want, file.size() - pos);
        if (got) std::memcpy(buf, file.data() + pos, got);
        pos += got;
        return true;
    };
    BOOST_REQUIRE_MESSAGE(hyd2.Ingest(read, /*resume=*/true, err), err);
    BOOST_CHECK_EQUAL(hyd2.Progress().origin_get_ops, 0);
    BOOST_CHECK_EQUAL(hyd2.Progress().origin_range_ops, 1);
    BOOST_CHECK_EQUAL(hyd2.Progress().pieces_verified, 3);
    BOOST_CHECK(hyd2.IsAdvertisable());
    BOOST_CHECK(!fs::exists(FileStreamJobPath(jobs, artifact, 0)));
}

BOOST_AUTO_TEST_CASE(fullcloud_09_job_json_no_secrets_or_query)
{
    using namespace modelnet;
    Digest48 artifact{};
    artifact.data[0] = 0x0b;
    FileStreamJob j;
    j.artifact = artifact;
    j.file_index = 1;
    j.expected_size = PIECE_SIZE;
    j.resume_offset = PIECE_SIZE;
    const fs::path dir = Scratch(m_path_root, "jobs-redact");
    std::string err;
    BOOST_REQUIRE_MESSAGE(SaveFileStreamJob(dir, j, err), err);
    const auto [ok, raw] = ReadBinaryFile(FileStreamJobPath(dir, artifact, 1));
    BOOST_REQUIRE(ok);
    BOOST_CHECK(raw.find("SECRET") == std::string::npos);
    BOOST_CHECK(raw.find('?') == std::string::npos);
    BOOST_CHECK(raw.find("://") == std::string::npos);
    BOOST_CHECK(raw.find("X-Amz-") == std::string::npos);
    BOOST_CHECK(raw.find("presigned") == std::string::npos);
    UniValue obj;
    BOOST_REQUIRE(obj.read(raw));
    BOOST_CHECK_EQUAL(obj["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(obj["artifact"].get_str(), artifact.Hex());
    BOOST_CHECK_EQUAL(obj["file_index"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(obj["expected_size"].getInt<int64_t>(), static_cast<int64_t>(PIECE_SIZE));
    BOOST_CHECK_EQUAL(obj["resume_offset"].getInt<int64_t>(), static_cast<int64_t>(PIECE_SIZE));

    UniValue bad = obj;
    bad.pushKV("url", "https://example.r2.cloudflarestorage.com/obj?X-Amz-Signature=SECRET");
    BOOST_REQUIRE(WriteBinaryFile(FileStreamJobPath(dir, artifact, 1), bad.write() + "\n"));
    FileStreamJob loaded;
    BOOST_CHECK(!LoadFileStreamJob(dir, artifact, 1, loaded, err));
}

BOOST_AUTO_TEST_CASE(fullcloud_09_job_persists_across_reload)
{
    using namespace modelnet;
    Digest48 artifact{};
    artifact.data[0] = 0x09;
    artifact.data[1] = 0x72;
    FileStreamJobRecord rec;
    rec.artifact = artifact;
    rec.file_index = 2;
    rec.expected_size = uint64_t{7} * PIECE_SIZE;
    rec.next_piece = 3;
    rec.resume_offset = uint64_t{3} * PIECE_SIZE;
    rec.have_sha = true;
    rec.expected_sha384.data[0] = 0x38;
    rec.have_root = true;
    rec.expected_root.data[0] = 0x72;

    const fs::path modeldir = Scratch(m_path_root, "modeldir-reload");
    std::string err;
    BOOST_REQUIRE_MESSAGE(SaveFileStreamJob(modeldir, rec, err), err);

    const fs::path path = FileStreamJobPath(modeldir, artifact, 2);
    BOOST_CHECK_EQUAL(fs::PathToString(path.parent_path()), fs::PathToString(FileStreamJobDir(modeldir)));
    BOOST_CHECK_EQUAL(fs::PathToString(path.filename()), artifact.Hex() + "-2.json");
    BOOST_CHECK(fs::exists(path));
    const auto [ok, raw] = ReadBinaryFile(path);
    BOOST_REQUIRE(ok);
    BOOST_CHECK(raw.find("SECRET") == std::string::npos);
    BOOST_CHECK(raw.find('?') == std::string::npos);
    BOOST_CHECK(raw.find("://") == std::string::npos);

    FileStreamJobRecord loaded;
    BOOST_REQUIRE_MESSAGE(LoadFileStreamJob(modeldir, artifact, 2, loaded, err), err);
    BOOST_CHECK_EQUAL(loaded.resume_offset, rec.resume_offset);
    BOOST_CHECK_EQUAL(loaded.next_piece, 3U);
    BOOST_CHECK_EQUAL(loaded.resume_offset, uint64_t{loaded.next_piece} * PIECE_SIZE);
    BOOST_CHECK_EQUAL(loaded.expected_size, rec.expected_size);
    BOOST_CHECK(loaded.have_sha);
    BOOST_CHECK(loaded.have_root);

    ModelStore live(Scratch(m_path_root, "live-reload09"), 64 << 20);
    ModelStore q(Scratch(m_path_root, "q-reload09"), 64 << 20);
    FileStreamHydration hyd(artifact, 2, rec.expected_size, live, q);
    BOOST_REQUIRE_MESSAGE(hyd.ApplyRecord(loaded, err), err);
    BOOST_CHECK_EQUAL(hyd.ResumeOffset(), loaded.resume_offset);
    BOOST_CHECK_EQUAL(hyd.Progress().next_piece, 3U);
    BOOST_CHECK_EQUAL(hyd.ToRecord().resume_offset, loaded.resume_offset);

    BOOST_REQUIRE_MESSAGE(DeleteFileStreamJob(modeldir, artifact, 2, err), err);
    BOOST_CHECK(!fs::exists(path));
    FileStreamJobRecord gone;
    BOOST_CHECK(!LoadFileStreamJob(modeldir, artifact, 2, gone, err));

    FileStreamJobRecord bad = rec;
    bad.resume_offset = 1;
    BOOST_CHECK(!SaveFileStreamJob(modeldir, bad, err));
    BOOST_CHECK(err.find("PIECE_SIZE") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(direct_seed_rate_and_netgroup_limits)
{
    using namespace modelnet;
    DirectSeedLimits lim;
    lim.ttl_ms = 60 * 1000;
    lim.max_per_peer_per_minute = 1;
    lim.max_per_netgroup_per_minute = 2;
    lim.max_concurrent = 3;
    DirectSeedAdmissionState st;
    std::string err;
    BOOST_CHECK_EQUAL(DirectSeedNetgroup("10.1.2.3:29447"), "10.1.2.0");
    BOOST_REQUIRE(DirectSeedAllowIssue(st, lim, "10.1.2.3:29447", DirectSeedNetgroup("10.1.2.3:29447"), 1000, err));
    BOOST_CHECK(!DirectSeedAllowIssue(st, lim, "10.1.2.3:29447", DirectSeedNetgroup("10.1.2.3:29447"), 2000, err));
    BOOST_CHECK(err.find("peer rate") != std::string::npos);
    BOOST_REQUIRE(DirectSeedAllowIssue(st, lim, "10.1.2.9:29447", DirectSeedNetgroup("10.1.2.9:29447"), 3000, err));
    BOOST_CHECK(!DirectSeedAllowIssue(st, lim, "10.1.2.8:29447", DirectSeedNetgroup("10.1.2.8:29447"), 4000, err));
    BOOST_CHECK(err.find("netgroup") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
