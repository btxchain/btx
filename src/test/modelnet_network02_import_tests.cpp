// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// NETWORK-02 Lane D import adapters. Coordinator wires this file into test_btx CMake later.

#include <modelnet/import_coordinator.h>
#include <modelnet/source_huggingface.h>
#include <modelnet/source_torrent.h>
#include <modelnet/source_xet.h>
#include <modelnet/verified_manifest.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_network02_import_tests, BasicTestingSetup)

namespace {

modelnet::ImportPlan SamplePlan(modelnet::ImportSourceKind kind, const std::string& locator)
{
    modelnet::ImportPlan plan;
    plan.plan_id = std::string(96, 'a');
    plan.kind = kind;
    plan.locator = locator;
    plan.snapshot_token = "rev-fixture";
    plan.provenance_note = "source_integrity_only;not_publisher_authorship";
    modelnet::ImportFileSpec f;
    f.source_path = "model.safetensors";
    f.destination_path = "model.safetensors";
    f.size_bytes = 5;
    plan.files.push_back(std::move(f));
    return plan;
}

} // namespace

BOOST_AUTO_TEST_CASE(hf_ssrf_pin_and_no_live_http)
{
    std::string err;
    modelnet::HuggingFaceByteSource loopback{"http://127.0.0.1/x", "rev1"};
    BOOST_CHECK(!loopback.Pin(err));
    BOOST_CHECK_EQUAL(err, "ssrf");

    modelnet::HuggingFaceByteSource localnet{"https://192.168.1.9/model", "rev1"};
    BOOST_CHECK(!localnet.Pin(err));
    BOOST_CHECK_EQUAL(err, "ssrf");

    modelnet::HuggingFaceByteSource linklocal{"https://169.254.1.1/model", "rev1"};
    BOOST_CHECK(!linklocal.Pin(err));
    BOOST_CHECK_EQUAL(err, "ssrf");

    modelnet::HuggingFaceByteSource v6{"https://[::1]/model", "rev1"};
    BOOST_CHECK(!v6.Pin(err));
    BOOST_CHECK_EQUAL(err, "ssrf");

    modelnet::HuggingFaceByteSource rfc10{"https://10.0.0.1/model", "rev1"};
    BOOST_CHECK(!rfc10.Pin(err));
    BOOST_CHECK_EQUAL(err, "ssrf");

    modelnet::HuggingFaceByteSource rfc172{"https://172.16.1.1/model", "rev1"};
    BOOST_CHECK(!rfc172.Pin(err));
    BOOST_CHECK_EQUAL(err, "ssrf");

    modelnet::HuggingFaceByteSource meta{"https://169.254.169.254/latest/meta-data", "rev1"};
    BOOST_CHECK(!meta.Pin(err));
    BOOST_CHECK_EQUAL(err, "ssrf");

    modelnet::HuggingFaceByteSource gce{"https://metadata.google.internal/", "rev1"};
    BOOST_CHECK(!gce.Pin(err));
    BOOST_CHECK_EQUAL(err, "ssrf");

    modelnet::HuggingFaceByteSource path_not_host{"https://huggingface.co/org/model-v10.2", "rev1"};
    BOOST_REQUIRE(path_not_host.Pin(err));

    modelnet::HuggingFaceByteSource file_url{"file:///etc/passwd", "rev1"};
    BOOST_CHECK(!file_url.Pin(err));
    BOOST_CHECK_EQUAL(err, "scheme");

    modelnet::HuggingFaceByteSource unix_url{"unix:///tmp/socket", "rev1"};
    BOOST_CHECK(!unix_url.Pin(err));
    BOOST_CHECK_EQUAL(err, "scheme");

    modelnet::HuggingFaceByteSource gopher{"gopher://example.com/1", "rev1"};
    BOOST_CHECK(!gopher.Pin(err));
    BOOST_CHECK_EQUAL(err, "scheme");

    modelnet::HuggingFaceByteSource redirects{"https://huggingface.co/org/model", "rev1", /*follow_redirects=*/true};
    BOOST_CHECK(!redirects.Pin(err));
    BOOST_CHECK_EQUAL(err, "redirects forbidden");
    BOOST_CHECK(!redirects.FollowsRedirects());

    modelnet::HuggingFaceByteSource ok{"https://huggingface.co/org/model", "rev1"};
    BOOST_REQUIRE(ok.Pin(err));
    BOOST_CHECK_EQUAL(ok.SourceIntegrity(), "rev1");
    BOOST_CHECK_EQUAL(ok.Kind(), "HUGGINGFACE");
    std::vector<unsigned char> out;
    BOOST_CHECK(!ok.Read({0, 1}, out, 16, err));
    BOOST_CHECK_EQUAL(err, "not wired to live network");
}

BOOST_AUTO_TEST_CASE(hf_inject_test_bytes_only)
{
    modelnet::HuggingFaceByteSource src{"https://huggingface.co/org/model", "snap-abc"};
    src.InjectTestBytes(std::vector<unsigned char>{'h', 'e', 'l', 'l', 'o'});
    std::string err;
    BOOST_REQUIRE(src.Pin(err));
    std::vector<unsigned char> out;
    BOOST_CHECK(!src.Read({0, 5}, out, /*budget=*/2, err));
    BOOST_CHECK_EQUAL(err, "credit exhausted");
    BOOST_REQUIRE(src.Read({1, 3}, out, 8, err));
    BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), "ell");
    BOOST_CHECK_EQUAL(src.SourceIntegrity(), "snap-abc");
}

BOOST_AUTO_TEST_CASE(xet_cas_reconstruct_not_identity)
{
    modelnet::XetByteSource src{"https://huggingface.co/org/model", "cas-root-1"};
    modelnet::XetChunkMap chunks;
    chunks["a"] = std::vector<unsigned char>{'h', 'e', 'l', 'l', 'o'};
    chunks["b"] = std::vector<unsigned char>{'w', 'o', 'r', 'l', 'd'};
    src.SetChunkMap(std::move(chunks), {"a", "b"});
    std::string err;
    BOOST_REQUIRE(src.Pin(err));
    BOOST_CHECK(!src.ClaimsModelIdentity());
    BOOST_CHECK_EQUAL(src.Kind(), "XET");
    BOOST_CHECK_EQUAL(src.SourceIntegrity(), "cas-root-1");
    BOOST_CHECK(src.Size() == 10);
    std::vector<unsigned char> out;
    BOOST_REQUIRE(src.Read({0, 10}, out, 16, err));
    BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), "helloworld");
    BOOST_REQUIRE(src.Read({3, 5}, out, 16, err));
    BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), "lowor");
    BOOST_CHECK(std::string(modelnet::XET_PROVENANCE_NOTE).find("not a second model identity") != std::string::npos);

    modelnet::XetByteSource missing{"https://huggingface.co/org/model", "cas-root-1"};
    missing.SetChunkMap({{"a", {'x'}}}, {"a", "missing"});
    BOOST_CHECK(!missing.Pin(err));
    BOOST_CHECK_EQUAL(err, "missing xet chunk");
}

BOOST_AUTO_TEST_CASE(torrent_map_range_infohash_not_authorship)
{
    std::vector<modelnet::TorrentFileMap> files{{"a", 10, false}, {"pad", 2, true}, {"b", 10, false}};
    modelnet::TorrentByteSource src{"magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567",
                                    "0123456789abcdef0123456789abcdef01234567", files};
    src.InjectFileBytes("a", std::vector<unsigned char>{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'});
    src.InjectFileBytes("b", std::vector<unsigned char>{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J'});
    std::string err;
    BOOST_REQUIRE(src.Pin(err));
    BOOST_CHECK_EQUAL(src.Kind(), "MAGNET");
    BOOST_CHECK_EQUAL(src.SourceIntegrity(), "0123456789abcdef0123456789abcdef01234567");
    BOOST_CHECK_EQUAL(src.ProvenanceNote(), modelnet::TORRENT_PROVENANCE_NOTE);
    BOOST_CHECK(std::string(src.ProvenanceNote()).find("not publisher authorship") != std::string::npos);
    std::vector<unsigned char> out;
    BOOST_REQUIRE(src.Read({8, 6}, out, 6, err));
    BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), "89AB");
    BOOST_CHECK(!src.Read({8, 6}, out, /*budget=*/3, err));
    BOOST_CHECK_EQUAL(err, "credit exhausted");
}

BOOST_AUTO_TEST_CASE(import_coordinator_staging_uuid_until_verified_manifest)
{
    const fs::path root = m_path_root / "n02-import-stage";
    auto plan = SamplePlan(modelnet::ImportSourceKind::HUGGINGFACE, "https://huggingface.co/org/model");
    plan.snapshot_token = "hf_secret_token_xyz";
    modelnet::ImportFileSpec pickle;
    pickle.source_path = "weights.pt";
    pickle.destination_path = "weights.pt";
    pickle.size_bytes = 4;
    plan.files.push_back(pickle);
    modelnet::ImportCoordinator a{plan, root};
    modelnet::ImportCoordinator b{plan, root};
    BOOST_CHECK_NE(a.StagingUuid(), b.StagingUuid());
    BOOST_CHECK_EQUAL(a.StagingUuid().size(), 36U);
    BOOST_CHECK(!a.HasFinalModelId());
    std::string err;
    BOOST_REQUIRE(a.PrepareStaging(err));
    BOOST_CHECK(a.Phase() == modelnet::ImportPhase::STAGING);
    BOOST_REQUIRE_EQUAL(a.AcceptedFiles().size(), 1);
    BOOST_CHECK_EQUAL(a.AcceptedFiles()[0].destination_path, "model.safetensors");
    BOOST_CHECK(fs::exists(a.StagingDir() / fs::PathFromString("staging.json")));
    const UniValue st = a.StatusJson();
    const std::string dumped = st.write();
    BOOST_CHECK(!st.exists("model_id"));
    BOOST_CHECK(!st.exists("snapshot_token"));
    BOOST_CHECK(dumped.find("hf_secret_token_xyz") == std::string::npos);
    BOOST_CHECK(dumped.find("snapshot_token") == std::string::npos);
    BOOST_CHECK(st["provenance_note"].get_str().find("not publisher authorship") != std::string::npos);
    BOOST_CHECK_EQUAL(st["authorship"].get_str(), "not implied by source integrity");
    BOOST_CHECK_EQUAL(st["staging_uuid"].get_str(), a.StagingUuid());
    BOOST_CHECK(a.FinalModelId().IsNull());

    modelnet::HuggingFaceByteSource pickle_bytes{plan.locator, plan.snapshot_token};
    pickle_bytes.InjectTestBytes(std::vector<unsigned char>{0x80, 0x04, 'p', 'k', 'l'});
    BOOST_CHECK(!a.StageFromSource(pickle_bytes, a.AcceptedFiles()[0], 16, err));
    BOOST_CHECK_EQUAL(err, "pickle/.pt execution forbidden");

    modelnet::HuggingFaceByteSource src{plan.locator, plan.snapshot_token};
    src.InjectTestBytes(std::vector<unsigned char>{'w', 'e', 'i', 'g', 'h'});
    BOOST_REQUIRE(a.StageFromSource(src, a.AcceptedFiles()[0], 16, err));
    BOOST_CHECK(!a.HasFinalModelId());
    BOOST_CHECK(fs::exists(a.StagingDir() / fs::PathFromString("model.safetensors")));

    modelnet::VerifiedManifest vm;
    vm.model_id.data.fill(0x11);
    vm.artifact_id.data.fill(0x22);
    BOOST_REQUIRE(a.AcceptVerifiedManifest(vm, err));
    BOOST_CHECK(a.HasFinalModelId());
    BOOST_CHECK_EQUAL(a.FinalModelId().Hex(), vm.model_id.Hex());
    BOOST_CHECK(a.StatusJson().exists("model_id"));
}

BOOST_AUTO_TEST_CASE(import_coordinator_rejects_pickle_only_and_mismatch)
{
    const fs::path root = m_path_root / "n02-import-pickle";
    modelnet::ImportPlan plan;
    plan.plan_id = std::string(96, 'b');
    plan.kind = modelnet::ImportSourceKind::LOCAL;
    plan.locator = "/tmp/unused";
    plan.snapshot_token = "local";
    modelnet::ImportFileSpec pickle;
    pickle.source_path = "model.pt";
    pickle.destination_path = "model.pt";
    pickle.size_bytes = 8;
    plan.files.push_back(pickle);
    modelnet::ImportCoordinator coord{plan, root};
    std::string err;
    BOOST_CHECK(!coord.PrepareStaging(err));
    BOOST_CHECK_EQUAL(err, "no importable files (pickle/.pt/.py/.so/.bin skipped)");
    BOOST_CHECK(coord.Phase() == modelnet::ImportPhase::FAILED);
    BOOST_CHECK(!coord.HasFinalModelId());

    auto hf = SamplePlan(modelnet::ImportSourceKind::HUGGINGFACE, "https://huggingface.co/org/model");
    hf.expected_btx_manifest = std::string(96, 'c');
    modelnet::ImportCoordinator coord2{hf, root / fs::PathFromString("m")};
    BOOST_REQUIRE(coord2.PrepareStaging(err));
    modelnet::VerifiedManifest vm;
    vm.model_id.data.fill(0x11);
    vm.artifact_id.data.fill(0x22);
    BOOST_CHECK(!coord2.AcceptVerifiedManifest(vm, err));
    BOOST_CHECK_EQUAL(err, "ID_MISMATCH");
    BOOST_CHECK(!coord2.HasFinalModelId());
}

BOOST_AUTO_TEST_CASE(make_plan_bytesource_and_ssrf)
{
    std::string err;
    auto plan = SamplePlan(modelnet::ImportSourceKind::HUGGINGFACE, "http://localhost/secret");
    auto src = modelnet::MakePlanByteSource(plan, err);
    BOOST_REQUIRE(src);
    BOOST_CHECK(!src->Pin(err));
    BOOST_CHECK_EQUAL(err, "ssrf");

    auto s3 = SamplePlan(modelnet::ImportSourceKind::S3, "s3://bucket/key");
    BOOST_CHECK(!modelnet::MakePlanByteSource(s3, err));
    BOOST_CHECK_EQUAL(err, "source adapter not in this module");
}

BOOST_AUTO_TEST_SUITE_END()
