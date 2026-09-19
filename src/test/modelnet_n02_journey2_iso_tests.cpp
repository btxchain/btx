// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// NETWORK-02 journey 2 isolated (no live R2 WAN). Multipart abort then
// re-initiate with a new upload_id, HF Pin+InjectTestBytes staging,
// reverse-torrent accounting, IoExecutor drain after staging.
// Coordinator wires this file into test_btx CMake later.

#include <modelnet/import_coordinator.h>
#include <modelnet/io_executor.h>
#include <modelnet/multipart_journal.h>
#include <modelnet/s3_client.h>
#include <modelnet/source_huggingface.h>
#include <modelnet/source_torrent.h>
#include <modelnet/verified_manifest.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_n02_journey2_iso_tests, BasicTestingSetup)

namespace {

modelnet::ImportPlan HfStagePlan(const std::string& snapshot, uint64_t size_bytes)
{
    modelnet::ImportPlan plan;
    plan.plan_id = std::string(96, 'a');
    plan.kind = modelnet::ImportSourceKind::HUGGINGFACE;
    plan.locator = "https://huggingface.co/org/model";
    plan.snapshot_token = snapshot;
    plan.provenance_note = modelnet::HUGGINGFACE_PROVENANCE_NOTE;
    modelnet::ImportFileSpec f;
    f.source_path = "model.safetensors";
    f.destination_path = "model.safetensors";
    f.size_bytes = size_bytes;
    plan.files.push_back(std::move(f));
    return plan;
}

modelnet::MultipartPart OpaquePart(uint32_t index, uint64_t offset, uint64_t length, std::string etag)
{
    modelnet::MultipartPart p;
    p.index = index;
    p.offset = offset;
    p.length = length;
    p.etag = std::move(etag);
    return p;
}

} // namespace

BOOST_AUTO_TEST_CASE(n02_j2_iso_multipart_abort_reinitiate_etag_not_identity)
{
    modelnet::MultipartJournal j;
    std::string err;
    const std::string snapshot = "hf-rev-j2";
    BOOST_REQUIRE(j.Initiate("models/org/model", "upload-1", snapshot, /*planned_parts=*/2, err));
    BOOST_CHECK(j.Phase() == modelnet::MultipartPhase::INITIATED);
    BOOST_REQUIRE(j.NotePart(OpaquePart(0, 0, 64, "etag-part0-opaque"), err));
    BOOST_CHECK(j.Phase() == modelnet::MultipartPhase::PARTS);
    BOOST_CHECK(!j.Complete(err));
    BOOST_CHECK_EQUAL(err, "incomplete parts");

    BOOST_REQUIRE(j.Abort());
    BOOST_CHECK(j.Phase() == modelnet::MultipartPhase::ABORTED);
    BOOST_CHECK(!j.Complete(err));
    BOOST_CHECK_EQUAL(err, "phase");

    BOOST_REQUIRE(j.Initiate("models/org/model", "upload-2", snapshot, /*planned_parts=*/2, err));
    BOOST_CHECK_EQUAL(j.Json()["upload_id"].get_str(), "upload-2");
    BOOST_CHECK_EQUAL(j.Json()["source_snapshot"].get_str(), snapshot);
    BOOST_REQUIRE(j.NotePart(OpaquePart(0, 0, 64, "etag-part0-retry"), err));
    BOOST_REQUIRE(j.NotePart(OpaquePart(1, 64, 32, "etag-part1-opaque"), err));
    BOOST_REQUIRE(j.Complete(err));
    BOOST_CHECK(j.Phase() == modelnet::MultipartPhase::COMPLETED);

    BOOST_CHECK(!modelnet::MultipartEtagIsCanonicalIdentity());
    const UniValue dumped = j.Json();
    BOOST_CHECK(!dumped["etag_is_canonical_identity"].get_bool());
    BOOST_CHECK_EQUAL(dumped["phase"].get_str(), "COMPLETED");
    BOOST_CHECK_EQUAL(dumped["upload_id"].get_str(), "upload-2");
    BOOST_CHECK_EQUAL(dumped["source_snapshot"].get_str(), snapshot);
    BOOST_REQUIRE_EQUAL(dumped["parts"].size(), 2);
    BOOST_CHECK(dumped["parts"][0]["etag_present"].get_bool());
    BOOST_CHECK(dumped["parts"][1]["etag_present"].get_bool());
}

BOOST_AUTO_TEST_CASE(n02_j2_iso_hf_inject_stage_provenance_not_authorship_id_mismatch)
{
    const std::vector<unsigned char> bytes{'h', 'e', 'l', 'l', 'o'};
    auto plan = HfStagePlan("snap-j2-iso", bytes.size());
    plan.expected_btx_manifest = std::string(96, 'c');

    modelnet::HuggingFaceByteSource src{plan.locator, plan.snapshot_token};
    std::string err;
    BOOST_REQUIRE(src.Pin(err));
    BOOST_CHECK(!src.FollowsRedirects());
    BOOST_CHECK_EQUAL(src.Kind(), "HUGGINGFACE");
    BOOST_CHECK_EQUAL(src.SourceIntegrity(), "snap-j2-iso");
    src.InjectTestBytes(bytes);

    const fs::path root = m_path_root / "n02-j2-iso-hf-stage";
    modelnet::ImportCoordinator coord{plan, root};
    BOOST_REQUIRE(coord.PrepareStaging(err));
    BOOST_CHECK(coord.Phase() == modelnet::ImportPhase::STAGING);
    BOOST_REQUIRE_EQUAL(coord.AcceptedFiles().size(), 1);
    BOOST_REQUIRE(coord.StageFromSource(src, coord.AcceptedFiles()[0], bytes.size(), err));
    BOOST_CHECK(fs::exists(coord.StagingDir() / fs::PathFromString("model.safetensors")));
    BOOST_CHECK(!coord.HasFinalModelId());

    const UniValue st = coord.StatusJson();
    BOOST_CHECK_EQUAL(st["provenance_note"].get_str(), modelnet::HUGGINGFACE_PROVENANCE_NOTE);
    BOOST_CHECK(st["provenance_note"].get_str().find("not publisher authorship") != std::string::npos);
    BOOST_CHECK_EQUAL(st["authorship"].get_str(), "not implied by source integrity");
    BOOST_CHECK(!st.exists("model_id"));

    modelnet::VerifiedManifest vm;
    vm.model_id.data.fill(0x11);
    vm.artifact_id.data.fill(0x22);
    BOOST_CHECK_NE(plan.expected_btx_manifest, vm.model_id.Hex());
    BOOST_CHECK(!coord.AcceptVerifiedManifest(vm, err));
    BOOST_CHECK_EQUAL(err, "ID_MISMATCH");
    BOOST_CHECK(!coord.HasFinalModelId());
    BOOST_CHECK(coord.Phase() == modelnet::ImportPhase::STAGING);
}

BOOST_AUTO_TEST_CASE(n02_j2_iso_reverse_torrent_bridge_live_flag_no_torrentd_s3)
{
    modelnet::ReverseTorrentBridge br;
    br.NoteBtToBtxBytes(128);
    br.NoteBtxToTorrentBytes(64);
    BOOST_CHECK_EQUAL(br.BtToBtxBytes(), 128);
    BOOST_CHECK_EQUAL(br.BtxToTorrentBytes(), 64);
    BOOST_CHECK(!br.TorrentdProcess());
    BOOST_CHECK(!br.ReceivesS3Credentials());
    BOOST_CHECK(!br.HoldsS3Secrets());
    BOOST_CHECK_EQUAL(std::string(br.UploadClassName()), modelnet::TORRENT_REVERSE_UPLOAD_CLASS);

    const UniValue dead = modelnet::ReverseTorrentStatusJson(nullptr);
    BOOST_CHECK(dead["reverse_bridge"].get_bool());
    BOOST_CHECK(!dead["reverse_bridge_live"].get_bool());
    BOOST_CHECK(!dead["torrentd_process"].get_bool());
    BOOST_CHECK(!dead["receives_s3_credentials"].get_bool());

    const UniValue live = modelnet::ReverseTorrentStatusJson(&br);
    BOOST_CHECK(live["reverse_bridge_live"].get_bool());
    BOOST_CHECK(!live["torrentd_process"].get_bool());
    BOOST_CHECK(!live["receives_s3_credentials"].get_bool());
    BOOST_CHECK_EQUAL(live["bt_to_btx_bytes"].get_str(), "128");
    BOOST_CHECK_EQUAL(live["btx_to_torrent_bytes"].get_str(), "64");
    BOOST_CHECK(br.Json()["reverse_bridge_live"].get_bool());
}

BOOST_AUTO_TEST_CASE(n02_j2_iso_fakes3_mpu_abort_then_restart)
{
    modelnet::FakeS3 fake;
    fake.SetSigningContext("AKIATESTKEYNOTREAL00", "super-secret-cloud-value-xyz", "auto", "btx-models");
    std::string err;
    std::string upload_1;
    BOOST_REQUIRE(fake.BeginMultipart("models/org/model.bin", upload_1, err));
    const unsigned char p0[] = {'h', 'e', 'l', 'l'};
    BOOST_REQUIRE(fake.UploadPart(upload_1, 1, Span<const unsigned char>{p0, 4}, err));
    BOOST_REQUIRE(fake.AbortMultipart(upload_1, err));
    BOOST_CHECK(!fake.CompleteMultipart(upload_1, err));
    BOOST_CHECK(!fake.Contains("models/org/model.bin"));

    std::string upload_2;
    BOOST_REQUIRE(fake.BeginMultipart("models/org/model.bin", upload_2, err));
    BOOST_CHECK(upload_2 != upload_1);
    const unsigned char p1[] = {'o', '!'};
    BOOST_REQUIRE(fake.UploadPart(upload_2, 1, Span<const unsigned char>{p0, 4}, err));
    BOOST_REQUIRE(fake.UploadPart(upload_2, 2, Span<const unsigned char>{p1, 2}, err));
    BOOST_REQUIRE(fake.CompleteMultipart(upload_2, err));
    BOOST_CHECK(fake.Contains("models/org/model.bin"));
    BOOST_CHECK_EQUAL(fake.ObjectBytes("models/org/model.bin"), 6);
}

BOOST_AUTO_TEST_CASE(n02_j2_iso_io_executor_max2_drain_after_staging)
{
    const std::vector<unsigned char> bytes{'w', 'e', 'i', 'g', 'h'};
    auto plan = HfStagePlan("snap-j2-io", bytes.size());
    modelnet::HuggingFaceByteSource src{plan.locator, plan.snapshot_token};
    std::string err;
    BOOST_REQUIRE(src.Pin(err));
    src.InjectTestBytes(bytes);

    const fs::path root = m_path_root / "n02-j2-iso-io-stage";
    modelnet::ImportCoordinator coord{plan, root};
    BOOST_REQUIRE(coord.PrepareStaging(err));
    BOOST_REQUIRE(coord.StageFromSource(src, coord.AcceptedFiles()[0], bytes.size(), err));
    BOOST_CHECK(!coord.HasFinalModelId());

    modelnet::IoExecutor io(/*max_outstanding=*/2);
    BOOST_CHECK_EQUAL(io.MaxOutstanding(), 2);
    BOOST_REQUIRE(io.Submit(err));
    BOOST_REQUIRE(io.Submit(err));
    BOOST_CHECK(!io.Submit(err));
    BOOST_CHECK_EQUAL(io.Outstanding(), 2);
    io.Drain();
    BOOST_CHECK_EQUAL(io.Outstanding(), 0);
    BOOST_REQUIRE(io.Submit(err));
    BOOST_CHECK(!io.StatusJson()["io_uring"].get_bool());
}

BOOST_AUTO_TEST_SUITE_END()
