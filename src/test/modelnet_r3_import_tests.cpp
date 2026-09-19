// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// R3 (Imports) independent-review evidence for 0.34.8. See audit/r3-imports.md.
//
// Registered in src/test/CMakeLists.txt. Cases suffixed _FINDING assert the
// behaviour the tree has today, which this review considers a defect. They
// document a gap; they do not endorse it. No case touches the network. Nothing
// here reaches Hugging Face.

#include <modelnet/import_coordinator.h>
#include <modelnet/import_plan.h>
#include <modelnet/source_huggingface.h>
#include <modelnet/source_local.h>
#include <modelnet/source_policy.h>
#include <modelnet/source_torrent.h>
#include <modelnet/source_xet.h>
#include <modelnet/verified_manifest.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <functional>
#include <limits>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_r3_import_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> Bytes(const std::string& s)
{
    return std::vector<unsigned char>(s.begin(), s.end());
}

std::string Str(const std::vector<unsigned char>& v)
{
    return std::string(v.begin(), v.end());
}

modelnet::ImportPlan OneFilePlan(modelnet::ImportSourceKind kind, const std::string& locator,
                                 const std::string& name, uint64_t declared_size)
{
    modelnet::ImportPlan plan;
    plan.plan_id = std::string(96, 'r');
    plan.kind = kind;
    plan.locator = locator;
    plan.snapshot_token = "r3-fixture";
    plan.provenance_note = "source_integrity_only;not_publisher_authorship";
    modelnet::ImportFileSpec f;
    f.source_path = name;
    f.destination_path = name;
    f.size_bytes = declared_size;
    plan.files.push_back(std::move(f));
    return plan;
}

} // namespace

// --- torrent piece geometry -------------------------------------------------

// BTX pieces are PIECE_SIZE (4 MiB). The torrent adapter models no piece
// geometry at all, so a dense file map maps byte-exactly regardless of the
// torrent's own piece length. This is the positive half of the piece-size
// question.
BOOST_AUTO_TEST_CASE(torrent_dense_map_is_piece_size_agnostic)
{
    const std::vector<modelnet::TorrentFileMap> files{{"a", 10, false}, {"b", 10, false}};
    modelnet::TorrentByteSource src{"magnet:?xt=urn:btih:" + std::string(40, '1'), "", files};
    src.InjectFileBytes("a", Bytes("0123456789"));
    src.InjectFileBytes("b", Bytes("ABCDEFGHIJ"));

    std::string err;
    BOOST_REQUIRE(src.Pin(err));
    BOOST_CHECK_EQUAL(src.Kind(), "MAGNET");

    std::vector<unsigned char> out;
    BOOST_REQUIRE(src.Read({8, 6}, out, 64, err));
    BOOST_CHECK_EQUAL(Str(out), "89ABCD");
    BOOST_CHECK_EQUAL(out.size(), 6U);

    BOOST_REQUIRE(src.Read({0, 20}, out, 64, err));
    BOOST_CHECK_EQUAL(out.size(), 20U);
}

// R3-1. MapTorrentRange drops padding from its output while callers pass
// torrent-global offsets, so Read() returns fewer bytes than extent.length and
// still reports success. BEP-47 pad files make this reachable input.
BOOST_AUTO_TEST_CASE(torrent_padding_silently_short_reads_FINDING)
{
    const std::vector<modelnet::TorrentFileMap> files{{"a", 10, false}, {"pad", 2, true}, {"b", 10, false}};
    modelnet::TorrentByteSource src{"magnet:?xt=urn:btih:" + std::string(40, '2'), "ih", files};
    src.InjectFileBytes("a", Bytes("0123456789"));
    src.InjectFileBytes("b", Bytes("ABCDEFGHIJ"));

    std::string err;
    BOOST_REQUIRE(src.Pin(err));

    // Six bytes requested across the pad boundary; four delivered, no error.
    std::vector<unsigned char> out;
    BOOST_REQUIRE(src.Read({8, 6}, out, 64, err));
    BOOST_CHECK_EQUAL(out.size(), 4U);
    BOOST_CHECK_EQUAL(Str(out), "89AB");

    // An extent entirely inside padding succeeds with zero bytes.
    BOOST_REQUIRE(src.Read({10, 2}, out, 64, err));
    BOOST_CHECK(out.empty());
}

// R3-1 / R3-3. The staging writer never compares the delivered length to the
// declared one, so the short read above becomes a truncated staged file that
// reports success.
BOOST_AUTO_TEST_CASE(torrent_padding_silently_short_reads_into_staging_FINDING)
{
    const fs::path root = m_path_root / "r3-torrent-short";
    auto plan = OneFilePlan(modelnet::ImportSourceKind::TORRENT,
                            "magnet:?xt=urn:btih:" + std::string(40, '3'), "model.safetensors",
                            /*declared_size=*/6);
    modelnet::ImportCoordinator coord{plan, root};
    std::string err;
    BOOST_REQUIRE(coord.PrepareStaging(err));
    BOOST_REQUIRE_EQUAL(coord.AcceptedFiles().size(), 1U);
    BOOST_CHECK_EQUAL(coord.AcceptedFiles()[0].size_bytes, 6U);

    const std::vector<modelnet::TorrentFileMap> files{{"model.safetensors", 4, false}, {"pad", 2, true}};
    modelnet::TorrentByteSource src{plan.locator, "ih", files};
    src.InjectFileBytes("model.safetensors", Bytes("weig"));
    BOOST_REQUIRE(src.Pin(err));

    BOOST_REQUIRE(coord.StageFromSource(src, coord.AcceptedFiles()[0], /*budget=*/64, err));
    const fs::path staged = coord.StagingDir() / fs::PathFromString("model.safetensors");
    BOOST_REQUIRE(fs::exists(staged));
    BOOST_CHECK_EQUAL(fs::file_size(staged), 4U); // declared 6, staged 4, no error
}

// R3-9. Nothing hashes the payload against the infohash: no v1 SHA-1 piece
// hash, no v2 merkle root, no piece length. SourceIntegrity is the caller's
// string verbatim.
BOOST_AUTO_TEST_CASE(torrent_infohash_is_never_verified_FINDING)
{
    const std::string bogus(40, 'f');
    const std::vector<modelnet::TorrentFileMap> files{{"a", 4, false}};
    modelnet::TorrentByteSource src{"magnet:?xt=urn:btih:" + bogus, bogus, files};
    src.InjectFileBytes("a", Bytes("junk"));

    std::string err;
    BOOST_REQUIRE(src.Pin(err));
    BOOST_CHECK_EQUAL(src.SourceIntegrity(), bogus);
    BOOST_CHECK(std::string(src.ProvenanceNote()).find("not publisher authorship") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(torrent_traversal_names_rejected)
{
    std::string err;
    BOOST_CHECK(!modelnet::TorrentFileNameAllowed("../../etc/passwd", err));
    BOOST_CHECK_EQUAL(err, "torrent path");
    BOOST_CHECK(!modelnet::TorrentFileNameAllowed("/etc/passwd", err));
    BOOST_CHECK_EQUAL(err, "torrent path");
    BOOST_CHECK(!modelnet::TorrentFileNameAllowed("a/../../b", err));
    BOOST_CHECK(modelnet::TorrentFileNameAllowed("dir/model.safetensors", err));

    std::vector<modelnet::TorrentSlice> slices;
    const std::vector<modelnet::TorrentFileMap> bad{{"../../etc/passwd", 10, false}};
    BOOST_CHECK(!modelnet::MapTorrentRangeSafe(bad, 0, 4, slices, err));
    BOOST_CHECK_EQUAL(err, "torrent path");

    modelnet::TorrentByteSource src{"magnet:?xt=urn:btih:" + std::string(40, '4'), "ih", bad};
    BOOST_CHECK(!src.Pin(err));
    BOOST_CHECK_EQUAL(err, "torrent path");

    // R3-11: percent-encoded traversal is not filtered. Harmless only because
    // torrent member names are map keys and never filesystem paths.
    BOOST_CHECK(modelnet::TorrentFileNameAllowed("%2e%2e/etc/passwd", err));
}

// Reverse bridge is byte accounting. The only state it can hold is two
// counters, and "live" is decided by whether that accounting object exists --
// not by a policy flag a caller could flip. See audit/r3-imports.md section 6.
//
// The torrentd_process / receives_s3_credentials fields are constant `false`
// in the header, so asserting them proves nothing about behaviour; the
// structural claim worth pinning is that the counters are the whole state.
BOOST_AUTO_TEST_CASE(torrent_reverse_bridge_is_two_counters)
{
    // reverse_bridge_live is derived from the pointer, so a caller with no
    // accounting object cannot report a live bridge.
    const UniValue absent = modelnet::ReverseTorrentStatusJson(nullptr);
    BOOST_CHECK(absent["reverse_bridge"].get_bool());
    BOOST_CHECK(!absent["reverse_bridge_live"].get_bool());
    BOOST_CHECK_EQUAL(absent["bt_to_btx_bytes"].get_str(), "0");
    BOOST_CHECK_EQUAL(absent["btx_to_torrent_bytes"].get_str(), "0");
    BOOST_CHECK_EQUAL(absent["upload_class"].get_str(), modelnet::TORRENT_REVERSE_UPLOAD_CLASS);

    modelnet::ReverseTorrentBridge bridge;
    bridge.NoteBtToBtxBytes(7);
    bridge.NoteBtxToTorrentBytes(9);
    BOOST_CHECK_EQUAL(bridge.BtToBtxBytes(), 7U);
    BOOST_CHECK_EQUAL(bridge.BtxToTorrentBytes(), 9U);
    const UniValue live = modelnet::ReverseTorrentStatusJson(&bridge);
    BOOST_CHECK(live["reverse_bridge_live"].get_bool());
    BOOST_CHECK_EQUAL(live["bt_to_btx_bytes"].get_str(), "7");
    BOOST_CHECK_EQUAL(live["btx_to_torrent_bytes"].get_str(), "9");
    // The two directions are independent counters, not one shared total.
    BOOST_CHECK(live["bt_to_btx_bytes"].get_str() != live["btx_to_torrent_bytes"].get_str());

    // Saturating, never wrapping: a hostile byte count cannot roll the counter
    // back to a small number and hide traffic.
    modelnet::ReverseTorrentBridge sat;
    sat.NoteBtToBtxBytes(std::numeric_limits<uint64_t>::max());
    sat.NoteBtToBtxBytes(1000);
    BOOST_CHECK_EQUAL(sat.BtToBtxBytes(), std::numeric_limits<uint64_t>::max());
    BOOST_CHECK_EQUAL(sat.BtxToTorrentBytes(), 0U);
}

// --- Hugging Face -----------------------------------------------------------

// No HTTP client exists in the adapter; bytes only arrive by injection.
BOOST_AUTO_TEST_CASE(hf_read_requires_injection)
{
    modelnet::HuggingFaceByteSource src{"https://huggingface.co/org/model", "rev-1"};
    std::string err;
    BOOST_REQUIRE(src.Pin(err));
    std::vector<unsigned char> out;
    BOOST_CHECK(!src.Read({0, 1}, out, 64, err));
    BOOST_CHECK_EQUAL(err, "not wired to live network");
}

// R3-5. The SSRF blocklist is textual. Integer, octal and expanded-IPv6
// loopback encodings all pass. Latent only because no resolver and no client
// exist; it must move behind name resolution before HF live is authorized.
BOOST_AUTO_TEST_CASE(hf_numeric_loopback_encodings_not_blocked_FINDING)
{
    std::string err;
    BOOST_CHECK(modelnet::HuggingFaceLocatorAllowed("http://2130706433/model", err));   // 127.0.0.1
    BOOST_CHECK(modelnet::HuggingFaceLocatorAllowed("http://0177.0.0.1/model", err));   // octal 127
    BOOST_CHECK(modelnet::HuggingFaceLocatorAllowed("http://0x7f000001/model", err));   // hex 127.0.0.1
    BOOST_CHECK(modelnet::HuggingFaceLocatorAllowed("https://[0:0:0:0:0:0:0:1]/x", err)); // expanded ::1

    modelnet::HuggingFaceByteSource numeric{"http://2130706433/model", "rev-1"};
    BOOST_CHECK(numeric.Pin(err));

    // The literal forms are blocked, which is what the existing suite covers.
    BOOST_CHECK(!modelnet::HuggingFaceLocatorAllowed("http://127.0.0.1/model", err));
    BOOST_CHECK(!modelnet::HuggingFaceLocatorAllowed("https://[::1]/model", err));
    BOOST_CHECK(!modelnet::HuggingFaceLocatorAllowed("https://169.254.169.254/latest", err));
}

// R3-5. There is no host allowlist: any https host satisfies the
// "HuggingFace" gate.
BOOST_AUTO_TEST_CASE(hf_any_https_host_allowed_FINDING)
{
    std::string err;
    BOOST_CHECK(modelnet::HuggingFaceLocatorAllowed("https://evil.example/model.safetensors", err));
    modelnet::HuggingFaceByteSource src{"https://evil.example/model.safetensors", "rev-1"};
    BOOST_CHECK(src.Pin(err));
    BOOST_CHECK_EQUAL(src.SourceIntegrity(), "rev-1");
}

// R3-4. The accessor is a hard false even when the constructor was told to
// follow redirects. Pin() is fail-closed, so this is reporting only.
BOOST_AUTO_TEST_CASE(hf_follows_redirects_accessor_is_constant_FINDING)
{
    modelnet::HuggingFaceByteSource src{"https://huggingface.co/org/model", "rev-1", /*follow_redirects=*/true};
    std::string err;
    BOOST_CHECK(!src.Pin(err));
    BOOST_CHECK_EQUAL(err, "redirects forbidden");
    BOOST_CHECK(!src.FollowsRedirects());
}

// --- Xet --------------------------------------------------------------------

// R3-7. Xet::Pin never applies the locator policy that HF applies.
BOOST_AUTO_TEST_CASE(xet_locator_has_no_ssrf_gate_FINDING)
{
    modelnet::XetByteSource src{"file:///etc/passwd", "cas-root-1"};
    modelnet::XetChunkMap chunks;
    chunks["c0"] = Bytes("hello");
    src.SetChunkMap(chunks, {"c0"});
    std::string err;
    BOOST_CHECK(src.Pin(err));

    modelnet::XetByteSource loopback{"http://127.0.0.1/cas", "cas-root-1"};
    loopback.SetChunkMap(chunks, {"c0"});
    BOOST_CHECK(loopback.Pin(err));

    // The same locators are refused by the HF gate.
    BOOST_CHECK(!modelnet::HuggingFaceLocatorAllowed("file:///etc/passwd", err));
    BOOST_CHECK(!modelnet::HuggingFaceLocatorAllowed("http://127.0.0.1/cas", err));

    // This sharpens the finding: a gate that would have refused both locators
    // already exists and already covers a non-LOCAL kind. Xet::Pin simply never
    // calls it, so the fix is a call site, not new policy.
    BOOST_CHECK(!modelnet::SourceLocatorAllowed("XET", "file:///etc/passwd", err));
    BOOST_CHECK(!modelnet::SourceLocatorAllowed("XET", "http://127.0.0.1/cas", err));
    BOOST_CHECK(modelnet::SourceLocatorAllowed("XET", "https://huggingface.co/org/model", err));

    // R3-7 (second half). The LOCAL arm of that same gate checks only for an
    // empty string, so it would not have helped: routing a remote locator
    // through kind=LOCAL passes every scheme and host.
    BOOST_CHECK(modelnet::SourceLocatorAllowed("LOCAL", "file:///etc/passwd", err));
    BOOST_CHECK(modelnet::SourceLocatorAllowed("LOCAL", "http://169.254.169.254/latest", err));
    BOOST_CHECK(!modelnet::SourceLocatorAllowed("LOCAL", "", err));
    BOOST_CHECK_EQUAL(err, "locator");
}

// R3-6. Chunk ids are plain map keys. Content is never hashed against its id,
// and cas_root is echoed without being recomputed.
BOOST_AUTO_TEST_CASE(xet_chunk_ids_are_not_verified_FINDING)
{
    modelnet::XetByteSource src{"https://huggingface.co/org/model", "cas-root-unchecked"};
    modelnet::XetChunkMap chunks;
    chunks["sha256:" + std::string(64, '0')] = Bytes("not-the-hashed-content");
    src.SetChunkMap(chunks, {"sha256:" + std::string(64, '0')});
    std::string err;
    BOOST_REQUIRE(src.Pin(err));
    // Pin succeeded even though the chunk id claims a SHA-256 the content does
    // not have, and cas_root is echoed back rather than recomputed.
    BOOST_CHECK_EQUAL(src.SourceIntegrity(), "cas-root-unchecked");
    std::vector<unsigned char> out;
    BOOST_REQUIRE(src.Read({0, src.Size()}, out, 4096, err));
    BOOST_CHECK_EQUAL(Str(out), "not-the-hashed-content");
}

// Bounds and overflow handling on the Xet reconstruction are correct; recorded
// so the R3-6 finding is not read as "Xet reads are unsafe".
BOOST_AUTO_TEST_CASE(xet_extent_bounds_hold)
{
    modelnet::XetByteSource src{"https://huggingface.co/org/model", "cas-root-1"};
    modelnet::XetChunkMap chunks;
    chunks["a"] = Bytes("hello");
    chunks["b"] = Bytes("world");
    src.SetChunkMap(chunks, {"a", "b"});
    std::string err;
    BOOST_REQUIRE(src.Pin(err));
    BOOST_CHECK_EQUAL(src.Size(), 10U);

    std::vector<unsigned char> out;
    BOOST_CHECK(!src.Read({0, 11}, out, 4096, err));
    BOOST_CHECK_EQUAL(err, "extent");
    BOOST_CHECK(!src.Read({10, 1}, out, 4096, err));
    BOOST_CHECK_EQUAL(err, "extent");
    BOOST_CHECK(!src.Read({0, 10}, out, /*budget=*/4, err));
    BOOST_CHECK_EQUAL(err, "credit exhausted");
    BOOST_REQUIRE(src.Read({3, 5}, out, 4096, err));
    BOOST_CHECK_EQUAL(Str(out), "lowor");
}

// --- identity binding -------------------------------------------------------

// R3-2. AcceptVerifiedManifest adopts a caller-supplied model_id without
// hashing, or even requiring, any staged bytes.
BOOST_AUTO_TEST_CASE(publish_ready_without_any_staged_bytes_FINDING)
{
    const fs::path root = m_path_root / "r3-no-bytes";
    auto plan = OneFilePlan(modelnet::ImportSourceKind::HUGGINGFACE, "https://huggingface.co/org/model",
                            "model.safetensors", /*declared_size=*/1024);
    modelnet::ImportCoordinator coord{plan, root};
    std::string err;
    BOOST_REQUIRE(coord.PrepareStaging(err));
    BOOST_CHECK(coord.Phase() == modelnet::ImportPhase::STAGING);

    const fs::path staged = coord.StagingDir() / fs::PathFromString("model.safetensors");
    BOOST_REQUIRE(!fs::exists(staged)); // nothing was ever fetched

    modelnet::VerifiedManifest vm;
    vm.model_id.data.fill(0xab);
    vm.artifact_id.data.fill(0xcd);
    BOOST_REQUIRE(coord.AcceptVerifiedManifest(vm, err));
    BOOST_CHECK(coord.Phase() == modelnet::ImportPhase::PUBLISH_READY);
    BOOST_CHECK(coord.HasFinalModelId());
    BOOST_CHECK_EQUAL(coord.FinalModelId().Hex(), vm.model_id.Hex());
    BOOST_CHECK(!fs::exists(staged));
}

// R3-2. Staged bytes unrelated to the manifest are accepted too: the id is
// asserted by the caller, not derived from what is on disk.
BOOST_AUTO_TEST_CASE(staged_bytes_are_not_rehashed_at_accept_FINDING)
{
    const fs::path root = m_path_root / "r3-no-rehash";
    auto plan = OneFilePlan(modelnet::ImportSourceKind::HUGGINGFACE, "https://huggingface.co/org/model",
                            "model.safetensors", /*declared_size=*/5);
    modelnet::ImportCoordinator coord{plan, root};
    std::string err;
    BOOST_REQUIRE(coord.PrepareStaging(err));

    modelnet::HuggingFaceByteSource src{plan.locator, plan.snapshot_token};
    src.InjectTestBytes(Bytes("weigh"));
    BOOST_REQUIRE(coord.StageFromSource(src, coord.AcceptedFiles()[0], /*budget=*/64, err));

    modelnet::VerifiedManifest vm;
    vm.model_id.data.fill(0x11);
    vm.artifact_id.data.fill(0x22);
    BOOST_REQUIRE(coord.AcceptVerifiedManifest(vm, err));
    BOOST_CHECK_EQUAL(coord.FinalModelId().Hex(), vm.model_id.Hex());

    // The snapshot token still never appears in status JSON.
    const std::string dumped = coord.StatusJson().write();
    BOOST_CHECK(dumped.find("snapshot_token") == std::string::npos);
    BOOST_CHECK(dumped.find(plan.snapshot_token) == std::string::npos);
}

// R3-13. ImportPlanJson does serialize the snapshot token. It has no non-test
// caller today; it must not become an RPC reply or a staging marker.
BOOST_AUTO_TEST_CASE(import_plan_json_carries_snapshot_token_FINDING)
{
    auto plan = OneFilePlan(modelnet::ImportSourceKind::HUGGINGFACE, "https://huggingface.co/org/model",
                            "model.safetensors", 5);
    plan.snapshot_token = "hf_secret_token_xyz";
    const std::string dumped = modelnet::ImportPlanJson(plan).write();
    BOOST_CHECK(dumped.find("hf_secret_token_xyz") != std::string::npos);
}

// Destination-path policy on the staging write path is sound.
BOOST_AUTO_TEST_CASE(destination_path_traversal_rejected)
{
    for (const char* bad : {"../../etc/passwd", "/etc/passwd", "a/../b", "..", ".hidden/x",
                            "dir/./x", "C:\\win\\x", "a\\b", "model.pt", "model.pickle",
                            "weights.bin", "run.sh", "lib.so"}) {
        const fs::path root = m_path_root / "r3-paths" / fs::PathFromString(std::string("case-") + std::to_string(std::hash<std::string>{}(bad) % 1000));
        auto plan = OneFilePlan(modelnet::ImportSourceKind::LOCAL, "/unused", bad, 4);
        modelnet::ImportCoordinator coord{plan, root};
        std::string err;
        BOOST_CHECK_MESSAGE(!coord.PrepareStaging(err), std::string("accepted unsafe path: ") + bad);
        BOOST_CHECK(coord.Phase() == modelnet::ImportPhase::FAILED);
        BOOST_CHECK(!coord.HasFinalModelId());
    }
}

BOOST_AUTO_TEST_SUITE_END()
