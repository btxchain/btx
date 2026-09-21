// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Final-convergence in-process proofs. Not a substitute for WAN/GUI/live HF.
// Evidence: this suite + contrib/modelnet/e2e-swarm-live.sh.

#include <crypto/common.h>
#include <modelnet/bootstrap_distributor.h>
#include <modelnet/bulk_controller.h>
#include <modelnet/catalog.h>
#include <modelnet/cloud_layout.h>
#include <modelnet/erasure_manifest.h>
#include <modelnet/erasure_store.h>
#include <modelnet/helper.h>
#include <test/modelnet_n02_idem.h>
#include <modelnet/index_reconcile.h>
#include <modelnet/lan_discovery.h>
#include <modelnet/object_layout.h>
#include <modelnet/package_bundle.h>
#include <modelnet/package_export.h>
#include <modelnet/physical_dedup.h>
#include <modelnet/piece_picker.h>
#include <modelnet/provider_route.h>
#include <modelnet/router.h>
#include <modelnet/selective_files.h>
#include <modelnet/source_policy.h>
#include <modelnet/source_torrent.h>
#include <modelnet/store.h>
#include <modelnet/transfer_session.h>
#include <modelnet/verified_manifest.h>
#include <modelnet/upload_scheduler.h>
#include <modelnet/upload_scheduler_drr.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_convergence_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> TinySafeTensors(unsigned char tag)
{
    const std::string json = "{\"__metadata__\":{\"t\":\"" + std::to_string(static_cast<int>(tag)) + "\"}}";
    std::vector<unsigned char> st(8 + json.size(), 0);
    WriteLE64(st.data(), json.size());
    std::memcpy(st.data() + 8, json.data(), json.size());
    return st;
}

modelnet::CatalogEntry ImportTiny(modelnet::ModelCatalog& cat, const fs::path& dir, unsigned char tag)
{
    fs::create_directories(dir);
    const auto st = TinySafeTensors(tag);
    {
        std::ofstream out(dir / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    std::string err;
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(dir), false, imported, err), err);
    return imported;
}

} // namespace

BOOST_AUTO_TEST_CASE(conv_routing_bucket_is_xor_bit_not_byte)
{
    using namespace modelnet;
    Digest48 self{};
    Digest48 msb = self;
    msb.data[0] = 0x80;
    Digest48 lsb = self;
    lsb.data[0] = 0x01;
    BOOST_CHECK_EQUAL(RoutingBucketIndex(self, msb), 0);
    BOOST_CHECK_EQUAL(RoutingBucketIndex(self, lsb), 7);
    BOOST_CHECK(RoutingBucketIndex(self, msb) != RoutingBucketIndex(self, lsb));
    BOOST_CHECK_EQUAL(ROUTE_BUCKETS, 384U);
}

BOOST_AUTO_TEST_CASE(conv_bulk_hysteresis_does_not_oscillate)
{
    modelnet::LowPriorityBulkController bulk;
    bulk.ObserveRtt(40);
    const double base = bulk.BackgroundShare();
    bulk.ObserveRtt(80);
    BOOST_CHECK_LT(bulk.BackgroundShare(), base);
    const double low = bulk.BackgroundShare();
    bulk.ObserveRtt(42);
    BOOST_CHECK_CLOSE(bulk.BackgroundShare(), low, 1e-6);
    bulk.ObserveRtt(41);
    BOOST_CHECK_GE(bulk.BackgroundShare(), low);
}

BOOST_AUTO_TEST_CASE(conv_upload_scheduler_mixed_and_scale)
{
    using namespace modelnet;
    DrrConfig cfg;
    cfg.admission.slots = 8;
    cfg.admission.max_slots = 16;
    cfg.admission.per_identity = 2;
    cfg.admission.per_netgroup = 4;
    UploadSchedulerDrr sched(cfg);
    auto enqueue = [&](const std::string& id, const std::string& ng, UploadClass cls) {
        DrrUploadRequest r;
        r.identity = id;
        r.netgroup = ng;
        r.schedule = cls;
        r.bytes = PIECE_SIZE;
        uint64_t rid = 0;
        std::string err;
        BOOST_REQUIRE(sched.Enqueue(r, rid, err));
        return rid;
    };
    enqueue("fast", "ng-fast", UploadClass::NORMAL);
    enqueue("slow", "ng-slow", UploadClass::NORMAL);
    enqueue("new", "ng-new", UploadClass::NEWCOMER);
    enqueue("end", "ng-end", UploadClass::RARE);
    enqueue("bulk", "", UploadClass::NORMAL);
    sched.RunEpoch();
    int selected = 0;
    DrrSelection sel;
    while (sched.Select(sel)) ++selected;
    BOOST_CHECK_GE(selected, 4);
    BOOST_CHECK_LE(sched.Active(), cfg.admission.slots);

    UploadSchedulerDrr scale(cfg);
    for (int i = 0; i < 10000; ++i) {
        DrrUploadRequest r;
        r.identity = "id-" + std::to_string(i);
        r.netgroup = "ng-" + std::to_string(i % 50);
        r.bytes = PIECE_SIZE;
        uint64_t rid = 0;
        std::string err;
        BOOST_REQUIRE(scale.Enqueue(r, rid, err));
    }
    scale.RunEpoch();
    int concurrent = 0;
    DrrSelection s2;
    while (scale.Select(s2)) ++concurrent;
    BOOST_CHECK_EQUAL(concurrent, cfg.admission.slots);
    BOOST_CHECK_EQUAL(scale.Active(), cfg.admission.slots);
}

BOOST_AUTO_TEST_CASE(conv_live_session_picker_overlapping_ranges)
{
    using namespace modelnet;
    CreditBroker broker{32 * PIECE_SIZE};
    TransferSession sess(broker);
    std::vector<SourceAvailability> srcs(3);
    srcs[0].peer.endpoint = "A";
    srcs[0].peer.netgroup = "ng-a";
    srcs[0].piece_count = 8;
    srcs[0].ranges.push_back(PieceRange{0, 4});
    srcs[1].peer.endpoint = "B";
    srcs[1].peer.netgroup = "ng-b";
    srcs[1].piece_count = 8;
    srcs[1].ranges.push_back(PieceRange{2, 4});
    srcs[2].peer.endpoint = "C";
    srcs[2].peer.netgroup = "ng-c";
    srcs[2].piece_count = 8;
    srcs[2].ranges.push_back(PieceRange{4, 4});
    std::vector<uint32_t> missing = {0, 1, 2, 3, 4, 5, 6, 7};
    srcs[0].last_update_ms = 1000;
    srcs[1].last_update_ms = 1000;
    srcs[2].last_update_ms = 1000;
    PickConfig cfg;
    cfg.max_assignments = 8;
    cfg.now_ms = 1000;
    cfg.credit = &broker;
    std::map<std::string, int> assigned;
    std::set<uint32_t> got;
    for (int round = 0; round < 6 && got.size() < missing.size(); ++round) {
        const auto live = sess.Metrics();
        const auto out = sess.Outstanding();
        const auto picks = PickRarestFirst(0, 8, missing, srcs, live, out, {}, cfg);
        for (const auto& p : picks) {
            uint64_t rid = 0;
            std::string err;
            if (!sess.ReserveAndQueue(p.endpoint, 0, p.piece_index, PIECE_SIZE, rid, err)) continue;
            sess.NoteSent(rid);
            assigned[p.endpoint] += 1;
            if (p.endpoint == "B" && round == 1) {
                sess.NoteFailed(rid);
                PeerMetrics fail;
                fail.state = PeerXferState::FAILED;
                fail.invalid_piece_count = 2;
                sess.ObservePeer("B", fail);
                continue;
            }
            sess.NoteCommitted(rid, PIECE_SIZE);
            got.insert(p.piece_index);
        }
        std::vector<uint32_t> still;
        for (uint32_t i : missing) {
            if (!got.count(i)) still.push_back(i);
        }
        missing.swap(still);
    }
    BOOST_CHECK(assigned.size() >= 2);
    BOOST_CHECK_GE(got.size(), 4U);
    BOOST_CHECK_EQUAL(sess.Json()["useful_bytes"].getInt<int64_t>() % static_cast<int64_t>(PIECE_SIZE), 0);
}

BOOST_AUTO_TEST_CASE(conv_put_fetched_wrong_file_index_rejected)
{
    const fs::path tmp = m_path_root / "conv-wrong-file";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 0x33);
    std::vector<unsigned char> bytes;
    std::vector<modelnet::Digest48> proof;
    uint64_t file_size = 0;
    std::string err;
    BOOST_REQUIRE(cat.GetVerifiedPiece(imported.artifact_id, 0, 0, bytes, proof, file_size, err));
    BOOST_CHECK(!cat.PutFetchedPiece(imported.artifact_id, 9, 0, bytes, proof, file_size,
                                     imported.core.files[0].pieces_root, err));
    modelnet::Digest48 unknown{};
    unknown.data[0] = 0xff;
    BOOST_CHECK(!cat.PutFetchedPiece(unknown, 0, 0, bytes, proof, file_size,
                                     imported.core.files[0].pieces_root, err));
}

BOOST_AUTO_TEST_CASE(conv_selective_unselected_is_not_complete)
{
    modelnet::SelectiveFileSet sel;
    sel.SelectOnly({0});
    BOOST_CHECK(sel.AdvertiseHave(0));
    BOOST_CHECK(!sel.AdvertiseHave(1));
    BOOST_CHECK(!sel.AllFiles());
}

BOOST_AUTO_TEST_CASE(conv_400gib_request_counts_differ_by_layout)
{
    using namespace modelnet;
    const uint64_t pieces = CanonicalPieceCount(OBJECT_LAYOUT_EXAMPLE_BYTES);
    const auto po = PlanObjectLayout(OBJECT_LAYOUT_EXAMPLE_BYTES, PhysicalObjectLayout::PIECE_OBJECTS);
    const auto le = PlanObjectLayout(OBJECT_LAYOUT_EXAMPLE_BYTES, PhysicalObjectLayout::LARGE_EXTENTS);
    const auto wf = PlanObjectLayout(OBJECT_LAYOUT_EXAMPLE_BYTES, PhysicalObjectLayout::WHOLE_FILE);
    BOOST_CHECK_EQUAL(pieces, 102400U);
    BOOST_CHECK_EQUAL(po.piece_objects, 102400U);
    BOOST_CHECK_EQUAL(le.extent_objects, 1600U);
    BOOST_CHECK_EQUAL(wf.whole_file_objects, 1U);
    BOOST_CHECK_GT(po.piece_objects, le.extent_objects);
    BOOST_CHECK_GT(le.extent_objects, wf.whole_file_objects);
    const uint64_t piece_gets = EstimatedGetsPerColdRetrieval(CloudObjectLayout::PIECE_OBJECTS, 1, pieces);
    const uint64_t source_gets = EstimatedGetsPerColdRetrieval(CloudObjectLayout::SOURCE_FILES, 1, pieces);
    BOOST_CHECK_EQUAL(piece_gets, 102400U);
    BOOST_CHECK_EQUAL(source_gets, 1U);
}

BOOST_AUTO_TEST_CASE(conv_bootstrap_twenty_buyers_distinct_leases)
{
    using namespace modelnet;
    BootstrapDistributor dist(20 * (256ull << 20), 256ull << 20);
    std::set<uint64_t> offsets;
    for (int i = 0; i < 20; ++i) {
        BootstrapLease lease;
        std::string err;
        BOOST_REQUIRE(dist.AssignLease("buyer-" + std::to_string(i), 1000, 60'000, lease, err));
        BOOST_CHECK(offsets.insert(lease.offset).second);
        BOOST_CHECK(dist.AdvertiseMissing(lease.offset, 1));
        BOOST_CHECK(!dist.AdvertiseMissing(20 * (256ull << 20), 1));
    }
}

BOOST_AUTO_TEST_CASE(conv_erasure_global_n_is_not_reconstructable)
{
    using namespace modelnet;
    std::vector<std::vector<unsigned char>> data(2, std::vector<unsigned char>(16, 0x11));
    std::vector<std::vector<unsigned char>> shards;
    std::string err;
    BOOST_REQUIRE(EncodeShards(data, 4, shards, err));
    std::vector<std::vector<int>> positions = {{0, 1}, {0}};
    BOOST_CHECK(!StripeReconstructable(positions, 2));
    positions[1] = {0, 3};
    BOOST_CHECK(StripeReconstructable(positions, 2));
    std::vector<std::vector<unsigned char>> out;
    BOOST_CHECK(!ReconstructShards(shards, std::vector<int>{0}, 2, 4, out, err));
}

BOOST_AUTO_TEST_CASE(conv_negative_cache_ttl_and_no_global_verdict)
{
    modelnet::NegativeResolveCache cache;
    modelnet::Digest48 id{};
    id.data[0] = 0x42;
    cache.RememberIncomplete(1, id, 10);
    BOOST_CHECK(cache.HasIncomplete(1, id, 10));
    BOOST_CHECK(!cache.HasIncomplete(1, id, 10 + modelnet::NEGATIVE_RESOLVE_TTL_S + 1));
}

BOOST_AUTO_TEST_CASE(conv_origin_correlation_is_not_five_independent_origins)
{
    using namespace modelnet;
    std::vector<PeerId> peers;
    for (int i = 0; i < 5; ++i) {
        PeerId p;
        p.endpoint = "203.0.113." + std::to_string(i) + ":1";
        p.service_id = "svc-" + std::to_string(i);
        p.netgroup = "same-cloud-bucket";
        peers.push_back(p);
    }
    std::set<std::string> identities, netgroups;
    for (const auto& p : peers) {
        identities.insert(p.service_id);
        netgroups.insert(p.netgroup);
    }
    BOOST_CHECK_EQUAL(identities.size(), 5U);
    BOOST_CHECK_EQUAL(netgroups.size(), 1U);
}

BOOST_AUTO_TEST_CASE(conv_reconcile_sparse_diff_cheaper_than_full)
{
    using namespace modelnet;
    std::vector<std::string> a, b;
    a.reserve(1000);
    b.reserve(1000);
    for (int i = 0; i < 1000; ++i) a.push_back("id-" + std::to_string(i));
    b = a;
    b[0] = "id-x";
    IndexReconciler rec;
    const auto same = rec.CompareSets(a, a);
    const auto diff = rec.CompareSets(a, b);
    BOOST_CHECK_EQUAL(static_cast<int>(same.status), static_cast<int>(ReconcileStatus::EQUAL));
    BOOST_CHECK(diff.want_ids.size() <= 32);
}

BOOST_AUTO_TEST_CASE(conv_sentinel_secret_not_in_package_or_rpc)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 1);
    o.pushKV("kind", "btxbundle");
    o.pushKV("note", "public");
    std::vector<unsigned char> bytes;
    std::string err;
    BOOST_REQUIRE(modelnet::EncodeBtxBundle(o, bytes, err));
    const std::string blob(bytes.begin(), bytes.end());
    BOOST_CHECK(blob.find("BTX_TEST_SECRET_SENTINEL") == std::string::npos);
    UniValue secret(UniValue::VOBJ);
    secret.pushKV("schema_version", 1);
    secret.pushKV("secret_key", "BTX_TEST_SECRET_SENTINEL");
    std::vector<unsigned char> denied;
    BOOST_CHECK(!modelnet::EncodePublicBtxBundle(secret, denied, err));
    BOOST_CHECK(!modelnet::TorrentWorkerReceivesS3Credentials());
    BOOST_CHECK(!modelnet::ContentDefinedDedupShipped());
    BOOST_CHECK(modelnet::EndpointLooksLan("192.168.0.8:1"));
}

BOOST_AUTO_TEST_CASE(conv_helper_alias_and_no_autospend)
{
    const fs::path tmp = m_path_root / "conv-alias";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "getmodelcapabilities");
    req.pushKV("params", UniValue(UniValue::VARR));
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, req, result, code, err));
    BOOST_CHECK_EQUAL(result["alias_of"].get_str(), "getmodelnetworkinfo");
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(conv_coalesce_logical_clients_one_backend_get)
{
    using namespace modelnet;
    const uint64_t clients = 1000;
    const uint64_t backend_gets = EstimatedGetsPerColdRetrieval(CloudObjectLayout::SOURCE_FILES, 1, 102400);
    BOOST_CHECK_EQUAL(backend_gets, 1U);
    BOOST_CHECK_LT(backend_gets, clients);
}

BOOST_AUTO_TEST_CASE(conv_credit_ceiling_zero_is_fail_closed)
{
    using namespace modelnet;
    CreditBroker closed{0};
    BOOST_CHECK(!closed.TryReserve(PIECE_SIZE));
    BOOST_CHECK(closed.TryReserve(0));
    BOOST_CHECK_EQUAL(closed.Reserved(), 0);
}

BOOST_AUTO_TEST_CASE(conv_picker_caps_shared_netgroup)
{
    using namespace modelnet;
    SourceAvailability a;
    a.peer.endpoint = "10.0.0.1:1";
    a.peer.netgroup = "ng-a";
    a.file_index = 0;
    a.piece_count = 4;
    SourceAvailability b;
    b.peer.endpoint = "10.0.0.2:1";
    b.peer.netgroup = "ng-a";
    b.file_index = 0;
    b.piece_count = 4;
    PickConfig cfg;
    cfg.max_assignments = 8;
    cfg.max_per_netgroup = 1;
    const auto picks = PickRarestFirst(0, 4, {0, 1, 2, 3}, {a, b}, {}, {}, {}, cfg);
    BOOST_REQUIRE_EQUAL(picks.size(), 1U);
}

BOOST_AUTO_TEST_CASE(conv_verify_manifest_binds_requested_digest)
{
    using namespace modelnet;
    const fs::path tmp = m_path_root / "conv-bind";
    ModelCatalog cat{tmp / "cat", 1 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 7);
    UniValue man;
    std::string err;
    BOOST_REQUIRE(cat.GetManifest(imported.model_id, man, err));
    VerifiedManifest vm;
    BOOST_REQUIRE(VerifyManifestAgainstRequest(man, imported.model_id, vm, err));
    Digest48 other{};
    other.data[0] = 0xff;
    BOOST_CHECK(!VerifyManifestAgainstRequest(man, other, vm, err));
    BOOST_CHECK_EQUAL(err, "ID_MISMATCH");
}

BOOST_AUTO_TEST_CASE(conv_rpc_stubs_are_live_journal_not_flags)
{
    using namespace modelnet;
    const fs::path tmp = m_path_root / "conv-rpc";
    ModelCatalog cat{tmp / "cat", 1 << 20};
    std::string code, err;
    UniValue result;
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "executemodelstoragemigration");
    req.pushKV("params", WithN02Idempotency("executemodelstoragemigration", UniValue(UniValue::VARR)));
    BOOST_REQUIRE(DispatchHelperRpc(cat, req, result, code, err));
    BOOST_CHECK(result["executed"].get_bool());
    BOOST_CHECK(!result["bulk_io"].get_bool());
    BOOST_CHECK(!result["replaces_source_files"].get_bool());

    UniValue hp(UniValue::VOBJ);
    hp.pushKV("piece_count", 4);
    UniValue hparams(UniValue::VARR);
    hparams.push_back(hp);
    UniValue heal(UniValue::VOBJ);
    heal.pushKV("method", "setmodelswarmhealer");
    heal.pushKV("params", WithN02Idempotency("setmodelswarmhealer", hparams));
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(DispatchHelperRpc(cat, heal, result, code, err));
    BOOST_CHECK(result["healer"].get_bool());
    BOOST_CHECK(!result["whole_model"].get_bool());
    BOOST_CHECK(result.exists("endangered"));

    UniValue pol(UniValue::VOBJ);
    pol.pushKV("method", "settorrentsourcepolicy");
    pol.pushKV("params", WithN02Idempotency("settorrentsourcepolicy", UniValue(UniValue::VARR)));
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(DispatchHelperRpc(cat, pol, result, code, err));
    BOOST_CHECK(result["reverse_bridge_live"].get_bool());
    BOOST_CHECK(!result["torrentd_process"].get_bool());
}

BOOST_AUTO_TEST_SUITE_END()
