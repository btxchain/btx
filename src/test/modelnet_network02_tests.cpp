// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// NETWORK-02 Phase A library tests. Packaged acceptance-matrix.csv stays NOT_RUN.

#include <crypto/common.h>
#include <modelnet/bootstrap_distributor.h>
#include <modelnet/catalog.h>
#include <modelnet/erasure_store.h>
#include <modelnet/helper.h>
#include <modelnet/import_plan.h>
#include <modelnet/index_reconcile.h>
#include <modelnet/io_executor.h>
#include <modelnet/metadata_gossip.h>
#include <modelnet/package_bundle.h>
#include <modelnet/piece_picker.h>
#include <modelnet/query_router.h>
#include <modelnet/source_local.h>
#include <modelnet/transfer_session.h>
#include <modelnet/upload_scheduler_drr.h>
#include <modelnet/verified_manifest.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_network02_tests, BasicTestingSetup)

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

BOOST_AUTO_TEST_CASE(v01_install_from_manifest_rederive_id_mismatch)
{
    const fs::path tmp = m_path_root / "n02-v01";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 0x11);
    UniValue man;
    std::string err;
    BOOST_REQUIRE(cat.GetManifest(imported.model_id, man, err));
    BOOST_REQUIRE(cat.InstallFromManifest(man, err, /*complete=*/false));

    UniValue bad = man;
    std::string hex = imported.model_id.Hex();
    hex.back() = (hex.back() == '0') ? '1' : '0';
    bad.pushKV("model_id", hex);
    BOOST_CHECK(!cat.InstallFromManifest(bad, err));
    BOOST_CHECK_EQUAL(err, "ID_MISMATCH");

    modelnet::VerifiedManifest vm;
    BOOST_CHECK(!modelnet::VerifyManifestAgainstRequest(bad, vm, err));
    BOOST_CHECK_EQUAL(err, "ID_MISMATCH");
}

BOOST_AUTO_TEST_CASE(v02_put_fetched_unknown_artifact_rejected)
{
    const fs::path tmp = m_path_root / "n02-v02";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 0x22);
    std::vector<unsigned char> bytes;
    std::vector<modelnet::Digest48> proof;
    uint64_t file_size = 0;
    std::string err;
    BOOST_REQUIRE(cat.GetVerifiedPiece(imported.artifact_id, 0, 0, bytes, proof, file_size, err));
    modelnet::Digest48 unknown{};
    unknown.data[0] = 0xab;
    BOOST_CHECK(!cat.PutFetchedPiece(unknown, 0, 0, bytes, proof, file_size,
                                    imported.core.files[0].pieces_root, err));
    BOOST_CHECK_EQUAL(err, "unknown artifact");
}

BOOST_AUTO_TEST_CASE(v03_rare_lane_respects_global_ceiling)
{
    using namespace modelnet;
    std::vector<SourceAvailability> srcs;
    SourceAvailability sole;
    sole.peer.endpoint = "only";
    sole.file_index = 0;
    sole.piece_count = 4;
    srcs.push_back(sole);
    std::vector<uint32_t> missing = {0, 1, 2, 3};
    PickConfig cfg;
    cfg.max_assignments = 8;
    cfg.global_inflight_ceiling = PIECE_SIZE;
    const auto picks = PickRarestFirst(0, 4, missing, srcs, {}, {}, {}, cfg);
    BOOST_REQUIRE_EQUAL(picks.size(), 1);
    CreditBroker broker{PIECE_SIZE};
    BOOST_REQUIRE(broker.TryReserve(PIECE_SIZE));
    cfg.credit = &broker;
    cfg.global_inflight_ceiling = 32 * PIECE_SIZE;
    const auto blocked = PickRarestFirst(0, 4, missing, srcs, {}, {}, {}, cfg);
    BOOST_CHECK(blocked.empty());
}

BOOST_AUTO_TEST_CASE(v04_diversity_netgroup_not_identity_fallback)
{
    using namespace modelnet;
    PeerId a;
    a.endpoint = "a:1";
    a.netgroup = "ng1";
    PeerId b;
    b.endpoint = "b:1";
    b.netgroup = "ng1";
    BOOST_CHECK(DiversityKey(a) != DiversityKey(b));
    BOOST_CHECK_EQUAL(NetgroupKey(a), NetgroupKey(b));
    std::vector<SourceAvailability> srcs;
    SourceAvailability sa;
    sa.peer = a;
    sa.piece_count = 1;
    SourceAvailability sb;
    sb.peer = b;
    sb.piece_count = 1;
    srcs.push_back(sa);
    srcs.push_back(sb);
    BOOST_CHECK_EQUAL(PieceRarity(0, 0, srcs, {}, {}), 2);
}

BOOST_AUTO_TEST_CASE(v05_credit_broker_and_session_ledger)
{
    using namespace modelnet;
    CreditBroker broker{2 * PIECE_SIZE};
    TransferSession sess(broker);
    uint64_t id1 = 0, id2 = 0, id3 = 0;
    std::string err;
    BOOST_REQUIRE(sess.ReserveAndQueue("a", 0, 0, PIECE_SIZE, id1, err));
    BOOST_REQUIRE(sess.ReserveAndQueue("b", 0, 1, PIECE_SIZE, id2, err));
    BOOST_CHECK(!sess.ReserveAndQueue("c", 0, 2, PIECE_SIZE, id3, err));
    BOOST_CHECK_EQUAL(err, "credit exhausted");
    sess.NoteSent(id1);
    sess.NoteCommitted(id1, PIECE_SIZE);
    BOOST_CHECK_EQUAL(sess.Json()["useful_bytes"].getInt<int64_t>(), static_cast<int64_t>(PIECE_SIZE));
    BOOST_REQUIRE(sess.ReserveAndQueue("c", 0, 2, PIECE_SIZE, id3, err));
    BOOST_CHECK_EQUAL(sess.Outstanding().size(), 2);
    sess.Cancel();
    BOOST_CHECK(sess.Outstanding().empty());
    BOOST_CHECK(sess.Generation() > 1);
    sess.NoteCommitted(id3, PIECE_SIZE);
    BOOST_CHECK(sess.Outstanding().empty());
}

BOOST_AUTO_TEST_CASE(v05_session_destructor_releases_credit)
{
    using namespace modelnet;
    CreditBroker broker{2 * PIECE_SIZE};
    uint64_t id1 = 0, id2 = 0;
    std::string err;
    {
        TransferSession sess(broker);
        BOOST_REQUIRE(sess.ReserveAndQueue("a", 0, 0, PIECE_SIZE, id1, err));
        BOOST_REQUIRE(sess.ReserveAndQueue("b", 0, 1, PIECE_SIZE, id2, err));
        BOOST_CHECK_EQUAL(broker.Reserved(), 2 * PIECE_SIZE);
    }
    BOOST_CHECK_EQUAL(broker.Reserved(), 0);
}

BOOST_AUTO_TEST_CASE(aud06_future_timestamp_not_fresh)
{
    using namespace modelnet;
    SourceAvailability src;
    src.peer.endpoint = "a";
    src.piece_count = 1;
    src.last_update_ms = 5000;
    PickConfig cfg;
    cfg.now_ms = 1000;
    cfg.stale_after_ms = 60000;
    BOOST_CHECK(!SourceIsFresh(src, cfg));
    src.last_update_ms = 0;
    BOOST_CHECK(!SourceIsFresh(src, cfg));
}

BOOST_AUTO_TEST_CASE(package_bundle_roundtrip)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 1);
    o.pushKV("kind", "btxbundle");
    std::vector<unsigned char> bytes;
    std::string err;
    BOOST_REQUIRE(modelnet::EncodeBtxBundle(o, bytes, err));
    BOOST_REQUIRE_GE(bytes.size(), 68U);
    BOOST_CHECK_EQUAL(bytes[0], 'B');
    UniValue got;
    BOOST_REQUIRE(modelnet::DecodeBtxBundle(Span<const unsigned char>{bytes.data(), bytes.size()}, got, err));
    BOOST_CHECK_EQUAL(got["kind"].get_str(), "btxbundle");
}

BOOST_AUTO_TEST_CASE(erasure_per_stripe_not_global_count)
{
    using namespace modelnet;
    std::vector<std::vector<unsigned char>> data{
        std::vector<unsigned char>{1, 2, 3, 4},
        std::vector<unsigned char>{5, 6, 7, 8},
    };
    std::vector<std::vector<unsigned char>> shards;
    std::string err;
    BOOST_REQUIRE(EncodeShards(data, 4, shards, err));
    BOOST_REQUIRE_EQUAL(shards.size(), 4);
    std::vector<std::vector<unsigned char>> rec;
    BOOST_REQUIRE(ReconstructShards({shards[0], shards[2]}, {0, 2}, 2, 4, rec, err));
    BOOST_REQUIRE_EQUAL(rec.size(), 2);
    BOOST_CHECK(rec[0] == data[0]);
    BOOST_CHECK(rec[1] == data[1]);
    BOOST_CHECK(StripeReconstructable({{0, 1, 2}, {0, 3}}, 2));
    BOOST_CHECK(!StripeReconstructable({{0, 1, 2}, {0, 0}}, 2));
}

BOOST_AUTO_TEST_CASE(torrent_range_skips_padding)
{
    using namespace modelnet;
    std::vector<TorrentFileMap> files{{"a", 10, false}, {"pad", 2, true}, {"b", 10, false}};
    std::vector<TorrentSlice> slices;
    std::string err;
    BOOST_REQUIRE(MapTorrentRange(files, 8, 6, slices, err));
    BOOST_REQUIRE_EQUAL(slices.size(), 2);
    BOOST_CHECK_EQUAL(slices[0].name, "a");
    BOOST_CHECK_EQUAL(slices[0].file_offset, 8);
    BOOST_CHECK_EQUAL(slices[0].length, 2);
    BOOST_CHECK_EQUAL(slices[1].name, "b");
    BOOST_CHECK_EQUAL(slices[1].file_offset, 0);
    BOOST_CHECK_EQUAL(slices[1].length, 2);
}

BOOST_AUTO_TEST_CASE(import_plan_immutable_and_authorship_note)
{
    UniValue src(UniValue::VOBJ);
    src.pushKV("kind", "HUGGINGFACE");
    src.pushKV("locator", "https://huggingface.co/org/model");
    src.pushKV("snapshot_token", "rev1");
    UniValue plan(UniValue::VOBJ);
    plan.pushKV("plan_id", std::string(96, 'a'));
    plan.pushKV("source", src);
    modelnet::ImportPlan parsed;
    std::string err;
    BOOST_REQUIRE(modelnet::ParseImportPlan(plan, parsed, err));
    const UniValue dumped = modelnet::ImportPlanJson(parsed);
    BOOST_CHECK(dumped["authorship"].get_str().find("not implied") != std::string::npos);
    std::string ssrf;
    BOOST_CHECK(!modelnet::HuggingFaceLocatorAllowed("http://127.0.0.1/x", ssrf));
    BOOST_CHECK(modelnet::HuggingFaceLocatorAllowed("https://huggingface.co/org/model", ssrf));
}

BOOST_AUTO_TEST_CASE(upload_and_bootstrap_and_gossip)
{
    using namespace modelnet;
    // UploadScheduler (upload_scheduler.cpp) is library-only. Production
    // admits via UploadSchedulerDrr (g_drr in helper_network02.cpp). Do not
    // cite UploadScheduler::Admit as shipping-path evidence.
    DrrConfig cfg;
    cfg.admission.slots = 4;
    cfg.admission.per_identity = 2;
    UploadSchedulerDrr up{cfg};
    DrrUploadRequest a;
    a.identity = "id-a";
    a.netgroup = "ng-a";
    a.schedule = UploadClass::NORMAL;
    a.bytes = 1024;
    uint64_t rid1 = 0, rid2 = 0, rid3 = 0;
    std::string up_err;
    BOOST_REQUIRE(up.Enqueue(a, rid1, up_err));
    BOOST_REQUIRE(up.Enqueue(a, rid2, up_err));
    BOOST_REQUIRE(up.Enqueue(a, rid3, up_err));
    up.RunEpoch();
    DrrSelection s;
    BOOST_CHECK(up.Select(s));
    BOOST_CHECK(up.Select(s));
    BOOST_CHECK(!up.Select(s));
    BOOST_CHECK_EQUAL(s.reason, "per-identity");
    BOOST_CHECK_EQUAL(up.IdentityActive("id-a"), 2);
    BOOST_CHECK_EQUAL(up.Active(), 2);
    BootstrapDistributor dist(1024, 256);
    BOOST_CHECK(dist.AdvertiseMissing(0, 256));
    BootstrapLease lease;
    std::string err;
    BOOST_REQUIRE(dist.AssignLease("p1", 1000, 5000, lease, err));
    OriginOffer ext;
    ext.mode = OriginMode::EXPLICIT_EXTERNAL;
    ext.follow_redirects = true;
    BOOST_CHECK(!OriginOfferAllowed(ext, err));
    GossipMessage gm;
    gm.secret_bearing = true;
    BOOST_CHECK(!GossipMessageAllowed(gm, err));
    const auto sum = SummarizeQueryHits({"a", "b", "c"}, 1);
    BOOST_CHECK_EQUAL(sum.hit_count, 3);
    BOOST_CHECK_EQUAL(sum.truncated, 2);
}

BOOST_AUTO_TEST_CASE(query_router_summary_truncation_and_reconcile_want_cap)
{
    using namespace modelnet;
    QueryRouter qr;
    std::vector<std::string> ids;
    ids.reserve(40);
    for (int i = 0; i < 40; ++i) ids.push_back("id" + std::to_string(i));
    const auto sum = qr.SummarizeIds(ids);
    BOOST_CHECK_EQUAL(sum.hit_count, 40);
    BOOST_CHECK_EQUAL(sum.sample_ids.size(), QUERY_SAMPLE_MAX);
    BOOST_CHECK_EQUAL(sum.truncated, 8);
    BOOST_CHECK(sum.sample_ids.size() < sum.hit_count);

    IndexReconciler rec;
    GossipMessage bad;
    bad.secret_bearing = true;
    std::string err;
    BOOST_CHECK(!rec.AdmitInbound(bad, err));
    BOOST_CHECK(!GossipMessageAllowed(bad, err));
    BOOST_CHECK(err.find("secret") != std::string::npos);

    GossipMessage ok;
    ok.secret_bearing = false;
    BOOST_CHECK(rec.AdmitInbound(ok, err));

    std::vector<std::string> local, remote;
    for (int i = 0; i < 300; ++i) remote.push_back("r" + std::to_string(i));
    const auto diff = rec.CompareSets(local, remote);
    BOOST_CHECK(diff.status == ReconcileStatus::WANT);
    BOOST_CHECK_EQUAL(diff.want_ids.size(), RECONCILE_WANT_MAX);
    BOOST_CHECK(diff.want_truncated);
    BOOST_CHECK(!diff.outbound.secret_bearing);
    BOOST_CHECK(GossipMessageAllowed(diff.outbound, err));
    BOOST_CHECK(!ProviderThroughputIsRankingAuthority());
    BOOST_CHECK(!ReconcileDigestAuthorizesInsert());

    SearchQuery q;
    q.scope = SearchScope::LOCAL;
    const auto plan = qr.Plan(q, {}, 0);
    BOOST_CHECK(plan.local_only);
}

BOOST_AUTO_TEST_CASE(local_bytesource_respects_budget)
{
    const fs::path p = m_path_root / "n02-local" / "blob.bin";
    fs::create_directories(p.parent_path());
    {
        std::ofstream out(p, std::ios::binary);
        out.write("abcdefgh", 8);
    }
    modelnet::LocalFileByteSource src{p};
    std::string err;
    BOOST_REQUIRE(src.Pin(err));
    std::vector<unsigned char> out;
    BOOST_CHECK(!src.Read({0, 8}, out, /*budget*/ 4, err));
    BOOST_REQUIRE(src.Read({2, 3}, out, 8, err));
    BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), "cde");
}

BOOST_AUTO_TEST_CASE(v03_win_zero_and_credit_ceiling_zero_block_unique_rare)
{
    using namespace modelnet;
    std::vector<SourceAvailability> srcs;
    SourceAvailability sole;
    sole.peer.endpoint = "only";
    sole.file_index = 0;
    sole.piece_count = 4;
    srcs.push_back(sole);
    std::vector<uint32_t> missing = {0, 1, 2, 3};
    PickConfig cfg;
    cfg.max_assignments = 8;
    cfg.global_inflight_ceiling = 32 * PIECE_SIZE;

    PeerMetrics dead;
    dead.state = PeerXferState::FAILED;
    BOOST_CHECK_EQUAL(RequestWindowBytes(dead, cfg), 0);
    std::map<std::string, PeerMetrics> metrics;
    metrics["only"] = dead;
    BOOST_CHECK(PickRarestFirst(0, 4, missing, srcs, metrics, {}, {}, cfg).empty());

    CreditBroker closed{0};
    BOOST_CHECK(!closed.TryReserve(PIECE_SIZE));
    BOOST_CHECK(closed.TryReserve(0));
    cfg.credit = &closed;
    BOOST_CHECK(PickRarestFirst(0, 4, missing, srcs, {}, {}, {}, cfg).empty());
}

BOOST_AUTO_TEST_CASE(v05_live_metrics_rerun_and_request_phases)
{
    using namespace modelnet;
    CreditBroker broker{8 * PIECE_SIZE};
    TransferSession sess(broker);
    std::vector<SourceAvailability> srcs;
    SourceAvailability sole;
    sole.peer.endpoint = "live";
    sole.file_index = 0;
    sole.piece_count = 4;
    srcs.push_back(sole);
    std::vector<uint32_t> missing = {0, 1, 2, 3};
    PickConfig cfg;
    cfg.max_assignments = 1;
    cfg.global_inflight_ceiling = 32 * PIECE_SIZE;
    const auto first = PickRarestFirst(0, 4, missing, srcs, sess.Metrics(), {}, {}, cfg);
    BOOST_REQUIRE_EQUAL(first.size(), 1);
    BOOST_CHECK_EQUAL(first[0].endpoint, "live");

    uint64_t rid = 0;
    std::string err;
    BOOST_REQUIRE(sess.ReserveAndQueue("live", 0, first[0].piece_index, PIECE_SIZE, rid, err));
    TransferRequest tr;
    BOOST_REQUIRE(sess.GetRequest(rid, tr));
    BOOST_CHECK(tr.phase == RequestPhase::CREDIT_RESERVED);
    sess.NoteSent(rid);
    BOOST_REQUIRE(sess.GetRequest(rid, tr));
    BOOST_CHECK(tr.phase == RequestPhase::SENT);
    sess.NoteReceiving(rid);
    BOOST_REQUIRE(sess.GetRequest(rid, tr));
    BOOST_CHECK(tr.phase == RequestPhase::RECEIVING);
    sess.NoteVerifying(rid);
    BOOST_REQUIRE(sess.GetRequest(rid, tr));
    BOOST_CHECK(tr.phase == RequestPhase::VERIFYING);
    sess.NoteCommitted(rid, PIECE_SIZE);
    BOOST_REQUIRE(sess.GetRequest(rid, tr));
    BOOST_CHECK(tr.phase == RequestPhase::COMMITTED);

    PeerMetrics fail;
    fail.state = PeerXferState::FAILED;
    sess.ObservePeer("live", fail);
    BOOST_CHECK(PickRarestFirst(0, 4, missing, srcs, sess.Metrics(), {}, {}, cfg).empty());

    uint64_t stale = 0;
    BOOST_REQUIRE(sess.ReserveAndQueue("live", 0, 1, PIECE_SIZE, stale, err));
    sess.Cancel();
    sess.NoteReceiving(stale);
    sess.NoteVerifying(stale);
    sess.NoteCommitted(stale, PIECE_SIZE);
    sess.NoteFailed(stale);
    BOOST_REQUIRE(sess.GetRequest(stale, tr));
    BOOST_CHECK(tr.phase == RequestPhase::CANCELLED);
}

BOOST_AUTO_TEST_CASE(v06_thread_join_raii)
{
    using namespace modelnet;
    std::atomic<int> n{0};
    {
        ThreadJoin join;
        join.threads.emplace_back([&] { n.store(1); });
    }
    BOOST_CHECK_EQUAL(n.load(), 1);
}

BOOST_AUTO_TEST_CASE(bootstrap_expire_reassigns_gap_without_overlap)
{
    using namespace modelnet;
    BootstrapDistributor dist(1024, 256);
    BOOST_CHECK(dist.AdvertiseMissing(0, 256));
    BOOST_CHECK(!dist.AdvertiseMissing(800, 256));
    BOOST_CHECK(!dist.AdvertiseMissing(1024, 1));
    BootstrapLease a, b, c;
    std::string err;
    BOOST_REQUIRE(dist.AssignLease("p1", 1000, 100, a, err));
    BOOST_REQUIRE(dist.AssignLease("p2", 1000, 5000, b, err));
    BOOST_CHECK_EQUAL(a.offset, 0);
    BOOST_CHECK_EQUAL(b.offset, 256);
    BOOST_CHECK_EQUAL(a.length, 256);
    dist.Expire(1101);
    BOOST_REQUIRE(dist.AssignLease("p3", 1101, 100, c, err));
    BOOST_CHECK_EQUAL(c.offset, a.offset);
    BOOST_CHECK_EQUAL(c.length, a.length);
    BOOST_CHECK(c.offset + c.length <= b.offset || c.offset >= b.offset + b.length);
}

BOOST_AUTO_TEST_CASE(io_executor_drain_is_not_io_uring)
{
    modelnet::IoExecutor io(2);
    std::string err;
    BOOST_REQUIRE(io.Submit(err));
    BOOST_REQUIRE(io.Submit(err));
    BOOST_CHECK(!io.Submit(err));
    io.Drain();
    BOOST_CHECK_EQUAL(io.Outstanding(), 0);
    BOOST_REQUIRE(io.Submit(err));
    BOOST_CHECK(!io.StatusJson()["io_uring"].get_bool());
}

BOOST_AUTO_TEST_CASE(n02_upload_policy_idempotency_key_required_and_conflict)
{
    const fs::path tmp = m_path_root / "n02-upload-idem";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue params(UniValue::VARR);
    UniValue body(UniValue::VOBJ);
    body.pushKV("max_slots", 3);
    params.push_back(body);
    UniValue result;
    std::string code, err;
    BOOST_CHECK(!modelnet::DispatchNetwork02Rpc(cat, "setmodeluploadpolicy", params, result, code, err));
    BOOST_CHECK_EQUAL(code, "INVALID_PARAMETER");
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);

    body.pushKV("idempotency_key", "n02-tests-upload-k1");
    params = UniValue(UniValue::VARR);
    params.push_back(body);
    BOOST_REQUIRE(modelnet::DispatchNetwork02Rpc(cat, "setmodeluploadpolicy", params, result, code, err));
    const std::string first = result.write();
    UniValue replay;
    BOOST_REQUIRE(modelnet::DispatchNetwork02Rpc(cat, "setmodeluploadpolicy", params, replay, code, err));
    BOOST_CHECK_EQUAL(first, replay.write());

    UniValue other = body;
    other.pushKV("max_slots", 11);
    UniValue conflict_params(UniValue::VARR);
    conflict_params.push_back(other);
    UniValue conflicted;
    BOOST_CHECK(!modelnet::DispatchNetwork02Rpc(cat, "setmodeluploadpolicy", conflict_params, conflicted, code, err));
    BOOST_CHECK(code == "IDEMPOTENCY_CONFLICT" || code == "REJECTED");
    BOOST_CHECK_EQUAL(conflicted["status"].get_str(), "REJECTED");
    BOOST_CHECK_EQUAL(conflicted["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue info;
    BOOST_REQUIRE(modelnet::DispatchNetwork02Rpc(cat, "getmodeluploadinfo", UniValue(UniValue::VARR), info, code, err));
    BOOST_CHECK_EQUAL(info["max_slots"].getInt<int>(), 3);
}

BOOST_AUTO_TEST_CASE(n02_helper_path_cloud_mirror_require_idempotency_key)
{
    const fs::path tmp = m_path_root / "n02-helper-idem";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue result;
    std::string code, err;
    const char* methods[] = {"setcloudstorage", "setmodelstoragepolicy", "setmodelmirror"};
    for (const char* method : methods) {
        UniValue req(UniValue::VOBJ);
        req.pushKV("method", method);
        req.pushKV("params", UniValue(UniValue::VARR));
        result = UniValue(UniValue::VOBJ);
        code.clear();
        err.clear();
        BOOST_CHECK_MESSAGE(!modelnet::DispatchHelperRpc(cat, req, result, code, err),
                            std::string(method) + " helper path accepted a costly write without idempotency_key");
        BOOST_CHECK_EQUAL(code, "INVALID_PARAMETER");
        BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    }
}

BOOST_AUTO_TEST_SUITE_END()
