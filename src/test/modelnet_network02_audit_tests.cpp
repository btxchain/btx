// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// NETWORK-02 coordinator audit: V-07 wrap cap, object layout, SUBPIECE,
// bulk/io, helper RPC wiring. Packaged acceptance-matrix.csv stays NOT_RUN.

#include <crypto/common.h>
#include <test/modelnet_n02_idem.h>
#include <modelnet/bulk_controller.h>
#include <modelnet/catalog.h>
#include <modelnet/crypto.h>
#include <modelnet/erasure_manifest.h>
#include <modelnet/file_stream.h>
#include <modelnet/hello_caps.h>
#include <modelnet/helper.h>
#include <modelnet/import_plan.h>
#include <modelnet/io_executor.h>
#include <modelnet/lan_discovery.h>
#include <modelnet/multipart_journal.h>
#include <modelnet/operation_budget.h>
#include <modelnet/query_router.h>
#include <modelnet/object_layout.h>
#include <modelnet/package_export.h>
#include <modelnet/physical_dedup.h>
#include <modelnet/residency_state.h>
#include <modelnet/selective_files.h>
#include <modelnet/source_policy.h>
#include <modelnet/subpiece.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <fstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_network02_audit_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> TinySafeTensors(unsigned char tag)
{
    const std::string json = "{\"__metadata__\":{\"t\":\"" + std::to_string(static_cast<int>(tag)) + "\"}}";
    std::vector<unsigned char> st(8 + json.size(), 0);
    WriteLE64(st.data(), json.size());
    std::memcpy(st.data() + 8, json.data(), json.size());
    return st;
}

std::string PlanId()
{
    return std::string(96, 'c');
}

UniValue Rpc(const std::string& method, const UniValue& params)
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", method);
    req.pushKV("params", WithN02Idempotency(method, params));
    return req;
}

void RequireZeroSpend(const UniValue& o)
{
    BOOST_REQUIRE(o.isObject());
    BOOST_REQUIRE_MESSAGE(o.exists("automatic_spend_atoms"), o.write());
    BOOST_CHECK_EQUAL(o["automatic_spend_atoms"].getInt<int>(), 0);
}

void NeverWalletSignedTrue(const UniValue& o)
{
    BOOST_CHECK(!o.exists("wallet_signed") || !o["wallet_signed"].get_bool());
}

} // namespace

BOOST_AUTO_TEST_CASE(v07_release_wrap_is_bounded)
{
    BOOST_CHECK(modelnet::ReleaseWrapAllowed(64ull << 20));
    BOOST_CHECK(!modelnet::ReleaseWrapAllowed((64ull << 20) + 1));
    BOOST_CHECK(!modelnet::ReleaseWrapAllowed(400ull * modelnet::GIB));
}

BOOST_AUTO_TEST_CASE(object_layout_400gib_arithmetic_does_not_replace_source_files)
{
    const auto p = modelnet::PlanObjectLayout(modelnet::OBJECT_LAYOUT_EXAMPLE_BYTES);
    BOOST_CHECK_EQUAL(p.piece_objects, 102400);
    BOOST_CHECK_EQUAL(p.extent_objects, 1600);
    BOOST_CHECK_EQUAL(p.whole_file_objects, 1);
    BOOST_CHECK_EQUAL(p.multipart_parts, 6400);
    BOOST_CHECK(!p.replaces_source_files);
    BOOST_CHECK_EQUAL(modelnet::PhysicalObjectLayoutName(p.effective), "LARGE_EXTENTS");
    const UniValue j = modelnet::ObjectLayoutPlanJson(p);
    BOOST_CHECK_EQUAL(j["cloud_r2_auto"].get_str(), "SOURCE_FILES");
}

BOOST_AUTO_TEST_CASE(subpiece_rejects_overlap_overflow_and_does_not_advertise_partial)
{
    modelnet::SubpieceRequest a;
    a.piece_index = 0;
    a.offset = 0;
    a.length = modelnet::SUBPIECE_SIZE;
    std::string err;
    BOOST_REQUIRE(modelnet::ValidateSubpieceRequest(a, modelnet::PIECE_SIZE, err));

    modelnet::SubpieceRequest bad = a;
    bad.offset = 1;
    BOOST_CHECK(!modelnet::ValidateSubpieceRequest(bad, modelnet::PIECE_SIZE, err));

    bad = a;
    bad.length = modelnet::SUBPIECE_SIZE + 1;
    BOOST_CHECK(!modelnet::ValidateSubpieceRequest(bad, modelnet::PIECE_SIZE, err));

    bad = a;
    bad.offset = modelnet::PIECE_SIZE;
    BOOST_CHECK(!modelnet::ValidateSubpieceRequest(bad, modelnet::PIECE_SIZE, err));

    modelnet::SubpieceAssembly asmbl;
    BOOST_REQUIRE(asmbl.Admit(a, modelnet::PIECE_SIZE, 1, err));
    modelnet::SubpieceRequest overlap = a;
    BOOST_CHECK(!asmbl.Admit(overlap, modelnet::PIECE_SIZE, 1, err));
    BOOST_CHECK(err.find("overlap") != std::string::npos);

    modelnet::SubpieceRequest next = a;
    next.offset = modelnet::SUBPIECE_SIZE;
    BOOST_REQUIRE(asmbl.Admit(next, modelnet::PIECE_SIZE, 1, err));
    BOOST_CHECK(!modelnet::AdvertiseFullPieceOnly() == false);
    BOOST_CHECK(modelnet::AdvertiseFullPieceOnly());
}

BOOST_AUTO_TEST_CASE(bulk_and_io_executor_are_bounded)
{
    modelnet::LowPriorityBulkController bulk;
    bulk.ObserveRtt(40);
    const double ok = bulk.BackgroundShare();
    bulk.ObserveRtt(200);
    bulk.ObserveBackpressure(true);
    BOOST_CHECK(bulk.BackgroundShare() < ok);
    BOOST_CHECK(bulk.InteractiveHasPriority());

    modelnet::IoExecutor io(2);
    std::string err;
    BOOST_REQUIRE(io.Submit(err));
    BOOST_REQUIRE(io.Submit(err));
    BOOST_CHECK(!io.Submit(err));
    io.Complete();
    BOOST_REQUIRE(io.Submit(err));
    BOOST_CHECK_EQUAL(io.Outstanding(), 2);
}

BOOST_AUTO_TEST_CASE(hello_capability_array_includes_network02)
{
    const UniValue caps = modelnet::HelloCapabilityArray();
    BOOST_REQUIRE(caps.isArray());
    bool sub = false, pkg = false, gossip = false;
    for (const auto& c : caps.getValues()) {
        std::string n;
        BOOST_REQUIRE(modelnet::HelloCapabilityEntryName(c, n));
        if (n == modelnet::SUBPIECE_V1) sub = true;
        if (n == "PACKAGE_V1") pkg = true;
        if (n == "METADATA_GOSSIP_V1") gossip = true;
        if (c.isObject()) {
            BOOST_CHECK(c.exists("min") && c.exists("max"));
        }
    }
    BOOST_CHECK(sub);
    BOOST_CHECK(pkg);
    BOOST_CHECK(gossip);
    UniValue hello(UniValue::VOBJ);
    hello.pushKV("capabilities", caps);
    BOOST_CHECK(modelnet::HelloHasCapability(hello, modelnet::FULL_FILE_STREAM_V1));
    BOOST_CHECK(modelnet::HelloHasCapability(hello, modelnet::SUBPIECE_V1));
    size_t stream_cap = 0;
    std::string caperr;
    BOOST_REQUIRE(modelnet::FullFileStreamHttpBodyCap(true, 1024 * 1024, stream_cap, caperr));
    BOOST_CHECK_EQUAL(stream_cap, modelnet::FULL_FILE_STREAM_HTTP_HEADER_SLACK + 1024u * 1024u);
    BOOST_CHECK(!modelnet::FullFileStreamHttpBodyCap(true, modelnet::FULL_FILE_STREAM_MAX_BYTES + 1, stream_cap, caperr));
}

BOOST_AUTO_TEST_CASE(helper_rpc_import_package_erasure_torrent_origin)
{
    const fs::path tmp = m_path_root / "n02-audit-rpc";
    fs::create_directories(tmp / "src");
    const auto st = TinySafeTensors(0x42);
    {
        std::ofstream out(tmp / "src" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::ModelCatalog cat{tmp / "cat", 8 << 20};

    UniValue plan(UniValue::VOBJ);
    plan.pushKV("plan_id", PlanId());
    UniValue src(UniValue::VOBJ);
    src.pushKV("kind", "LOCAL");
    src.pushKV("locator", fs::PathToString(tmp / "src"));
    src.pushKV("snapshot_token", "rev-local");
    plan.pushKV("source", src);
    UniValue files(UniValue::VARR);
    UniValue f(UniValue::VOBJ);
    f.pushKV("source_path", "model.safetensors");
    f.pushKV("destination_path", "model.safetensors");
    f.pushKV("size_bytes", static_cast<int>(st.size()));
    files.push_back(f);
    plan.pushKV("files", files);

    UniValue params(UniValue::VARR);
    params.push_back(plan);
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("executemodelimport", params), result, code, err), err);
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(result["authorship"].get_str().find("not implied") != std::string::npos);
    BOOST_CHECK(result["has_verified_manifest"].get_bool());
    BOOST_CHECK_EQUAL(result["phase"].get_str(), "PUBLISH_READY");

    UniValue getp(UniValue::VARR);
    UniValue gid(UniValue::VOBJ);
    gid.pushKV("plan_id", PlanId());
    getp.push_back(gid);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getmodelimport", getp), result, code, err));
    BOOST_CHECK(result["publish_ready"].get_bool());

    UniValue pkg(UniValue::VOBJ);
    pkg.pushKV("kind", "btxbundle");
    pkg.pushKV("schema_version", 1);
    UniValue pp(UniValue::VARR);
    pp.push_back(pkg);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("createbtxpackage", pp), result, code, err), err);
    BOOST_CHECK(result.exists("hex"));
    BOOST_CHECK(!result["magnet_analog"].get_bool());

    UniValue insp(UniValue::VARR);
    UniValue ih(UniValue::VOBJ);
    ih.pushKV("hex", result["hex"].get_str());
    insp.push_back(ih);
    UniValue inspected;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("inspectbtxpackage", insp), inspected, code, err));
    BOOST_CHECK(inspected["ok"].get_bool());
    BOOST_CHECK(!inspected["imported_catalog"].get_bool());

    UniValue er(UniValue::VOBJ);
    er.pushKV("version", 1);
    er.pushKV("profile", modelnet::ERASURE_PROFILE_CAUCHY_16_20_V1);
    er.pushKV("canonical_artifact_id", std::string(96, 'f'));
    er.pushKV("canonical_manifest_id", std::string(96, 'a'));
    er.pushKV("file_index", 0);
    er.pushKV("file_size_bytes", "429496729600");
    er.pushKV("data_shards", 16);
    er.pushKV("total_shards", 20);
    er.pushKV("shard_bytes", 4194304);
    er.pushKV("field_polynomial", "0x11d");
    er.pushKV("stripe_count", "2");
    er.pushKV("final_real_piece_count", 16);
    er.pushKV("shard_index_root", std::string(96, 'b'));
    UniValue stripes(UniValue::VARR);
    UniValue s0(UniValue::VOBJ);
    s0.pushKV("index", 0);
    UniValue p0(UniValue::VARR);
    for (int i = 0; i < 16; ++i) p0.push_back(i);
    s0.pushKV("positions", p0);
    UniValue s1(UniValue::VOBJ);
    s1.pushKV("index", 1);
    UniValue p1(UniValue::VARR);
    for (int i = 0; i < 15; ++i) p1.push_back(i);
    s1.pushKV("positions", p1);
    stripes.push_back(s0);
    stripes.push_back(s1);
    er.pushKV("stripes", stripes);
    UniValue ep(UniValue::VARR);
    ep.push_back(er);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("preparemodelerasure", ep), result, code, err), err);
    BOOST_CHECK(!result["reconstructable"].get_bool());
    BOOST_CHECK(!result["global_n_is_sufficiency"].get_bool());
    BOOST_CHECK(!result["repair_executed"].get_bool());

    UniValue tor(UniValue::VOBJ);
    tor.pushKV("locator", "magnet:?xt=urn:btih:abcdef");
    UniValue tp(UniValue::VARR);
    tp.push_back(tor);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("gettorrentsourcestatus", tp), result, code, err));
    BOOST_CHECK_EQUAL(result["infohash"].get_str(), "abcdef");
    BOOST_CHECK(!result["torrentd_process"].get_bool());
    BOOST_CHECK(result["authorship"].get_str().find("not implied") != std::string::npos);
    BOOST_CHECK(result["reverse_bridge"].get_bool());
    BOOST_CHECK(!result["reverse_bridge_live"].get_bool());

    UniValue orig(UniValue::VOBJ);
    orig.pushKV("artifact_id", "local");
    orig.pushKV("length_bytes", 4096);
    UniValue op(UniValue::VARR);
    op.push_back(orig);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("getmodeloriginoffer", op), result, code, err), err);
    BOOST_CHECK(!result.exists("external_url"));
    BOOST_CHECK(!result["presigned_get_is_meter"].get_bool());

    UniValue lay(UniValue::VOBJ);
    lay.pushKV("file_size_bytes", "429496729600");
    UniValue lp(UniValue::VARR);
    lp.push_back(lay);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getmodelobjectlayout", lp), result, code, err));
    BOOST_CHECK_EQUAL(result["piece_objects"].getInt<int>(), 102400);
    BOOST_CHECK(!result["replaces_source_files"].get_bool());

    UniValue ev;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getevaluatedtransport", UniValue(UniValue::VARR)), ev, code, err));
    BOOST_CHECK_EQUAL(ev["utp"].get_str(), "NONSHIPPING");
    BOOST_CHECK(!ev["quic"].get_bool());
    BOOST_CHECK(!ev["btx_torrentd_process"].get_bool());

    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = "/btx-model/2/hello";
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    UniValue hello;
    BOOST_REQUIRE(hello.read(nresp.body));
    BOOST_CHECK(modelnet::HelloHasCapability(hello, modelnet::SUBPIECE_V1));
    BOOST_CHECK(modelnet::HelloHasCapability(hello, modelnet::FULL_FILE_STREAM_V1));
}

BOOST_AUTO_TEST_CASE(v08_hf_plan_is_source_integrity_not_authorship)
{
    const fs::path tmp = m_path_root / "n02-audit-hf";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue plan(UniValue::VOBJ);
    plan.pushKV("plan_id", std::string(96, 'd'));
    UniValue src(UniValue::VOBJ);
    src.pushKV("kind", "HUGGINGFACE");
    src.pushKV("locator", "https://huggingface.co/example/model");
    src.pushKV("snapshot_token", "rev-abc");
    plan.pushKV("source", src);
    UniValue files(UniValue::VARR);
    UniValue f(UniValue::VOBJ);
    f.pushKV("source_path", "model.safetensors");
    f.pushKV("destination_path", "model.safetensors");
    f.pushKV("size_bytes", 5);
    files.push_back(f);
    plan.pushKV("files", files);
    UniValue params(UniValue::VARR);
    params.push_back(plan);
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("executemodelimport", params), result, code, err), err);
    BOOST_CHECK(!result["live_http"].get_bool());
    BOOST_CHECK(result["provenance_note"].get_str().find("not publisher") != std::string::npos);
    BOOST_CHECK(result["authorship"].get_str().find("not implied") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(catalog_aliases_and_remaining_network02_contracts)
{
    const fs::path tmp = m_path_root / "n02-audit-alias";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    std::string code, err;
    UniValue result;

    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getmodelcapabilities", UniValue(UniValue::VARR)), result, code, err));
    BOOST_CHECK_EQUAL(result["alias_of"].get_str(), "getmodelnetworkinfo");
    BOOST_CHECK_EQUAL(result["catalog_method"].get_str(), "getmodelcapabilities");

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getmodelresidency", UniValue(UniValue::VARR)), result, code, err));
    BOOST_CHECK_EQUAL(result["VERIFIED_LOCAL"].get_str(), "VERIFIED_LOCAL");
    BOOST_CHECK(!result["remote_existence_implies_verified_remote"].get_bool());

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getmodeldedupinfo", UniValue(UniValue::VARR)), result, code, err));
    BOOST_CHECK(!result["content_defined_dedup"].get_bool());
    BOOST_CHECK(!result["cross_tenant"].get_bool());

    UniValue lan(UniValue::VOBJ);
    lan.pushKV("endpoint", "192.168.1.20:8334");
    UniValue lp(UniValue::VARR);
    lp.push_back(lan);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getmodellandiscovery", lp), result, code, err));
    BOOST_CHECK(result["lan"].get_bool());
    BOOST_CHECK(!result["delegated_routing_is_consensus"].get_bool());

    UniValue sel(UniValue::VOBJ);
    UniValue files(UniValue::VARR);
    files.push_back(1);
    sel.pushKV("files", files);
    UniValue sp(UniValue::VARR);
    sp.push_back(sel);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getmodelfileselection", sp), result, code, err));
    BOOST_CHECK(!result["all_files"].get_bool());
    BOOST_CHECK(!result["selected_0"].get_bool());
    BOOST_CHECK(!result["advertise_have_0"].get_bool());

    UniValue mpu(UniValue::VOBJ);
    mpu.pushKV("initiate", true);
    mpu.pushKV("object_key", "staging/obj");
    mpu.pushKV("upload_id", "up-1");
    mpu.pushKV("planned_parts", 1);
    UniValue mp(UniValue::VARR);
    mp.push_back(mpu);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getmultipartjournal", mp), result, code, err));
    BOOST_CHECK(!result["etag_is_canonical_identity"].get_bool());

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getsourcepolicy", UniValue(UniValue::VARR)), result, code, err));
    BOOST_CHECK(!result["torrent_worker_s3_credentials"].get_bool());
    BOOST_CHECK(!result["follow_redirects"].get_bool());

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("planmodelstoragemigration", UniValue(UniValue::VARR)), result, code, err));
    BOOST_CHECK(result["planned"].get_bool());
    BOOST_CHECK(!result["executed"].get_bool());

    UniValue detach(UniValue::VOBJ);
    detach.pushKV("mode", "DETACH");
    UniValue dp(UniValue::VARR);
    dp.push_back(detach);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("removemodelstorage", dp), result, code, err));
    BOOST_CHECK(result["detached"].get_bool());
    BOOST_CHECK(!result["remote_objects_deleted"].get_bool());

    const unsigned char bytes[] = {1, 2, 3, 4};
    BOOST_CHECK(modelnet::SamePhysicalBytes(Span<const unsigned char>{bytes, 4},
                                          Span<const unsigned char>{bytes, 4}));
    BOOST_CHECK(!modelnet::ContentDefinedDedupShipped());
    BOOST_CHECK_EQUAL(modelnet::NetworkResidencyName(modelnet::FromPieceResidency(modelnet::PieceResidency::LOCAL)),
                      "VERIFIED_LOCAL");
    BOOST_CHECK(modelnet::PreferLanPeer("10.0.0.2:1", "203.0.113.4:1"));
    BOOST_CHECK(!modelnet::TorrentWorkerReceivesS3Credentials());

    modelnet::SelectiveFileSet selset;
    selset.SelectOnly({2});
    BOOST_CHECK(!selset.AdvertiseHave(0));
    BOOST_CHECK(selset.AdvertiseHave(2));

    modelnet::MultipartJournal j;
    std::string jerr;
    BOOST_REQUIRE(j.Initiate("k", "u", "snap", 1, jerr));
    modelnet::MultipartPart part;
    part.index = 0;
    part.length = 64;
    part.etag = "opaque";
    BOOST_REQUIRE(j.NotePart(part, jerr));
    BOOST_REQUIRE(j.Complete(jerr));
    BOOST_CHECK(!modelnet::MultipartEtagIsCanonicalIdentity());
}

BOOST_AUTO_TEST_CASE(n02_multipart_seven_phase_journal)
{
    using modelnet::MultipartPhase;
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(MultipartPhase::NONE), 0U);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(MultipartPhase::INITIATED), 1U);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(MultipartPhase::PARTS), 2U);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(MultipartPhase::COMPLETED), 3U);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(MultipartPhase::ABORTED), 4U);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(MultipartPhase::INIT_PLANNED), 5U);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(MultipartPhase::COMPLETE_PLANNED), 6U);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(MultipartPhase::OBJECT_COMMITTED), 7U);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(MultipartPhase::REMOTE_OUTCOME_UNKNOWN), 8U);

    modelnet::MultipartJournal j;
    std::string err;
    const std::string snap = "snap-seven-phase";
    BOOST_REQUIRE(j.PlanInit("models/org/obj", snap, 2, err));
    BOOST_CHECK(j.Phase() == MultipartPhase::INIT_PLANNED);
    BOOST_REQUIRE(j.Initiate("models/org/obj", "upload-seven", snap, 2, err));
    BOOST_CHECK(j.Phase() == MultipartPhase::INITIATED);

    modelnet::MultipartPart p0;
    p0.index = 0;
    p0.offset = 0;
    p0.length = 32;
    p0.etag = "etag-0";
    modelnet::MultipartPart p1;
    p1.index = 1;
    p1.offset = 32;
    p1.length = 16;
    p1.etag = "etag-1";
    BOOST_REQUIRE(j.NotePart(p0, err));
    BOOST_CHECK(j.Phase() == MultipartPhase::PARTS);
    BOOST_REQUIRE(j.NotePart(p1, err));
    BOOST_REQUIRE(j.PlanComplete(err));
    BOOST_CHECK(j.Phase() == MultipartPhase::COMPLETE_PLANNED);
    BOOST_REQUIRE(j.Complete(err));
    BOOST_CHECK(j.Phase() == MultipartPhase::COMPLETED);
    BOOST_REQUIRE(j.CommitObject(err));
    BOOST_CHECK(j.Phase() == MultipartPhase::OBJECT_COMMITTED);
    BOOST_CHECK_EQUAL(j.ListParts().size(), 2U);
    BOOST_CHECK_EQUAL(j.Json()["phase"].get_str(), "OBJECT_COMMITTED");

    modelnet::MultipartJournal uncertain;
    BOOST_REQUIRE(uncertain.Initiate("k2", "u2", snap, 1, err));
    BOOST_REQUIRE(uncertain.NotePart(p0, err));
    BOOST_REQUIRE(uncertain.NoteRemoteUnknown(err));
    BOOST_CHECK(uncertain.Phase() == MultipartPhase::REMOTE_OUTCOME_UNKNOWN);
}

BOOST_AUTO_TEST_CASE(n02_operation_budget_reserve_release_cancel)
{
    using namespace modelnet;
    OperationBudget budget;
    budget.max_bytes = 128;
    budget.max_ops = OPERATION_BUDGET_DEFAULT_MAX_OPS;
    CancelToken token;
    std::string err;

    BOOST_REQUIRE(Reserve(budget, 64, 1, err));
    BOOST_REQUIRE(Reserve(budget, 32, 1, err));
    BOOST_CHECK(!Reserve(budget, 64, 1, err));

    OperationBudget tight;
    tight.max_ops = OPERATION_BUDGET_MAX_OPS_CAP;
    for (uint64_t i = 0; i < OPERATION_BUDGET_MAX_OPS_CAP; ++i) {
        BOOST_REQUIRE(Reserve(tight, 0, 1, err));
    }
    BOOST_CHECK(!Reserve(tight, 0, 1, err));

    Release(budget, 64, 1);
    BOOST_REQUIRE(Reserve(budget, 64, 1, err));

    Cancel(budget, &token);
    BOOST_CHECK(budget.cancelled);
    BOOST_CHECK(token.cancelled);
    BOOST_CHECK(!Reserve(budget, 1, 1, err));
}

BOOST_AUTO_TEST_CASE(n02_query_summary_snapshot_generation_stamps)
{
    modelnet::QueryRouter router;
    std::vector<std::string> ids{"a", "b", "c"};
    const auto first = router.SummarizeIds(ids);
    BOOST_CHECK_EQUAL(first.hit_count, 3U);
    BOOST_CHECK_EQUAL(first.snapshot_generation, 1U);
    const auto second = router.SummarizeIds(ids);
    BOOST_CHECK_EQUAL(second.snapshot_generation, 2U);
    BOOST_CHECK_EQUAL(second.tombstone_floor, 0U);
}

BOOST_AUTO_TEST_CASE(n02_healer_and_execute_migration_are_not_stubs)
{
    const fs::path tmp = m_path_root / "n02-audit-gap";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    std::string code, err;
    UniValue result;

    UniValue exec(UniValue::VOBJ);
    exec.pushKV("file_size_bytes", "429496729600");
    UniValue ep(UniValue::VARR);
    ep.push_back(exec);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("executemodelstoragemigration", ep), result, code, err));
    BOOST_CHECK(result["executed"].get_bool());
    BOOST_CHECK(!result["bulk_io"].get_bool());

    UniValue h(UniValue::VOBJ);
    h.pushKV("piece_count", 2);
    UniValue hp(UniValue::VARR);
    hp.push_back(h);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("setmodelswarmhealer", hp), result, code, err));
    BOOST_CHECK(result["healer"].get_bool());
    BOOST_CHECK(result.exists("endangered"));
    BOOST_CHECK(!result["whole_model"].get_bool());

    UniValue tp(UniValue::VARR);
    tp.push_back(UniValue(UniValue::VOBJ));
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("settorrentsourcepolicy", tp), result, code, err));
    BOOST_CHECK(result["reverse_bridge_live"].get_bool());
    BOOST_CHECK(!result["torrentd_process"].get_bool());

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getbootstrapstatus", UniValue(UniValue::VARR)), result, code, err));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!result.exists("have_as_missing") || !result["have_as_missing"].get_bool());

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getmodeluploadinfo", UniValue(UniValue::VARR)), result, code, err));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue er(UniValue::VOBJ);
    er.pushKV("version", 1);
    er.pushKV("profile", modelnet::ERASURE_PROFILE_CAUCHY_16_20_V1);
    er.pushKV("canonical_artifact_id", std::string(96, 'f'));
    er.pushKV("canonical_manifest_id", std::string(96, 'a'));
    er.pushKV("file_index", 0);
    er.pushKV("file_size_bytes", "429496729600");
    er.pushKV("data_shards", 16);
    er.pushKV("total_shards", 20);
    er.pushKV("shard_bytes", 4194304);
    er.pushKV("field_polynomial", "0x11d");
    er.pushKV("stripe_count", "2");
    er.pushKV("final_real_piece_count", 16);
    er.pushKV("shard_index_root", std::string(96, 'b'));
    UniValue stripes(UniValue::VARR);
    UniValue s0(UniValue::VOBJ);
    s0.pushKV("index", 0);
    UniValue p0(UniValue::VARR);
    for (int i = 0; i < 16; ++i) p0.push_back(i);
    s0.pushKV("positions", p0);
    UniValue s1(UniValue::VOBJ);
    s1.pushKV("index", 1);
    UniValue p1(UniValue::VARR);
    for (int i = 0; i < 15; ++i) p1.push_back(i);
    s1.pushKV("positions", p1);
    stripes.push_back(s0);
    stripes.push_back(s1);
    er.pushKV("stripes", stripes);
    UniValue ep2(UniValue::VARR);
    ep2.push_back(er);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("executemodelerasure", ep2), result, code, err), err);
    BOOST_CHECK(!result["reconstructable"].get_bool());
    BOOST_CHECK(!result["global_n_is_sufficiency"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("repairmodel", ep2), result, code, err), err);
    BOOST_CHECK(!result["repair_executed"].get_bool() || result.exists("note"));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(n02_bootstrap_routing_discovery_package_import_export)
{
    const fs::path tmp = m_path_root / "n02-audit-remaining";
    fs::create_directories(tmp / "src");
    const auto st = TinySafeTensors(0x43);
    {
        std::ofstream out(tmp / "src" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::ModelCatalog cat{tmp / "cat", 8 << 20};
    std::string code, err;
    UniValue result;

    UniValue boot(UniValue::VOBJ);
    boot.pushKV("file_size_bytes", "429496729600");
    UniValue bp(UniValue::VARR);
    bp.push_back(boot);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("setbootstrapdistributor", bp), result, code, err), err);
    BOOST_CHECK(!result["false_missing_advertised"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getmodelroutingstatus", UniValue(UniValue::VARR)), result, code, err));
    BOOST_CHECK(!result["throughput_is_ranking"].get_bool());
    BOOST_CHECK(!result["delegated_routing_is_consensus"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("setmodeldiscoverypolicy", UniValue(UniValue::VARR)), result, code, err));
    BOOST_CHECK(!result["throughput_is_ranking"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue pkg(UniValue::VOBJ);
    pkg.pushKV("kind", "btxbundle");
    pkg.pushKV("schema_version", 1);
    UniValue pp(UniValue::VARR);
    pp.push_back(pkg);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("createbtxpackage", pp), result, code, err), err);
    BOOST_CHECK(result.exists("hex"));
    BOOST_CHECK(!result["hex"].get_str().empty());

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("exportbtxbundle", pp), result, code, err), err);
    BOOST_CHECK(!result["magnet_analog"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(result.exists("hex"));
    BOOST_CHECK(!result["hex"].get_str().empty());
    const std::string hex = result["hex"].get_str();

    UniValue ih(UniValue::VOBJ);
    ih.pushKV("hex", hex);
    UniValue ip(UniValue::VARR);
    ip.push_back(ih);

    UniValue inspected;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("inspectbtxpackage", ip), inspected, code, err));
    BOOST_CHECK(inspected["ok"].get_bool());
    BOOST_CHECK(!inspected["imported_catalog"].get_bool());
    BOOST_CHECK_EQUAL(inspected["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!inspected.exists("wallet_signed") || !inspected["wallet_signed"].get_bool());

    result = UniValue(UniValue::VOBJ);
    const bool import_ok = modelnet::DispatchHelperRpc(cat, Rpc("importbtxpackage", ip), result, code, err);
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!result.exists("wallet_signed") || !result["wallet_signed"].get_bool());
    BOOST_CHECK(!result.exists("imported_catalog") || !result["imported_catalog"].get_bool());
    if (import_ok) {
        BOOST_CHECK(!result["imported_catalog"].get_bool());
    } else {
        BOOST_CHECK(code != "METHOD_NOT_FOUND");
        BOOST_CHECK(err.find("VerifiedManifest") != std::string::npos || err.find("manifest") != std::string::npos ||
                    err.find("INVALID") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(n02_query_io_erasure_acq_import_lifecycle)
{
    const fs::path tmp = m_path_root / "n02-audit-lifecycle";
    fs::create_directories(tmp / "src");
    const auto st = TinySafeTensors(0x44);
    {
        std::ofstream out(tmp / "src" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::ModelCatalog cat{tmp / "cat", 8 << 20};
    std::string code, err;
    UniValue result;

    UniValue er(UniValue::VOBJ);
    er.pushKV("version", 1);
    er.pushKV("profile", modelnet::ERASURE_PROFILE_CAUCHY_16_20_V1);
    er.pushKV("canonical_artifact_id", std::string(96, 'f'));
    er.pushKV("canonical_manifest_id", std::string(96, 'a'));
    er.pushKV("file_index", 0);
    er.pushKV("file_size_bytes", "429496729600");
    er.pushKV("data_shards", 16);
    er.pushKV("total_shards", 20);
    er.pushKV("shard_bytes", 4194304);
    er.pushKV("field_polynomial", "0x11d");
    er.pushKV("stripe_count", "2");
    er.pushKV("final_real_piece_count", 16);
    er.pushKV("shard_index_root", std::string(96, 'b'));
    UniValue stripes(UniValue::VARR);
    UniValue s0(UniValue::VOBJ);
    s0.pushKV("index", 0);
    UniValue p0(UniValue::VARR);
    for (int i = 0; i < 16; ++i) p0.push_back(i);
    s0.pushKV("positions", p0);
    UniValue s1(UniValue::VOBJ);
    s1.pushKV("index", 1);
    UniValue p1(UniValue::VARR);
    for (int i = 0; i < 15; ++i) p1.push_back(i);
    s1.pushKV("positions", p1);
    stripes.push_back(s0);
    stripes.push_back(s1);
    er.pushKV("stripes", stripes);
    UniValue ep(UniValue::VARR);
    ep.push_back(er);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("getmodelerasurehealth", ep), result, code, err), err);
    BOOST_CHECK(!result["reconstructable"].get_bool());
    BOOST_CHECK(!result["global_n_is_sufficiency"].get_bool());
    RequireZeroSpend(result);
    NeverWalletSignedTrue(result);

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("querymodelsummary", UniValue(UniValue::VARR)), result, code, err));
    BOOST_CHECK(!result["complete"].get_bool());
    BOOST_CHECK(!result["throughput_is_ranking"].get_bool());
    RequireZeroSpend(result);
    NeverWalletSignedTrue(result);

    UniValue rec(UniValue::VOBJ);
    UniValue remote_ids(UniValue::VARR);
    remote_ids.push_back(std::string(96, '1'));
    remote_ids.push_back(std::string(96, '2'));
    rec.pushKV("remote_ids", remote_ids);
    UniValue rp(UniValue::VARR);
    rp.push_back(rec);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("reconcilemodelindex", rp), result, code, err));
    BOOST_CHECK(!result["digest_authorizes_insert"].get_bool());
    BOOST_CHECK(result.exists("want_cap"));
    RequireZeroSpend(result);
    NeverWalletSignedTrue(result);

    UniValue sp(UniValue::VOBJ);
    sp.pushKV("offset", 0);
    sp.pushKV("length", 262144);
    sp.pushKV("piece_index", 0);
    sp.pushKV("file_size_bytes", 4194304);
    UniValue spp(UniValue::VARR);
    spp.push_back(sp);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("validatesubpiece", spp), result, code, err), err);
    BOOST_CHECK(result["ok"].get_bool());
    if (result.exists("advertise_full_piece_only")) {
        BOOST_CHECK(result["advertise_full_piece_only"].get_bool());
    }
    if (result.exists("automatic_spend_atoms")) {
        BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    }
    NeverWalletSignedTrue(result);

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getmodelioexecutor", UniValue(UniValue::VARR)), result, code, err));
    if (result.exists("io_uring")) {
        BOOST_CHECK(!result["io_uring"].get_bool());
    }
    RequireZeroSpend(result);
    NeverWalletSignedTrue(result);

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getmodelbulkstatus", UniValue(UniValue::VARR)), result, code, err));
    RequireZeroSpend(result);
    NeverWalletSignedTrue(result);

    UniValue up(UniValue::VOBJ);
    up.pushKV("max_slots", 2);
    UniValue upp(UniValue::VARR);
    upp.push_back(up);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("setmodeluploadpolicy", upp), result, code, err));
    BOOST_CHECK(!result["connection_count_is_capacity"].get_bool());
    RequireZeroSpend(result);
    NeverWalletSignedTrue(result);

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getmodeloriginstatus", UniValue(UniValue::VARR)), result, code, err));
    BOOST_CHECK(!result["presigned_get_is_meter"].get_bool());
    RequireZeroSpend(result);
    NeverWalletSignedTrue(result);

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getbtxpackagecapabilities", UniValue(UniValue::VARR)), result, code, err));
    RequireZeroSpend(result);
    NeverWalletSignedTrue(result);
    BOOST_CHECK(!result.exists("remote_inference") || !result["remote_inference"].get_bool());
    BOOST_CHECK(!result.exists("public_inference") || !result["public_inference"].get_bool());

    const std::string plan_id(96, 'e');
    UniValue plan(UniValue::VOBJ);
    plan.pushKV("plan_id", plan_id);
    UniValue src(UniValue::VOBJ);
    src.pushKV("kind", "LOCAL");
    src.pushKV("locator", fs::PathToString(tmp / "src"));
    src.pushKV("snapshot_token", "rev-lifecycle");
    plan.pushKV("source", src);
    UniValue files(UniValue::VARR);
    UniValue f(UniValue::VOBJ);
    f.pushKV("source_path", "model.safetensors");
    f.pushKV("destination_path", "model.safetensors");
    f.pushKV("size_bytes", static_cast<int>(st.size()));
    files.push_back(f);
    plan.pushKV("files", files);
    UniValue ip(UniValue::VARR);
    ip.push_back(plan);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("executemodelimport", ip), result, code, err), err);
    RequireZeroSpend(result);
    NeverWalletSignedTrue(result);

    UniValue gid(UniValue::VOBJ);
    gid.pushKV("plan_id", plan_id);
    UniValue gp(UniValue::VARR);
    gp.push_back(gid);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("getmodelimport", gp), result, code, err), err);
    RequireZeroSpend(result);
    NeverWalletSignedTrue(result);

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("resumemodelimport", gp), result, code, err), err);
    RequireZeroSpend(result);
    NeverWalletSignedTrue(result);

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("publishmodelimport", gp), result, code, err), err);
    RequireZeroSpend(result);
    NeverWalletSignedTrue(result);

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("cancelmodelimport", gp), result, code, err), err);
    BOOST_CHECK(result["cancelled"].get_bool());
    RequireZeroSpend(result);
    NeverWalletSignedTrue(result);
    result = UniValue(UniValue::VOBJ);
    code.clear();
    err.clear();
    const bool get_after_cancel = modelnet::DispatchHelperRpc(cat, Rpc("getmodelimport", gp), result, code, err);
    if (get_after_cancel) {
        RequireZeroSpend(result);
        NeverWalletSignedTrue(result);
    } else {
        BOOST_CHECK(code != "METHOD_NOT_FOUND");
        BOOST_CHECK(err.find("unknown") != std::string::npos || code == "INVALID_PARAMETER");
    }

    UniValue pkg(UniValue::VOBJ);
    pkg.pushKV("kind", "btxbundle");
    pkg.pushKV("schema_version", 1);
    UniValue pp(UniValue::VARR);
    pp.push_back(pkg);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("createbtxpackage", pp), result, code, err), err);
    BOOST_REQUIRE(result.exists("hex"));
    BOOST_CHECK(!result["hex"].get_str().empty());
    if (result.exists("automatic_spend_atoms")) {
        BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    }
    NeverWalletSignedTrue(result);
    const std::string hex = result["hex"].get_str();

    UniValue acq(UniValue::VOBJ);
    acq.pushKV("hex", hex);
    UniValue acqp(UniValue::VARR);
    acqp.push_back(acq);
    result = UniValue(UniValue::VOBJ);
    code.clear();
    err.clear();
    const bool plan_ok = modelnet::DispatchHelperRpc(cat, Rpc("planbtxacquisition", acqp), result, code, err);
    BOOST_CHECK(code != "METHOD_NOT_FOUND");
    if (result.exists("automatic_spend_atoms")) {
        BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    }
    NeverWalletSignedTrue(result);
    std::string acq_plan_id;
    if (plan_ok && result.exists("plan_id") && result["plan_id"].isStr() && !result["plan_id"].get_str().empty()) {
        acq_plan_id = result["plan_id"].get_str();
        RequireZeroSpend(result);
    } else {
        BOOST_CHECK(!plan_ok);
        BOOST_CHECK(code != "METHOD_NOT_FOUND");
        BOOST_TEST_MESSAGE(std::string("planbtxacquisition fail-closed without documents: ") + code + " " + err);
    }

    if (acq_plan_id.empty()) {
        BOOST_TEST_MESSAGE("skip getbtxacquisition: no plan_id");
        BOOST_TEST_MESSAGE("skip executebtxacquisition: no plan_id");
        BOOST_TEST_MESSAGE("skip cancelbtxacquisition: no plan_id");
    } else {
        UniValue aid(UniValue::VOBJ);
        aid.pushKV("plan_id", acq_plan_id);
        UniValue ap(UniValue::VARR);
        ap.push_back(aid);
        result = UniValue(UniValue::VOBJ);
        BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("getbtxacquisition", ap), result, code, err), err);
        RequireZeroSpend(result);
        NeverWalletSignedTrue(result);

        result = UniValue(UniValue::VOBJ);
        BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("executebtxacquisition", ap), result, code, err), err);
        RequireZeroSpend(result);
        NeverWalletSignedTrue(result);

        result = UniValue(UniValue::VOBJ);
        BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("cancelbtxacquisition", ap), result, code, err), err);
        RequireZeroSpend(result);
        NeverWalletSignedTrue(result);
    }
}

BOOST_AUTO_TEST_SUITE_END()
