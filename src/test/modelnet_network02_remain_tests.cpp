// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Remaining NETWORK-02 native evidence: V-05 rerun, truthful bootstrap have-set,
// isolated HF/Xet ByteSource (no live HTTP).

#include <crypto/common.h>
#include <modelnet/bootstrap_distributor.h>
#include <modelnet/catalog.h>
#include <modelnet/erasure_manifest.h>
#include <modelnet/helper.h>
#include <modelnet/io_executor.h>
#include <modelnet/origin_broker.h>
#include <modelnet/piece_picker.h>
#include <modelnet/source_huggingface.h>
#include <modelnet/source_xet.h>
#include <modelnet/transfer_session.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <fstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_network02_remain_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(v05_continuous_rerun_after_commit)
{
    using namespace modelnet;
    CreditBroker credit{uint64_t{8} * PIECE_SIZE};
    TransferSession sess(credit);
    std::vector<uint32_t> missing{0, 1, 2};
    SourceAvailability src;
    src.peer.endpoint = "peer-a";
    src.peer.netgroup = "ng-a";
    src.file_index = 0;
    src.piece_count = 4;
    std::vector<SourceAvailability> srcs{src};
    PickConfig cfg;
    cfg.max_assignments = 1;
    cfg.global_inflight_ceiling = 32 * PIECE_SIZE;

    const auto first = PickRarestFirst(0, 4, missing, srcs, sess.Metrics(), sess.Outstanding(), {}, cfg);
    BOOST_REQUIRE_EQUAL(first.size(), 1);
    uint64_t rid = 0;
    std::string err;
    BOOST_REQUIRE(sess.ReserveAndQueue(first[0].endpoint, 0, first[0].piece_index, PIECE_SIZE, rid, err));
    sess.NoteSent(rid);
    sess.NoteReceiving(rid);
    sess.NoteVerifying(rid);
    sess.NoteCommitted(rid, PIECE_SIZE);

    std::vector<uint32_t> leftover;
    for (uint32_t i : missing) {
        if (i != first[0].piece_index) leftover.push_back(i);
    }
    cfg.max_assignments = 8;
    const auto second = PickRarestFirst(0, 4, leftover, srcs, sess.Metrics(), sess.Outstanding(), {}, cfg);
    BOOST_REQUIRE(!second.empty());
    BOOST_CHECK_NE(second[0].piece_index, first[0].piece_index);
}

BOOST_AUTO_TEST_CASE(bootstrap_does_not_advertise_have_as_missing)
{
    modelnet::BootstrapDistributor dist(1024, 256);
    BOOST_CHECK(dist.AdvertiseMissing(0, 256));
    dist.NoteHave(0, 256);
    BOOST_CHECK(!dist.AdvertiseMissing(0, 256));
    BOOST_CHECK(dist.AdvertiseMissing(256, 256));
    BOOST_CHECK(!dist.AdvertiseMissing(800, 256));
}

BOOST_AUTO_TEST_CASE(huggingface_inject_is_not_authorship)
{
    modelnet::HuggingFaceByteSource src("https://huggingface.co/org/model", "snap-token");
    std::string err;
    BOOST_REQUIRE(src.Pin(err));
    BOOST_CHECK_EQUAL(src.SourceIntegrity(), "snap-token");
    BOOST_CHECK_EQUAL(src.Kind(), "HUGGINGFACE");
    src.InjectTestBytes({'a', 'b', 'c', 'd'});
    std::vector<unsigned char> out;
    modelnet::ReadExtent ext;
    ext.offset = 1;
    ext.length = 2;
    BOOST_REQUIRE(src.Read(ext, out, 16, err));
    BOOST_REQUIRE_EQUAL(out.size(), 2U);
    BOOST_CHECK_EQUAL(out[0], 'b');
    BOOST_CHECK(!src.FollowsRedirects());

    modelnet::HuggingFaceByteSource ssrf("http://127.0.0.1/secret", "snap-token");
    BOOST_CHECK(!ssrf.Pin(err));
}

BOOST_AUTO_TEST_CASE(xet_cas_is_not_model_identity)
{
    modelnet::XetByteSource src("xet://example", "cas-root-token");
    modelnet::XetChunkMap chunks;
    chunks["c0"] = {'h', 'i'};
    chunks["c1"] = {'!', '!'};
    src.SetChunkMap(chunks, {"c0", "c1"});
    std::string err;
    BOOST_REQUIRE(src.Pin(err));
    BOOST_CHECK_EQUAL(src.SourceIntegrity(), "cas-root-token");
    BOOST_CHECK(!src.ClaimsModelIdentity());
    std::vector<unsigned char> out;
    modelnet::ReadExtent ext;
    ext.offset = 0;
    ext.length = 4;
    BOOST_REQUIRE(src.Read(ext, out, 16, err));
    BOOST_REQUIRE_EQUAL(out.size(), 4U);
    BOOST_CHECK_EQUAL(out[0], 'h');
    BOOST_CHECK_EQUAL(out[3], '!');
}

BOOST_AUTO_TEST_CASE(origin_offer_and_io_executor_remain)
{
    modelnet::OriginOffer native;
    native.mode = modelnet::OriginMode::NATIVE_PROXY;
    std::string err;
    BOOST_CHECK(modelnet::OriginOfferAllowed(native, err));
    modelnet::OriginOffer ext;
    ext.mode = modelnet::OriginMode::EXPLICIT_EXTERNAL;
    BOOST_CHECK(!modelnet::OriginOfferAllowed(ext, err));
    ext.locator = "https://example.invalid/file";
    ext.follow_redirects = true;
    BOOST_CHECK(!modelnet::OriginOfferAllowed(ext, err));

    modelnet::IoExecutor io(1);
    BOOST_REQUIRE(io.Submit(err));
    BOOST_CHECK(!io.Submit(err));
    BOOST_CHECK(!io.StatusJson()["io_uring"].get_bool());
    io.Complete();
    BOOST_REQUIRE(io.Submit(err));
}

BOOST_AUTO_TEST_CASE(n02_remain_query_io_erasure_import_lifecycle)
{
    const fs::path tmp = m_path_root / "n02-remain-rpc";
    fs::create_directories(tmp / "src");
    const std::string json = "{\"__metadata__\":{\"t\":\"7\"}}";
    std::vector<unsigned char> st(8 + json.size(), 0);
    WriteLE64(st.data(), json.size());
    std::memcpy(st.data() + 8, json.data(), json.size());
    {
        std::ofstream out(tmp / "src" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::ModelCatalog cat{tmp / "cat", 8 << 20};

    auto rpc = [](const std::string& method, const UniValue& params) {
        UniValue req(UniValue::VOBJ);
        req.pushKV("method", method);
        req.pushKV("params", params);
        return req;
    };

    UniValue result;
    std::string code, err;

    UniValue plan(UniValue::VOBJ);
    plan.pushKV("plan_id", std::string(96, 'e'));
    UniValue src(UniValue::VOBJ);
    src.pushKV("kind", "LOCAL");
    src.pushKV("locator", fs::PathToString(tmp / "src"));
    src.pushKV("snapshot_token", "rev-remain");
    plan.pushKV("source", src);
    UniValue files(UniValue::VARR);
    UniValue f(UniValue::VOBJ);
    f.pushKV("source_path", "model.safetensors");
    f.pushKV("destination_path", "model.safetensors");
    f.pushKV("size_bytes", static_cast<int>(st.size()));
    files.push_back(f);
    plan.pushKV("files", files);
    plan.pushKV("idempotency_key", "n02-remain-import-lifecycle");
    UniValue pp(UniValue::VARR);
    pp.push_back(plan);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc("executemodelimport", pp), result, code, err), err);
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue gid(UniValue::VOBJ);
    gid.pushKV("plan_id", std::string(96, 'e'));
    UniValue gp(UniValue::VARR);
    gp.push_back(gid);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, rpc("getmodelimport", gp), result, code, err));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, rpc("resumemodelimport", gp), result, code, err));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, rpc("publishmodelimport", gp), result, code, err));
    BOOST_CHECK(!result.exists("wallet_signed") || !result["wallet_signed"].get_bool());
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, rpc("cancelmodelimport", gp), result, code, err));
    BOOST_CHECK(result["cancelled"].isTrue());

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
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc("getmodelerasurehealth", ep), result, code, err), err);
    BOOST_CHECK(!result["reconstructable"].get_bool());
    BOOST_CHECK(!result["global_n_is_sufficiency"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, rpc("querymodelsummary", UniValue(UniValue::VARR)), result, code, err));
    BOOST_CHECK(!result["complete"].get_bool());
    BOOST_CHECK(!result["throughput_is_ranking"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue remote(UniValue::VOBJ);
    UniValue ids(UniValue::VARR);
    ids.push_back("id-1");
    remote.pushKV("remote_ids", ids);
    UniValue rp(UniValue::VARR);
    rp.push_back(remote);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, rpc("reconcilemodelindex", rp), result, code, err));
    BOOST_CHECK(!result["digest_authorizes_insert"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue sub(UniValue::VOBJ);
    sub.pushKV("offset", 0);
    sub.pushKV("length", 262144);
    sub.pushKV("piece_index", 0);
    sub.pushKV("file_size_bytes", 4194304);
    UniValue spp(UniValue::VARR);
    spp.push_back(sub);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc("validatesubpiece", spp), result, code, err), err);
    BOOST_CHECK(result["ok"].get_bool());

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, rpc("getmodelioexecutor", UniValue(UniValue::VARR)), result, code, err));
    BOOST_CHECK(!result.exists("io_uring") || !result["io_uring"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, rpc("getmodelbulkstatus", UniValue(UniValue::VARR)), result, code, err));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue up(UniValue::VOBJ);
    up.pushKV("max_slots", 2);
    up.pushKV("idempotency_key", "n02-remain-upload-lifecycle");
    UniValue upp(UniValue::VARR);
    upp.push_back(up);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, rpc("setmodeluploadpolicy", upp), result, code, err));
    BOOST_CHECK(!result["connection_count_is_capacity"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, rpc("getmodeloriginstatus", UniValue(UniValue::VARR)), result, code, err));
    BOOST_CHECK(!result["presigned_get_is_meter"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, rpc("getbtxpackagecapabilities", UniValue(UniValue::VARR)), result, code, err));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!result.exists("remote_inference") || !result["remote_inference"].get_bool());
}

namespace {

bool CallN02(modelnet::ModelCatalog& cat, const std::string& method, UniValue body, UniValue& result, std::string& code,
             std::string& err)
{
    UniValue params(UniValue::VARR);
    params.push_back(std::move(body));
    result = UniValue(UniValue::VOBJ);
    code.clear();
    err.clear();
    return modelnet::DispatchNetwork02Rpc(cat, method, params, result, code, err);
}

UniValue TinyBundleBody()
{
    UniValue pkg(UniValue::VOBJ);
    pkg.pushKV("kind", "btxbundle");
    pkg.pushKV("schema_version", 1);
    return pkg;
}

UniValue TinyErasureBody()
{
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
    return er;
}

} // namespace

BOOST_AUTO_TEST_CASE(n02_costly_write_missing_idempotency_key)
{
    const fs::path tmp = m_path_root / "n02-idem-missing";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue result;
    std::string code, err;

    const char* methods[] = {
        "setcloudstorage",
        "addmodelstorage",
        "createbtxpackage",
        "exportbtxbundle",
        "preparemodelerasure",
        "executemodelerasure",
        "setbootstrapdistributor",
        "setmodeluploadpolicy",
        "planmodelstoragemigration",
        "executemodelstoragemigration",
        "setmodelswarmhealer",
        "settorrentsourcepolicy",
        "setmodeldiscoverypolicy",
        "setmodelmirror",
        "setmodelstoragepolicy",
    };
    for (const char* method : methods) {
        UniValue body = TinyBundleBody();
        if (std::string(method) == "preparemodelerasure" || std::string(method) == "executemodelerasure") {
            body = TinyErasureBody();
        } else if (std::string(method) == "setmodeluploadpolicy") {
            body = UniValue(UniValue::VOBJ);
            body.pushKV("max_slots", 3);
        } else if (std::string(method) == "setcloudstorage" || std::string(method) == "addmodelstorage") {
            body = UniValue(UniValue::VOBJ);
            body.pushKV("endpoint", "https://example.invalid");
        }
        const bool ok = CallN02(cat, method, body, result, code, err);
        BOOST_CHECK_MESSAGE(!ok, std::string(method) + " accepted a costly write without idempotency_key");
        BOOST_CHECK_EQUAL(code, "INVALID_PARAMETER");
        BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    }

    fs::create_directories(tmp / "src");
    const std::string json = "{\"__metadata__\":{\"t\":\"9\"}}";
    std::vector<unsigned char> st(8 + json.size(), 0);
    WriteLE64(st.data(), json.size());
    std::memcpy(st.data() + 8, json.data(), json.size());
    {
        std::ofstream out(tmp / "src" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    UniValue plan(UniValue::VOBJ);
    plan.pushKV("plan_id", std::string(96, 'd'));
    UniValue src(UniValue::VOBJ);
    src.pushKV("kind", "LOCAL");
    src.pushKV("locator", fs::PathToString(tmp / "src"));
    src.pushKV("snapshot_token", "rev-idem-missing");
    plan.pushKV("source", src);
    UniValue files(UniValue::VARR);
    UniValue f(UniValue::VOBJ);
    f.pushKV("source_path", "model.safetensors");
    f.pushKV("destination_path", "model.safetensors");
    f.pushKV("size_bytes", static_cast<int>(st.size()));
    files.push_back(f);
    plan.pushKV("files", files);
    BOOST_CHECK(!CallN02(cat, "executemodelimport", plan, result, code, err));
    BOOST_CHECK_EQUAL(code, "INVALID_PARAMETER");
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(n02_costly_write_idempotency_replay_identical)
{
    const fs::path tmp = m_path_root / "n02-idem-replay";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue first, second, probe;
    std::string code, err;

    UniValue body(UniValue::VOBJ);
    body.pushKV("max_slots", 4);
    body.pushKV("idempotency_key", "n02-replay-upload");
    BOOST_REQUIRE(CallN02(cat, "setmodeluploadpolicy", body, first, code, err));
    BOOST_CHECK_EQUAL(first["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_REQUIRE(CallN02(cat, "setmodeluploadpolicy", body, second, code, err));
    BOOST_CHECK_EQUAL(first.write(), second.write());

    UniValue changed = body;
    changed.pushKV("max_slots", 8);
    BOOST_CHECK(!CallN02(cat, "setmodeluploadpolicy", changed, probe, code, err));
    BOOST_CHECK(code == "IDEMPOTENCY_CONFLICT" || code == "REJECTED");
    BOOST_CHECK_EQUAL(probe["status"].get_str(), "REJECTED");
    BOOST_CHECK_EQUAL(probe["automatic_spend_atoms"].getInt<int>(), 0);

    BOOST_REQUIRE(CallN02(cat, "getmodeluploadinfo", UniValue(UniValue::VOBJ), probe, code, err));
    BOOST_CHECK_EQUAL(probe["max_slots"].getInt<int>(), 4);

    UniValue pkg = TinyBundleBody();
    pkg.pushKV("idempotency_key", "n02-replay-pkg");
    BOOST_REQUIRE_MESSAGE(CallN02(cat, "createbtxpackage", pkg, first, code, err), err);
    BOOST_REQUIRE(CallN02(cat, "createbtxpackage", pkg, second, code, err));
    BOOST_CHECK_EQUAL(first.write(), second.write());
    BOOST_CHECK_EQUAL(first["automatic_spend_atoms"].getInt<int>(), 0);

    fs::create_directories(tmp / "src");
    const std::string json = "{\"__metadata__\":{\"t\":\"a\"}}";
    std::vector<unsigned char> st(8 + json.size(), 0);
    WriteLE64(st.data(), json.size());
    std::memcpy(st.data() + 8, json.data(), json.size());
    {
        std::ofstream out(tmp / "src" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    UniValue plan(UniValue::VOBJ);
    plan.pushKV("plan_id", std::string(96, 'b'));
    UniValue src(UniValue::VOBJ);
    src.pushKV("kind", "LOCAL");
    src.pushKV("locator", fs::PathToString(tmp / "src"));
    src.pushKV("snapshot_token", "rev-idem-replay");
    plan.pushKV("source", src);
    UniValue files(UniValue::VARR);
    UniValue f(UniValue::VOBJ);
    f.pushKV("source_path", "model.safetensors");
    f.pushKV("destination_path", "model.safetensors");
    f.pushKV("size_bytes", static_cast<int>(st.size()));
    files.push_back(f);
    plan.pushKV("files", files);
    plan.pushKV("idempotency_key", "n02-replay-import");
    BOOST_REQUIRE_MESSAGE(CallN02(cat, "executemodelimport", plan, first, code, err), err);
    BOOST_REQUIRE(CallN02(cat, "executemodelimport", plan, second, code, err));
    BOOST_CHECK_EQUAL(first.write(), second.write());
    BOOST_CHECK(!second.exists("idempotent") || !second["idempotent"].get_bool());
}

BOOST_AUTO_TEST_CASE(n02_costly_write_idempotency_conflict_rejects)
{
    const fs::path tmp = m_path_root / "n02-idem-conflict";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue result;
    std::string code, err;

    auto roundtrip = [&](const char* method, UniValue a, UniValue b) {
        a.pushKV("idempotency_key", std::string("conflict-") + method);
        b.pushKV("idempotency_key", std::string("conflict-") + method);
        BOOST_REQUIRE_MESSAGE(CallN02(cat, method, a, result, code, err), std::string(method) + ": " + err);
        BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
        UniValue conflicted;
        BOOST_CHECK_MESSAGE(!CallN02(cat, method, b, conflicted, code, err),
                            std::string(method) + " mutated again under the same idempotency_key");
        BOOST_CHECK(code == "IDEMPOTENCY_CONFLICT" || code == "REJECTED");
        BOOST_CHECK_EQUAL(conflicted["status"].get_str(), "REJECTED");
        BOOST_CHECK_EQUAL(conflicted["automatic_spend_atoms"].getInt<int>(), 0);
    };

    {
        UniValue a(UniValue::VOBJ);
        a.pushKV("max_slots", 2);
        UniValue b(UniValue::VOBJ);
        b.pushKV("max_slots", 9);
        roundtrip("setmodeluploadpolicy", a, b);
        BOOST_REQUIRE(CallN02(cat, "getmodeluploadinfo", UniValue(UniValue::VOBJ), result, code, err));
        BOOST_CHECK_EQUAL(result["max_slots"].getInt<int>(), 2);
    }
    {
        UniValue a = TinyBundleBody();
        UniValue b = TinyBundleBody();
        b.pushKV("note", "different-body");
        roundtrip("createbtxpackage", a, b);
        roundtrip("exportbtxbundle", a, b);
    }
    {
        UniValue a = TinyErasureBody();
        UniValue b = TinyErasureBody();
        b.pushKV("file_index", 1);
        roundtrip("preparemodelerasure", a, b);
        roundtrip("executemodelerasure", a, b);
    }
    {
        UniValue a(UniValue::VOBJ);
        a.pushKV("file_size_bytes", 1024);
        UniValue b(UniValue::VOBJ);
        b.pushKV("file_size_bytes", 2048);
        roundtrip("setbootstrapdistributor", a, b);
        roundtrip("planmodelstoragemigration", a, b);
        roundtrip("executemodelstoragemigration", a, b);
    }
    {
        UniValue a(UniValue::VOBJ);
        a.pushKV("piece_count", 2);
        UniValue b(UniValue::VOBJ);
        b.pushKV("piece_count", 8);
        roundtrip("setmodelswarmhealer", a, b);
    }
    {
        UniValue a(UniValue::VOBJ);
        a.pushKV("external_seed", false);
        UniValue b(UniValue::VOBJ);
        b.pushKV("external_seed", true);
        roundtrip("settorrentsourcepolicy", a, b);
    }
    {
        UniValue a(UniValue::VOBJ);
        a.pushKV("lan", true);
        UniValue b(UniValue::VOBJ);
        b.pushKV("lan", false);
        roundtrip("setmodeldiscoverypolicy", a, b);
    }
    {
        UniValue a(UniValue::VOBJ);
        a.pushKV("endpoint", "https://a.example");
        UniValue b(UniValue::VOBJ);
        b.pushKV("endpoint", "https://b.example");
        roundtrip("setcloudstorage", a, b);
        roundtrip("addmodelstorage", a, b);
        roundtrip("setmodelstoragepolicy", a, b);
    }
    {
        UniValue a(UniValue::VOBJ);
        a.pushKV("publisher_id", "pub-a");
        UniValue b(UniValue::VOBJ);
        b.pushKV("publisher_id", "pub-b");
        roundtrip("setmodelmirror", a, b);
    }
}

BOOST_AUTO_TEST_CASE(n02_costly_write_idempotency_caller_scoped)
{
    const fs::path tmp = m_path_root / "n02-idem-caller";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue result;
    std::string code, err;

    UniValue a(UniValue::VOBJ);
    a.pushKV("caller", "alice");
    a.pushKV("idempotency_key", "shared-key");
    a.pushKV("max_slots", 5);
    BOOST_REQUIRE(CallN02(cat, "setmodeluploadpolicy", a, result, code, err));

    UniValue b(UniValue::VOBJ);
    b.pushKV("caller", "bob");
    b.pushKV("idempotency_key", "shared-key");
    b.pushKV("max_slots", 6);
    BOOST_REQUIRE_MESSAGE(CallN02(cat, "setmodeluploadpolicy", b, result, code, err), err);
    BOOST_CHECK_EQUAL(result["max_slots"].getInt<int>(), 6);
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue a2 = a;
    a2.pushKV("max_slots", 7);
    BOOST_CHECK(!CallN02(cat, "setmodeluploadpolicy", a2, result, code, err));
    BOOST_CHECK_EQUAL(code, "IDEMPOTENCY_CONFLICT");
}

BOOST_AUTO_TEST_CASE(n02_read_rpcs_do_not_require_idempotency_key)
{
    const fs::path tmp = m_path_root / "n02-idem-reads";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE(CallN02(cat, "getmodeluploadinfo", UniValue(UniValue::VOBJ), result, code, err));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_REQUIRE(CallN02(cat, "getbootstrapstatus", UniValue(UniValue::VOBJ), result, code, err));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_REQUIRE(CallN02(cat, "getevaluatedtransport", UniValue(UniValue::VOBJ), result, code, err));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_REQUIRE(result.exists("live_r2_wan"));
    BOOST_CHECK(result["live_r2_wan"].get_str() != "PASS");
    BOOST_REQUIRE(CallN02(cat, "querymodelsummary", UniValue(UniValue::VOBJ), result, code, err));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
