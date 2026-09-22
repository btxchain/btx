// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// 0.34.9 registry independence: origins[] are disposable delivery mechanisms.
// btx:// / VerifiedManifest is the artifact. Monetary plane is not required to
// fetch and is not removed. Native BTX signatures stay; OMS/Sigstore/Cosign
// are extra evidence slots. OCI is an origin, not a replacement packaging silo.

#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/identity.h>
#include <modelnet/import_coordinator.h>
#include <modelnet/import_plan.h>
#include <modelnet/oci_modelpack.h>
#include <modelnet/provenance.h>
#include <modelnet/registry_resolver.h>
#include <modelnet/source_huggingface.h>
#include <modelnet/source_local.h>
#include <modelnet/source_registry.h>
#include <modelnet/store.h>
#include <modelnet/types.h>
#include <modelnet/verified_manifest.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <arpa/inet.h>
#include <fstream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_registry_independence_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> Bytes(const std::string& s)
{
    return std::vector<unsigned char>(s.begin(), s.end());
}

std::string PlanId(char fill)
{
    return std::string(96, fill);
}

std::vector<unsigned char> TinySafeTensors(unsigned char tag)
{
    const std::string json = "{\"__metadata__\":{\"t\":\"" + std::to_string(static_cast<int>(tag)) + "\"}}";
    std::vector<unsigned char> st(8 + json.size(), 0);
    const uint64_t n = json.size();
    for (int i = 0; i < 8; ++i) {
        st[static_cast<size_t>(i)] = static_cast<unsigned char>((n >> (8 * i)) & 0xff);
    }
    std::copy(json.begin(), json.end(), st.begin() + 8);
    return st;
}

modelnet::ImportPlan MultiPlan()
{
    UniValue j(UniValue::VOBJ);
    j.pushKV("plan_id", PlanId('9'));
    UniValue origins(UniValue::VARR);
    auto add = [&](const char* type, const char* loc, const char* snap, int pri) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("type", type);
        o.pushKV("locator", loc);
        o.pushKV("snapshot_token", snap);
        o.pushKV("priority", pri);
        origins.push_back(o);
    };
    add("huggingface", "https://huggingface.co/org/model", "rev-a", 0);
    add("modelscope", "https://www.modelscope.cn/models/org/model", "rev-b", 1);
    add("oci", "oci://ghcr.io/org/model", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 2);
    add("s3", "s3://bucket/key", "gen-1", 3);
    add("btx", "btx://pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25", "peer", 4);
    j.pushKV("origins", origins);
    UniValue files(UniValue::VARR);
    UniValue f(UniValue::VOBJ);
    f.pushKV("source_path", "model.safetensors");
    f.pushKV("destination_path", "model.safetensors");
    f.pushKV("size_bytes", 5);
    files.push_back(f);
    j.pushKV("files", files);
    UniValue ev(UniValue::VARR);
    UniValue btx(UniValue::VOBJ);
    btx.pushKV("kind", "btx_publisher");
    btx.pushKV("note", "native BTX publisher signature remains first-class");
    ev.push_back(btx);
    UniValue oms(UniValue::VOBJ);
    oms.pushKV("kind", "openssf_oms");
    oms.pushKV("locator", "oms://example");
    ev.push_back(oms);
    j.pushKV("provenance_evidence", ev);
    modelnet::ImportPlan plan;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::ParseImportPlan(j, plan, err), err);
    return plan;
}

} // namespace

BOOST_AUTO_TEST_CASE(resolver_maps_heterogeneous_native_sources)
{
    const std::vector<std::pair<std::string, std::string>> cases = {
        {"huggingface", "huggingface.co"},
        {"hf-mirror", "hf-mirror.com"},
        {"modelscope", "www.modelscope.cn"},
        {"wisemodel", "www.wisemodel.cn"},
        {"openxlab", "download.openxlab.org.cn"},
        {"modelers", "modelers.cn"},
        {"gitcode", "gitcode.com"},
        {"gitee", "ai.gitee.com"},
        {"openi", "openi.org.cn"},
    };
    for (const auto& [type, host] : cases) {
        modelnet::ResolvedRegistryUrl u;
        std::string err;
        BOOST_REQUIRE_MESSAGE(
            modelnet::ResolveRegistryFileUrl(type, "org/model", "rev1", "model.safetensors", u, err), err);
        BOOST_CHECK_EQUAL(u.host, host);
        BOOST_CHECK(u.url.find("https://") == 0);
        BOOST_CHECK(u.url.find("org/model") != std::string::npos || u.url.find("org%2Fmodel") != std::string::npos);
    }
    modelnet::ResolvedRegistryUrl oci;
    std::string err;
    BOOST_REQUIRE(modelnet::ResolveRegistryFileUrl(
        "oci", "oci://ghcr.io/org/model",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "weights.safetensors", oci, err));
    BOOST_CHECK_EQUAL(oci.host, "ghcr.io");
    BOOST_CHECK(oci.url.find("/v2/org/model/blobs/sha256:") != std::string::npos);
    const auto types = modelnet::KnownRegistryOriginTypes();
    BOOST_CHECK(std::find(types.begin(), types.end(), "oci") != types.end());
    BOOST_CHECK(std::find(types.begin(), types.end(), "modelscope") != types.end());
}

BOOST_AUTO_TEST_CASE(v1_source_synthesizes_origins_and_wallet_is_never_required)
{
    UniValue j(UniValue::VOBJ);
    j.pushKV("plan_id", PlanId('v'));
    UniValue src(UniValue::VOBJ);
    src.pushKV("kind", "HUGGINGFACE");
    src.pushKV("locator", "https://huggingface.co/org/model");
    src.pushKV("snapshot_token", "abc");
    j.pushKV("source", src);
    modelnet::ImportPlan plan;
    std::string err;
    BOOST_REQUIRE(modelnet::ParseImportPlan(j, plan, err));
    BOOST_REQUIRE_EQUAL(plan.origins.size(), 1U);
    BOOST_CHECK_EQUAL(plan.origins[0].type, "huggingface");
    BOOST_CHECK(!plan.wallet_required);
    const UniValue dumped = modelnet::ImportPlanJson(plan);
    BOOST_CHECK(!dumped["wallet_required"].get_bool());
    BOOST_CHECK(!dumped["publisher_must_republish"].get_bool());
    BOOST_CHECK_EQUAL(dumped["min_independent_origins"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(plan.min_independent_origins, 1);
}

BOOST_AUTO_TEST_CASE(unknown_provenance_kind_rejected_btx_publisher_kept)
{
    UniValue j(UniValue::VOBJ);
    j.pushKV("plan_id", PlanId('p'));
    UniValue src(UniValue::VOBJ);
    src.pushKV("kind", "LOCAL");
    src.pushKV("locator", "/tmp/x");
    src.pushKV("snapshot_token", "t");
    j.pushKV("source", src);
    UniValue ev(UniValue::VARR);
    UniValue bad(UniValue::VOBJ);
    bad.pushKV("kind", "erase_btx_money");
    ev.push_back(bad);
    j.pushKV("provenance_evidence", ev);
    modelnet::ImportPlan plan;
    std::string err;
    BOOST_CHECK(!modelnet::ParseImportPlan(j, plan, err));
    BOOST_CHECK_EQUAL(err, "provenance kind");
}

BOOST_AUTO_TEST_CASE(piece_routing_skips_failed_origin_then_hash_binds)
{
    modelnet::ClearRegistryInjections();
    auto plan = MultiPlan();
    BOOST_CHECK_EQUAL(plan.provenance_evidence.size(), 2U);
    BOOST_CHECK_EQUAL(plan.provenance_evidence[0].kind, "btx_publisher");
    BOOST_CHECK_EQUAL(plan.provenance_evidence[1].kind, "openssf_oms");

    modelnet::InjectRegistryOriginError("huggingface");
    modelnet::InjectRegistryOriginBytes("modelscope", Bytes("weigh"));

    const fs::path root = m_path_root / "reg-route";
    modelnet::ImportCoordinator coord{plan, root};
    std::string err;
    BOOST_REQUIRE(coord.PrepareStaging(err));
    auto src = modelnet::MakePlanByteSource(plan, err);
    BOOST_REQUIRE(src);
    BOOST_CHECK_EQUAL(src->Kind(), "MULTI_ORIGIN");
    BOOST_REQUIRE(coord.StageFromSource(*src, coord.AcceptedFiles()[0], 5, err));

    const auto idj = coord.StatusJson();
    BOOST_CHECK(idj["identity"]["what"].get_str().find("btx://") != std::string::npos);
    BOOST_CHECK(idj["identity"]["who"].get_str().find("BTX publisher") != std::string::npos);
    BOOST_CHECK(idj["identity"]["money"].get_str().find("monetary plane stays") != std::string::npos);
    BOOST_CHECK(idj["identity"]["how"].get_str().find("admission ticket") != std::string::npos);
    BOOST_CHECK(idj["identity"]["evidence"].get_str().find("not the sole CA") != std::string::npos);
    BOOST_REQUIRE_EQUAL(idj["piece_origins"].getValues().size(), 1U);
    BOOST_CHECK_EQUAL(idj["piece_origins"][0].get_str(), "modelscope");
    BOOST_CHECK_EQUAL(idj["independent_origin_count"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(idj["min_independent_origins"].getInt<int>(), 1);
    BOOST_CHECK(!idj["below_min_independent_origins"].get_bool());
    BOOST_REQUIRE_EQUAL(idj["provenance_evidence"].getValues().size(), 2U);
    BOOST_CHECK_EQUAL(idj["provenance_evidence"][0]["kind"].get_str(), "btx_publisher");
    BOOST_CHECK_EQUAL(idj["provenance_evidence"][0]["role"].get_str(), "native_btx_publisher");
    BOOST_CHECK(!idj["provenance_evidence"][0]["verified_here"].get_bool());
    BOOST_CHECK_EQUAL(idj["provenance_evidence"][1]["kind"].get_str(), "openssf_oms");
    BOOST_CHECK_EQUAL(idj["provenance_evidence"][1]["role"].get_str(), "additional_evidence");
    BOOST_CHECK(!idj["provenance_evidence"][1]["verified_here"].get_bool());
    BOOST_CHECK_EQUAL(idj["capability"]["readiness_target"].get_str(), "VERIFIED_FILES");
    BOOST_CHECK(!idj["capability"]["inference"].get_bool());
    BOOST_CHECK(!idj["capability"]["funded_wallet"].get_bool());
    BOOST_CHECK_EQUAL(idj["capability"]["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!idj["wallet_required"].get_bool());

    modelnet::VerifiedManifest vm;
    BOOST_REQUIRE(modelnet::MakeVerifiedManifestFromStaged(coord.StagingDir(), {"model.safetensors"}, vm, err));
    BOOST_REQUIRE(coord.AcceptVerifiedManifest(vm, err));
    BOOST_CHECK(coord.Phase() == modelnet::ImportPhase::PUBLISH_READY);
    BOOST_CHECK(coord.HasFinalModelId());

    auto* multi = dynamic_cast<modelnet::MultiOriginByteSource*>(src.get());
    BOOST_REQUIRE(multi);
    BOOST_CHECK_EQUAL(multi->LastOriginType(), "modelscope");
    modelnet::ClearRegistryInjections();
}

BOOST_AUTO_TEST_CASE(wrong_bytes_from_first_origin_are_conflict_not_rename)
{
    modelnet::ClearRegistryInjections();
    auto plan = MultiPlan();
    // sha384 of "weigh"
    modelnet::VerifiedManifest tmp;
    {
        const fs::path tdir = m_path_root / "reg-hash-tmp";
        fs::create_directories(tdir);
        std::ofstream out(tdir / "model.safetensors", std::ios::binary);
        out << "weigh";
        out.close();
        std::string err;
        BOOST_REQUIRE(modelnet::MakeVerifiedManifestFromStaged(tdir, {"model.safetensors"}, tmp, err));
        plan.files[0].sha384_hex = tmp.core.files[0].sha384.Hex();
        plan.files[0].size_bytes = 5;
    }
    modelnet::InjectRegistryOriginBytes("huggingface", Bytes("XXXXX")); // same length, different bytes
    modelnet::InjectRegistryOriginBytes("modelscope", Bytes("weigh"));
    std::string err;
    auto src = modelnet::MakePlanByteSource(plan, err);
    BOOST_REQUIRE(src);
    src->SelectFile("model.safetensors", plan.files[0].sha384_hex);
    src->BindFileIdentity(plan.files[0].size_bytes, plan.files[0].piece_sha384_hex);
    std::vector<unsigned char> got;
    BOOST_REQUIRE(src->Read({0, 5}, got, 5, err));
    BOOST_CHECK_EQUAL(std::string(got.begin(), got.end()), "weigh");
    auto* multi = dynamic_cast<modelnet::MultiOriginByteSource*>(src.get());
    BOOST_REQUIRE(multi);
    BOOST_CHECK_EQUAL(multi->LastOriginType(), "modelscope");
    BOOST_REQUIRE(!multi->Conflicts().empty());
    modelnet::ClearRegistryInjections();
}

BOOST_AUTO_TEST_CASE(whole_file_hash_is_not_applied_to_the_first_piece)
{
    modelnet::ClearRegistryInjections();
    auto plan = MultiPlan();
    {
        const fs::path tdir = m_path_root / "reg-partial-tmp";
        fs::create_directories(tdir);
        std::ofstream out(tdir / "model.safetensors", std::ios::binary);
        out << "ABCDEFGH";
        out.close();
        modelnet::VerifiedManifest tmp;
        std::string herr;
        BOOST_REQUIRE(modelnet::MakeVerifiedManifestFromStaged(tdir, {"model.safetensors"}, tmp, herr));
        plan.files[0].sha384_hex = tmp.core.files[0].sha384.Hex();
        plan.files[0].size_bytes = 8;
    }
    modelnet::InjectRegistryOriginBytes("huggingface", Bytes("ABCDEFGH"));
    modelnet::InjectRegistryOriginBytes("modelscope", Bytes("XXXXXXXX"));
    std::string err;
    auto src = modelnet::MakePlanByteSource(plan, err);
    BOOST_REQUIRE(src);
    src->SelectFile("model.safetensors", plan.files[0].sha384_hex);
    src->BindFileIdentity(8, {});
    std::vector<unsigned char> got;
    BOOST_REQUIRE(src->Read({0, 4}, got, 4, err));
    BOOST_CHECK_EQUAL(std::string(got.begin(), got.end()), "ABCD");
    auto* multi = dynamic_cast<modelnet::MultiOriginByteSource*>(src.get());
    BOOST_REQUIRE(multi);
    BOOST_CHECK_EQUAL(multi->LastOriginType(), "huggingface");
    modelnet::ClearRegistryInjections();
}

BOOST_AUTO_TEST_CASE(piece_zero_from_hf_piece_one_from_modelscope)
{
    modelnet::ClearRegistryInjections();
    const uint64_t psz = modelnet::PIECE_SIZE;
    const uint64_t sz = psz + 8;
    modelnet::SetRegistryGetForTests([psz](const std::string& url, uint64_t offset, uint64_t length,
                                           std::vector<unsigned char>& out, std::string& err) {
        const bool hf = url.find("huggingface.co") != std::string::npos;
        const bool piece1 = offset >= psz;
        if (!piece1 && hf) out.assign(length, static_cast<unsigned char>('A'));
        else if (!piece1 && !hf) out.assign(length, static_cast<unsigned char>('B'));
        else if (piece1 && hf) out.assign(length, static_cast<unsigned char>('x'));
        else out.assign(length, static_cast<unsigned char>('Y'));
        err.clear();
        return true;
    });
    std::vector<unsigned char> p0(psz, static_cast<unsigned char>('A'));
    std::vector<unsigned char> p1(8, static_cast<unsigned char>('Y'));
    const std::vector<std::string> leaves = {
        modelnet::ChunkLeaf(0, Span<const unsigned char>{p0.data(), p0.size()}).Hex(),
        modelnet::ChunkLeaf(1, Span<const unsigned char>{p1.data(), p1.size()}).Hex(),
    };
    auto plan = MultiPlan();
    std::string err;
    auto src = modelnet::MakePlanByteSource(plan, err);
    BOOST_REQUIRE(src);
    src->SelectFile("model.safetensors", {});
    src->BindFileIdentity(sz, leaves);
    std::vector<unsigned char> got;
    BOOST_REQUIRE_MESSAGE(src->Read({0, psz}, got, psz, err), err);
    BOOST_REQUIRE_EQUAL(got.size(), psz);
    BOOST_CHECK_EQUAL(got.front(), static_cast<unsigned char>('A'));
    auto* multi = dynamic_cast<modelnet::MultiOriginByteSource*>(src.get());
    BOOST_REQUIRE(multi);
    BOOST_CHECK_EQUAL(multi->LastOriginType(), "huggingface");
    BOOST_REQUIRE_MESSAGE(src->Read({psz, 8}, got, 8, err), err);
    BOOST_CHECK_EQUAL(std::string(got.begin(), got.end()), "YYYYYYYY");
    BOOST_CHECK_EQUAL(multi->LastOriginType(), "modelscope");
    BOOST_REQUIRE_EQUAL(multi->PieceOrigins().size(), 2U);
    BOOST_CHECK_EQUAL(multi->PieceOrigins()[0], "huggingface");
    BOOST_CHECK_EQUAL(multi->PieceOrigins()[1], "modelscope");
    BOOST_CHECK_EQUAL(multi->IndependentOriginCount(), 2);
    modelnet::ClearRegistryInjections();
}

BOOST_AUTO_TEST_CASE(oci_attestation_is_extra_evidence_not_identity)
{
    UniValue j(UniValue::VOBJ);
    j.pushKV("plan_id", PlanId('o'));
    UniValue src(UniValue::VOBJ);
    src.pushKV("kind", "OCI");
    src.pushKV("locator", "oci://ghcr.io/org/model");
    src.pushKV("snapshot_token", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    j.pushKV("source", src);
    UniValue ev(UniValue::VARR);
    UniValue btx(UniValue::VOBJ);
    btx.pushKV("kind", "btx_publisher");
    ev.push_back(btx);
    UniValue oci(UniValue::VOBJ);
    oci.pushKV("kind", "oci_attestation");
    oci.pushKV("locator", "oci://ghcr.io/org/model");
    ev.push_back(oci);
    j.pushKV("provenance_evidence", ev);
    modelnet::ImportPlan plan;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::ParseImportPlan(j, plan, err), err);
    BOOST_CHECK_EQUAL(plan.provenance_evidence.size(), 2U);
    BOOST_CHECK_EQUAL(plan.provenance_evidence[1].kind, "oci_attestation");
    BOOST_CHECK(!plan.wallet_required);
}

BOOST_AUTO_TEST_CASE(accept_without_staged_bytes_fails_r3_2)
{
    const fs::path root = m_path_root / "r32-closed";
    auto plan = MultiPlan();
    modelnet::ImportCoordinator coord{plan, root};
    std::string err;
    BOOST_REQUIRE(coord.PrepareStaging(err));
    modelnet::VerifiedManifest vm;
    vm.model_id.data.fill(0xab);
    vm.artifact_id.data.fill(0xcd);
    BOOST_CHECK(!coord.AcceptVerifiedManifest(vm, err));
    BOOST_CHECK_EQUAL(err, "verified manifest files");
    BOOST_CHECK(coord.Phase() == modelnet::ImportPhase::STAGING);
}

BOOST_AUTO_TEST_CASE(s3_and_btx_and_oci_adapters_exist)
{
    std::string err;
    modelnet::ImportPlan p;
    p.plan_id = PlanId('s');
    p.kind = modelnet::ImportSourceKind::S3;
    p.locator = "s3://bucket/key";
    p.snapshot_token = "g";
    auto src = modelnet::MakePlanByteSource(p, err);
    BOOST_REQUIRE(src);
    BOOST_CHECK_EQUAL(src->Kind(), "S3");
    BOOST_REQUIRE(src->Pin(err));

    p.kind = modelnet::ImportSourceKind::BTX;
    p.locator = "btx://pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25";
    src = modelnet::MakePlanByteSource(p, err);
    BOOST_REQUIRE(src);
    BOOST_CHECK_EQUAL(src->Kind(), "BTX");
    BOOST_REQUIRE(src->Pin(err));

    p.kind = modelnet::ImportSourceKind::OCI;
    p.locator = "oci://ghcr.io/org/model";
    p.snapshot_token = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    src = modelnet::MakePlanByteSource(p, err);
    BOOST_REQUIRE(src);
}

BOOST_AUTO_TEST_CASE(hf_live_still_fail_closed_without_inject_or_env)
{
    modelnet::HuggingFaceByteSource src{"https://huggingface.co/org/model", "rev"};
    std::string err;
    BOOST_REQUIRE(src.Pin(err));
    std::vector<unsigned char> out;
    BOOST_CHECK(!src.Read({0, 1}, out, 8, err));
    BOOST_CHECK_EQUAL(err, "not wired to live network");

    modelnet::ImportPlan p;
    p.plan_id = PlanId('h');
    p.kind = modelnet::ImportSourceKind::HUGGINGFACE;
    p.locator = "https://huggingface.co/org/model";
    p.snapshot_token = "rev";
    p.live_wan = false;
    auto live = modelnet::MakePlanByteSource(p, err);
    BOOST_REQUIRE(live);
    BOOST_CHECK_EQUAL(live->Kind(), "HUGGINGFACE");
    BOOST_REQUIRE(live->Pin(err));
    BOOST_CHECK(!live->Read({0, 1}, out, 8, err));
    BOOST_CHECK_EQUAL(err, "not wired to live network");
}

BOOST_AUTO_TEST_CASE(executemodelimport_routes_modelscope_after_hf_fail)
{
    modelnet::ClearRegistryInjections();
    modelnet::InjectRegistryOriginError("huggingface");
    modelnet::InjectRegistryOriginBytes("modelscope", Bytes("weigh"));
    const fs::path tmp = m_path_root / "reg-rpc";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue planj = modelnet::ImportPlanJson(MultiPlan());
    planj.pushKV("idempotency_key", "reg-indep-ms-failover");
    UniValue params(UniValue::VARR);
    params.push_back(planj);
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "executemodelimport");
    req.pushKV("params", params);
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, req, result, code, err), err);
    BOOST_CHECK(result["imported"].get_bool());
    BOOST_CHECK_EQUAL(result["phase"].get_str(), "PUBLISH_READY");
    BOOST_CHECK(!result["wallet_required"].get_bool());
    BOOST_CHECK(!result["publisher_must_republish"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(result["identity"]["who"].get_str().find("BTX publisher") != std::string::npos);
    BOOST_CHECK(result["identity"]["money"].get_str().find("monetary plane stays") != std::string::npos);
    BOOST_CHECK(result["identity"]["how"].get_str().find("admission ticket") != std::string::npos);
    BOOST_CHECK_EQUAL(result["independent_origin_count"].getInt<int>(), 1);
    BOOST_REQUIRE_EQUAL(result["piece_origins"].getValues().size(), 1U);
    BOOST_CHECK_EQUAL(result["piece_origins"][0].get_str(), "modelscope");
    BOOST_CHECK_EQUAL(result["capability"]["readiness_target"].get_str(), "VERIFIED_FILES");
    BOOST_REQUIRE_EQUAL(result["provenance_evidence"].getValues().size(), 2U);
    BOOST_CHECK(!result["provenance_evidence"][1]["verified_here"].get_bool());
    modelnet::ClearRegistryInjections();
}

BOOST_AUTO_TEST_CASE(min_independent_origins_is_observation_not_admission)
{
    modelnet::ClearRegistryInjections();
    auto plan = MultiPlan();
    plan.min_independent_origins = 2;
    modelnet::InjectRegistryOriginError("huggingface");
    modelnet::InjectRegistryOriginBytes("modelscope", Bytes("weigh"));
    const fs::path root = m_path_root / "reg-min-origins";
    modelnet::ImportCoordinator coord{plan, root};
    std::string err;
    BOOST_REQUIRE(coord.PrepareStaging(err));
    auto src = modelnet::MakePlanByteSource(plan, err);
    BOOST_REQUIRE(src);
    BOOST_REQUIRE(coord.StageFromSource(*src, coord.AcceptedFiles()[0], 5, err));
    const auto st = coord.StatusJson();
    BOOST_CHECK_EQUAL(st["independent_origin_count"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(st["min_independent_origins"].getInt<int>(), 2);
    BOOST_CHECK(st["below_min_independent_origins"].get_bool());
    BOOST_CHECK_EQUAL(coord.Phase(), modelnet::ImportPhase::STAGING);
    BOOST_CHECK(!st["wallet_required"].get_bool());
    modelnet::VerifiedManifest vm;
    BOOST_REQUIRE(modelnet::MakeVerifiedManifestFromStaged(coord.StagingDir(), {"model.safetensors"}, vm, err));
    BOOST_REQUIRE(coord.AcceptVerifiedManifest(vm, err));
    BOOST_CHECK_EQUAL(coord.Phase(), modelnet::ImportPhase::PUBLISH_READY);
    BOOST_CHECK(coord.StatusJson()["below_min_independent_origins"].get_bool());
    modelnet::ClearRegistryInjections();
}

BOOST_AUTO_TEST_CASE(min_independent_origins_below_one_is_rejected)
{
    UniValue j(UniValue::VOBJ);
    j.pushKV("plan_id", PlanId('m'));
    UniValue src(UniValue::VOBJ);
    src.pushKV("kind", "LOCAL");
    src.pushKV("locator", "/tmp/x");
    src.pushKV("snapshot_token", "t");
    j.pushKV("source", src);
    j.pushKV("min_independent_origins", 0);
    modelnet::ImportPlan plan;
    std::string err;
    BOOST_CHECK(!modelnet::ParseImportPlan(j, plan, err));
    BOOST_CHECK_EQUAL(err, "min_independent_origins");
}

BOOST_AUTO_TEST_CASE(leafless_multi_origin_does_not_splice_pieces)
{
    modelnet::ClearRegistryInjections();
    const uint64_t psz = modelnet::PIECE_SIZE;
    const uint64_t sz = psz + 8;
    modelnet::SetRegistryGetForTests([psz](const std::string& url, uint64_t offset, uint64_t length,
                                           std::vector<unsigned char>& out, std::string& err) {
        const bool hf = url.find("huggingface.co") != std::string::npos;
        if (offset < psz && hf) {
            out.assign(length, static_cast<unsigned char>('A'));
            err.clear();
            return true;
        }
        if (offset >= psz && hf) {
            err = "origin unavailable";
            return false;
        }
        out.assign(length, static_cast<unsigned char>('Y'));
        err.clear();
        return true;
    });
    auto plan = MultiPlan();
    plan.files[0].size_bytes = sz;
    plan.files[0].piece_sha384_hex.clear();
    plan.files[0].sha384_hex.clear();
    const fs::path root = m_path_root / "reg-leafless-mix";
    modelnet::ImportCoordinator coord{plan, root};
    std::string err;
    BOOST_REQUIRE(coord.PrepareStaging(err));
    auto src = modelnet::MakePlanByteSource(plan, err);
    BOOST_REQUIRE(src);
    BOOST_CHECK(!coord.StageFromSource(*src, coord.AcceptedFiles()[0], sz, err));
    BOOST_CHECK(err == "origin unavailable" || err == "UNBOUND_ORIGIN_MIX");
    auto* multi = dynamic_cast<modelnet::MultiOriginByteSource*>(src.get());
    BOOST_REQUIRE(multi);
    BOOST_CHECK(multi->IndependentOriginCount() != 2);
    BOOST_CHECK(!multi->OriginsMixedWithoutIdentity() || multi->IndependentOriginCount() == 0);
    modelnet::ClearRegistryInjections();
}

BOOST_AUTO_TEST_CASE(declared_whole_file_sha384_is_enforced_across_pieces)
{
    modelnet::ClearRegistryInjections();
    const uint64_t psz = modelnet::PIECE_SIZE;
    const uint64_t sz = psz + 8;
    std::vector<unsigned char> want(sz, static_cast<unsigned char>('A'));
    const fs::path tdir = m_path_root / "reg-sha-want";
    fs::create_directories(tdir);
    {
        std::ofstream out(tdir / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(want.data()), static_cast<std::streamsize>(want.size()));
    }
    modelnet::VerifiedManifest tmp;
    std::string err;
    BOOST_REQUIRE(modelnet::MakeVerifiedManifestFromStaged(tdir, {"model.safetensors"}, tmp, err));
    modelnet::SetRegistryGetForTests([](const std::string&, uint64_t, uint64_t length,
                                        std::vector<unsigned char>& out, std::string& e) {
        out.assign(length, static_cast<unsigned char>('Y'));
        e.clear();
        return true;
    });
    auto plan = MultiPlan();
    plan.files[0].size_bytes = sz;
    plan.files[0].sha384_hex = tmp.core.files[0].sha384.Hex();
    plan.files[0].piece_sha384_hex.clear();
    const fs::path root = m_path_root / "reg-sha-pieces";
    modelnet::ImportCoordinator coord{plan, root};
    BOOST_REQUIRE(coord.PrepareStaging(err));
    auto src = modelnet::MakePlanByteSource(plan, err);
    BOOST_REQUIRE(src);
    BOOST_CHECK(!coord.StageFromSource(*src, coord.AcceptedFiles()[0], sz, err));
    BOOST_CHECK_EQUAL(err, "HASH_MISMATCH");
    modelnet::ClearRegistryInjections();
}

BOOST_AUTO_TEST_CASE(https_range_requires_206_and_rejects_chunked)
{
    std::string err;
    modelnet::RegistryHttpResponse resp;
    const std::string two_hundred = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nABCDEFGH";
    BOOST_REQUIRE(modelnet::ParseRegistryHttpResponse(two_hundred, resp, err));
    std::vector<unsigned char> out;
    BOOST_CHECK(!modelnet::RegistryHttpBodyAllowed(resp, /*range_requested=*/true, 4, 4, out, err));
    BOOST_CHECK_EQUAL(err, "range not satisfied");
    // HF resolve-cache: Range on a 8-byte object yields 200 + Content-Length 8.
    BOOST_REQUIRE(modelnet::ParseRegistryHttpResponse(two_hundred, resp, err));
    BOOST_REQUIRE(modelnet::RegistryHttpBodyAllowed(resp, /*range_requested=*/true, 0, 8, out, err));
    BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), "ABCDEFGH");
    // A 200 whose body is not the requested extent is still not a piece.
    BOOST_REQUIRE(modelnet::ParseRegistryHttpResponse(two_hundred, resp, err));
    BOOST_CHECK(!modelnet::RegistryHttpBodyAllowed(resp, /*range_requested=*/true, 0, 4, out, err));
    BOOST_CHECK_EQUAL(err, "range not satisfied");

    const std::string chunked = "HTTP/1.1 206 Partial Content\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\nABCD";
    BOOST_REQUIRE(modelnet::ParseRegistryHttpResponse(chunked, resp, err));
    BOOST_CHECK(resp.chunked);
    BOOST_CHECK(!modelnet::RegistryHttpBodyAllowed(resp, true, 0, 4, out, err));
    BOOST_CHECK_EQUAL(err, "chunked encoding forbidden");

    const std::string no_len = "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-3/8\r\n\r\nABCD";
    BOOST_REQUIRE(modelnet::ParseRegistryHttpResponse(no_len, resp, err));
    BOOST_CHECK(!modelnet::RegistryHttpBodyAllowed(resp, true, 0, 4, out, err));
    BOOST_CHECK_EQUAL(err, "content-length required");

    const std::string ok = "HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nContent-Range: bytes 4-7/8\r\n\r\nEFGH";
    BOOST_REQUIRE(modelnet::ParseRegistryHttpResponse(ok, resp, err));
    BOOST_REQUIRE(modelnet::RegistryHttpBodyAllowed(resp, true, 4, 4, out, err));
    BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), "EFGH");

    const std::string redir =
        "HTTP/1.1 302 Found\r\nLocation: https://us.aws.cdn.hf.co/xet/weights\r\nContent-Length: 0\r\n\r\n";
    BOOST_REQUIRE(modelnet::ParseRegistryHttpResponse(redir, resp, err));
    BOOST_CHECK(modelnet::RegistryHttpIsRedirect(resp));
    BOOST_CHECK_EQUAL(resp.location, "https://us.aws.cdn.hf.co/xet/weights");
    BOOST_CHECK(!modelnet::RegistryHttpBodyAllowed(resp, true, 0, 4, out, err));
    BOOST_CHECK_EQUAL(err, "redirects forbidden");

    std::string next;
    BOOST_REQUIRE(modelnet::ResolveHttpsRedirect(
        "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/config.json", "/api/resolve-cache/abc",
        next, err));
    BOOST_CHECK_EQUAL(next, "https://huggingface.co/api/resolve-cache/abc");
    BOOST_REQUIRE(modelnet::ResolveHttpsRedirect("https://hf-mirror.com/org/model/resolve/main/w.gguf",
                                                 "https://huggingface.co/org/model/resolve/main/w.gguf", next, err));
    BOOST_CHECK_EQUAL(next, "https://huggingface.co/org/model/resolve/main/w.gguf");
    BOOST_REQUIRE(modelnet::ResolveHttpsRedirect("https://huggingface.co/org/model", "//cdn.hf.co/blob", next, err));
    BOOST_CHECK_EQUAL(next, "https://cdn.hf.co/blob");
    BOOST_CHECK(!modelnet::ResolveHttpsRedirect("https://huggingface.co/org/model", "http://127.0.0.1/x", next, err));
    BOOST_CHECK_EQUAL(err, "https only");
    std::string ssrf;
    BOOST_REQUIRE(modelnet::ResolveHttpsRedirect("https://huggingface.co/org/model", "https://127.0.0.1/x", next, err));
    BOOST_CHECK(!modelnet::HuggingFaceLocatorAllowed(next, ssrf));
    BOOST_CHECK_EQUAL(ssrf, "ssrf");
}

BOOST_AUTO_TEST_CASE(multi_origin_reports_each_origin_error)
{
    modelnet::ClearRegistryInjections();
    modelnet::InjectRegistryOriginError("huggingface");
    modelnet::InjectRegistryOriginError("modelscope");
    auto plan = MultiPlan();
    plan.files[0].size_bytes = 5;
    const fs::path root = m_path_root / "reg-origin-errors";
    modelnet::ImportCoordinator coord{plan, root};
    std::string err;
    BOOST_REQUIRE(coord.PrepareStaging(err));
    auto src = modelnet::MakePlanByteSource(plan, err);
    BOOST_REQUIRE(src);
    BOOST_CHECK(!coord.StageFromSource(*src, coord.AcceptedFiles()[0], 5, err));
    const UniValue st = coord.StatusJson();
    BOOST_REQUIRE(st.exists("origin_errors"));
    BOOST_CHECK(st["origin_errors"].getValues().size() >= 2);
    bool saw_hf = false, saw_ms = false;
    for (const auto& row : st["origin_errors"].getValues()) {
        if (row["type"].get_str() == "huggingface") saw_hf = true;
        if (row["type"].get_str() == "modelscope") saw_ms = true;
    }
    BOOST_CHECK(saw_hf);
    BOOST_CHECK(saw_ms);
    modelnet::ClearRegistryInjections();
}

BOOST_AUTO_TEST_CASE(local_plan_without_files_synthesizes_from_locator)
{
    const fs::path tmp = m_path_root / "reg-local-synth";
    fs::create_directories(tmp / "src");
    const auto st = TinySafeTensors(0x61);
    {
        std::ofstream out(tmp / "src" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::ImportPlan plan;
    plan.plan_id = PlanId('S');
    plan.kind = modelnet::ImportSourceKind::LOCAL;
    plan.locator = fs::PathToString(tmp / "src");
    plan.snapshot_token = "local";
    modelnet::ImportCoordinator coord{plan, tmp / "jobs"};
    std::string err;
    BOOST_REQUIRE_MESSAGE(coord.PrepareStaging(err), err);
    BOOST_REQUIRE_EQUAL(coord.AcceptedFiles().size(), 1U);
    BOOST_CHECK_EQUAL(coord.AcceptedFiles()[0].destination_path, "model.safetensors");
}

BOOST_AUTO_TEST_CASE(local_import_records_piece_origin)
{
    const fs::path tmp = m_path_root / "reg-local-origin";
    fs::create_directories(tmp / "src");
    const auto st = TinySafeTensors(0x62);
    {
        std::ofstream out(tmp / "src" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue planj(UniValue::VOBJ);
    planj.pushKV("plan_id", PlanId('L'));
    UniValue src(UniValue::VOBJ);
    src.pushKV("type", "local");
    src.pushKV("locator", fs::PathToString(tmp / "src"));
    src.pushKV("snapshot_token", "local");
    planj.pushKV("source", src);
    planj.pushKV("idempotency_key", "local-origin-1");
    UniValue params(UniValue::VARR);
    params.push_back(planj);
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "executemodelimport");
    req.pushKV("params", params);
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, req, result, code, err), err);
    BOOST_CHECK(result["imported"].get_bool());
    BOOST_REQUIRE(result.exists("piece_origins"));
    BOOST_CHECK_GE(result["piece_origins"].getValues().size(), 1U);
    BOOST_CHECK_EQUAL(result["piece_origins"][0].get_str(), "local");
    BOOST_CHECK_GE(result["independent_origin_count"].getInt<int>(), 1);
    BOOST_CHECK(!result["wallet_required"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);

    req.pushKV("id", 2);
    planj.pushKV("idempotency_key", "local-origin-2");
    planj.pushKV("plan_id", PlanId('M'));
    params = UniValue(UniValue::VARR);
    params.push_back(planj);
    req.pushKV("params", params);
    UniValue again;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, req, again, code, err), err + " " + code);
    BOOST_CHECK(again["imported"].get_bool() || again["has_verified_manifest"].get_bool());
    BOOST_CHECK(again.exists("model_id"));
}

BOOST_AUTO_TEST_CASE(resolved_private_addresses_are_not_global_unicast)
{
    sockaddr_in v4{};
    v4.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &v4.sin_addr);
    BOOST_CHECK(!modelnet::AddressIsGlobalUnicast(reinterpret_cast<sockaddr*>(&v4), sizeof(v4)));
    inet_pton(AF_INET, "10.1.2.3", &v4.sin_addr);
    BOOST_CHECK(!modelnet::AddressIsGlobalUnicast(reinterpret_cast<sockaddr*>(&v4), sizeof(v4)));
    inet_pton(AF_INET, "192.168.1.1", &v4.sin_addr);
    BOOST_CHECK(!modelnet::AddressIsGlobalUnicast(reinterpret_cast<sockaddr*>(&v4), sizeof(v4)));
    inet_pton(AF_INET, "169.254.1.1", &v4.sin_addr);
    BOOST_CHECK(!modelnet::AddressIsGlobalUnicast(reinterpret_cast<sockaddr*>(&v4), sizeof(v4)));
    inet_pton(AF_INET, "100.64.0.1", &v4.sin_addr);
    BOOST_CHECK(!modelnet::AddressIsGlobalUnicast(reinterpret_cast<sockaddr*>(&v4), sizeof(v4)));
    inet_pton(AF_INET, "1.1.1.1", &v4.sin_addr);
    BOOST_CHECK(modelnet::AddressIsGlobalUnicast(reinterpret_cast<sockaddr*>(&v4), sizeof(v4)));

    sockaddr_in6 v6{};
    v6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::1", &v6.sin6_addr);
    BOOST_CHECK(!modelnet::AddressIsGlobalUnicast(reinterpret_cast<sockaddr*>(&v6), sizeof(v6)));
    inet_pton(AF_INET6, "fc00::1", &v6.sin6_addr);
    BOOST_CHECK(!modelnet::AddressIsGlobalUnicast(reinterpret_cast<sockaddr*>(&v6), sizeof(v6)));
    inet_pton(AF_INET6, "2001:4860:4860::8888", &v6.sin6_addr);
    BOOST_CHECK(modelnet::AddressIsGlobalUnicast(reinterpret_cast<sockaddr*>(&v6), sizeof(v6)));
}

BOOST_AUTO_TEST_CASE(btx_publisher_evidence_verifies_locally_without_wan)
{
    std::vector<unsigned char> pk, sk, sig;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    const std::string payload = "btx-provenance-v1";
    BOOST_REQUIRE(modelnet::SignMlDsa44(sk, Span<const unsigned char>{reinterpret_cast<const unsigned char*>(payload.data()), payload.size()}, sig, err));
    modelnet::ProvenanceEvidence pe;
    pe.kind = "btx_publisher";
    pe.payload = payload;
    pe.algorithm = "ML-DSA-44";
    pe.public_key_hex = HexStr(pk);
    pe.signature_hex = HexStr(sig);
    modelnet::ProvenanceVerifyResult vr;
    BOOST_REQUIRE(modelnet::VerifyProvenanceEvidence(pe, vr));
    BOOST_CHECK(vr.verified_here);
    pe.payload = "tampered";
    BOOST_REQUIRE(modelnet::VerifyProvenanceEvidence(pe, vr));
    BOOST_CHECK(!vr.verified_here);
    BOOST_CHECK_EQUAL(vr.error, "SIGNATURE_INVALID");
}

BOOST_AUTO_TEST_CASE(modelpack_config_is_an_origin_layout_not_identity)
{
    UniValue cfg(UniValue::VOBJ);
    cfg.pushKV("schemaVersion", "1.0.0");
    cfg.pushKV("mediaType", modelnet::MODELPACK_MEDIA_TYPE);
    UniValue model(UniValue::VOBJ);
    model.pushKV("path", "model.safetensors");
    UniValue parts(UniValue::VARR);
    UniValue part(UniValue::VOBJ);
    part.pushKV("path", "model.safetensors");
    part.pushKV("size", 5);
    part.pushKV("digest", "sha384:" + std::string(96, 'a'));
    parts.push_back(part);
    model.pushKV("parts", parts);
    cfg.pushKV("model", model);
    UniValue origin(UniValue::VOBJ);
    origin.pushKV("registry", "ghcr.io");
    origin.pushKV("repository", "org/model");
    origin.pushKV("digest", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    cfg.pushKV("origin", origin);

    UniValue j(UniValue::VOBJ);
    j.pushKV("plan_id", PlanId('k'));
    j.pushKV("modelpack", cfg);
    modelnet::ImportPlan plan;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::ParseImportPlan(j, plan, err), err);
    BOOST_REQUIRE_EQUAL(plan.files.size(), 1U);
    BOOST_CHECK_EQUAL(plan.files[0].destination_path, "model.safetensors");
    BOOST_CHECK_EQUAL(plan.files[0].size_bytes, 5U);
    BOOST_REQUIRE_EQUAL(plan.origins.size(), 1U);
    BOOST_CHECK_EQUAL(plan.origins[0].type, "oci");
    BOOST_CHECK(plan.origins[0].locator.find("ghcr.io") != std::string::npos);

    const fs::path tdir = m_path_root / "reg-mp-stage";
    fs::create_directories(tdir);
    {
        std::ofstream out(tdir / "model.safetensors", std::ios::binary);
        out << "weigh";
    }
    modelnet::VerifiedManifest vm;
    BOOST_REQUIRE(modelnet::MakeVerifiedManifestFromStaged(tdir, {"model.safetensors"}, vm, err));
    UniValue exported;
    BOOST_REQUIRE(modelnet::ExportModelPackConfig(vm, plan, exported, err));
    BOOST_CHECK_EQUAL(exported["mediaType"].get_str(), modelnet::MODELPACK_MEDIA_TYPE);
    BOOST_CHECK(exported["origin"]["identity"].get_str().find("not the identity") != std::string::npos);
    BOOST_CHECK(!exported["wallet_required"].get_bool());
}

BOOST_AUTO_TEST_CASE(parseimportplan_expands_modelpack_without_wallet)
{
    UniValue cfg(UniValue::VOBJ);
    cfg.pushKV("mediaType", modelnet::MODELPACK_MEDIA_TYPE);
    UniValue model(UniValue::VOBJ);
    model.pushKV("path", "weights.safetensors");
    cfg.pushKV("model", model);
    UniValue origin(UniValue::VOBJ);
    origin.pushKV("locator", "oci://ghcr.io/org/model");
    origin.pushKV("digest", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    cfg.pushKV("origin", origin);
    UniValue planj(UniValue::VOBJ);
    planj.pushKV("plan_id", PlanId('q'));
    planj.pushKV("modelpack", cfg);
    const fs::path tmp = m_path_root / "reg-parse-mp";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue params(UniValue::VARR);
    params.push_back(planj);
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "parseimportplan");
    req.pushKV("params", params);
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, req, result, code, err), err);
    BOOST_CHECK(!result["wallet_required"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_REQUIRE(result["files"].isArray());
    BOOST_CHECK_EQUAL(result["files"][0]["destination_path"].get_str(), "weights.safetensors");
}

BOOST_AUTO_TEST_SUITE_END()
