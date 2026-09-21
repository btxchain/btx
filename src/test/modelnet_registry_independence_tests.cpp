// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// 0.34.9 registry independence: origins[] are disposable delivery mechanisms.
// btx:// / VerifiedManifest is the artifact. Monetary plane is not required to
// fetch and is not removed. Native BTX signatures stay; OMS/Sigstore/Cosign
// are extra evidence slots. OCI is an origin, not a replacement packaging silo.

#include <modelnet/helper.h>
#include <modelnet/import_coordinator.h>
#include <modelnet/import_plan.h>
#include <modelnet/registry_resolver.h>
#include <modelnet/source_huggingface.h>
#include <modelnet/source_registry.h>
#include <modelnet/store.h>
#include <modelnet/types.h>
#include <modelnet/verified_manifest.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <fstream>
#include <string>
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
    modelnet::ClearRegistryInjections();
}

BOOST_AUTO_TEST_SUITE_END()
