// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/common.h>
#include <modelnet/acl.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/identity.h>
#include <modelnet/policy.h>
#include <modelnet/qualification.h>
#include <modelnet/records.h>
#include <modelnet/safety.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_safety_tests, BasicTestingSetup)

namespace {

struct SafetyReset {
    SafetyReset() { modelnet::GlobalSafety().ResetForTests(); }
    ~SafetyReset() { modelnet::GlobalSafety().ResetForTests(); }
};

modelnet::CatalogEntry ImportTiny(modelnet::ModelCatalog& cat)
{
    const fs::path src = cat.Store().Root().parent_path() / "src";
    fs::create_directories(src);
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    {
        std::ofstream out(src / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::CatalogEntry imported;
    std::string err;
    BOOST_REQUIRE(cat.ImportPath(fs::PathToString(src), true, imported, err));
    return imported;
}

} // namespace

BOOST_AUTO_TEST_CASE(relpath_skips_exec_and_inner_extensions)
{
    BOOST_CHECK(modelnet::RelPathLooksUnsafe("malware.exe"));
    BOOST_CHECK(modelnet::RelPathLooksUnsafe("weights/model.exe.safetensors"));
    BOOST_CHECK(modelnet::RelPathLooksUnsafe(".hidden.safetensors"));
    BOOST_CHECK(modelnet::RelPathLooksUnsafe("ok/../x.safetensors"));
    BOOST_CHECK(!modelnet::RelPathLooksUnsafe("model.safetensors"));
    BOOST_CHECK(!modelnet::RelPathLooksUnsafe("tokenizer/vocab.json"));
}

BOOST_AUTO_TEST_CASE(qualify_rejects_macho_shebang_wasm)
{
    modelnet::QualReport report;
    const unsigned char macho[4] = {0xFE, 0xED, 0xFA, 0xCE};
    BOOST_CHECK_EQUAL(modelnet::QualifyBytes("model.safetensors", Span<const unsigned char>{macho, 4}, report),
                      modelnet::QualResult::REJECTED_UNSAFE_FORMAT);
    const unsigned char sh[4] = {'#', '!', '/', 'b'};
    BOOST_CHECK_EQUAL(modelnet::QualifyBytes("model.safetensors", Span<const unsigned char>{sh, 4}, report),
                      modelnet::QualResult::REJECTED_UNSAFE_FORMAT);
    const unsigned char wasm[4] = {0x00, 'a', 's', 'm'};
    BOOST_CHECK_EQUAL(modelnet::QualifyBytes("model.safetensors", Span<const unsigned char>{wasm, 4}, report),
                      modelnet::QualResult::REJECTED_UNSAFE_FORMAT);
}

BOOST_AUTO_TEST_CASE(import_skips_single_file_exe)
{
    SafetyReset reset;
    const fs::path tmp = m_path_root / "safety-exe";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    const fs::path exe = tmp / "malware.exe";
    {
        const unsigned char elf[4] = {0x7f, 'E', 'L', 'F'};
        std::ofstream out(exe, std::ios::binary);
        out.write(reinterpret_cast<const char*>(elf), 4);
    }
    modelnet::CatalogEntry imported;
    std::string err;
    BOOST_CHECK(!cat.ImportPath(fs::PathToString(exe), true, imported, err));
}

BOOST_AUTO_TEST_CASE(unpinned_advisory_is_warning_only)
{
    SafetyReset reset;
    const fs::path tmp = m_path_root / "safety-warn";
    modelnet::GlobalSafety().Bind(tmp);
    const std::string tid(96, 'a');
    UniValue body(UniValue::VOBJ);
    body.pushKV("target_kind", modelnet::SAFETY_TARGET_MODEL);
    body.pushKV("target_id", tid);
    body.pushKV("severity", modelnet::SAFETY_MALWARE);
    body.pushKV("reason_code", 1);
    body.pushKV("content_sha384", std::string(96, '0'));
    body.pushKV("note", "gossip");
    body.pushKV("expires_at", 2000000000);
    bool applied = true;
    std::string err;
    const std::string signer(96, 'b');
    BOOST_REQUIRE(modelnet::GlobalSafety().IngestSigned(body, signer, std::string(96, 'c'), 1700000000, applied, err));
    BOOST_CHECK(!applied);
    BOOST_CHECK(!modelnet::GlobalSafety().SubjectBlocked(tid));
    BOOST_CHECK(!modelnet::SubscribedWarningIsAutomaticDeny());
}

BOOST_AUTO_TEST_CASE(pinned_publisher_advisory_blocks_and_unseeds)
{
    SafetyReset reset;
    const fs::path tmp = m_path_root / "safety-pin";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    modelnet::EnsureSafetyBound(tmp);
    auto imported = ImportTiny(cat);
    BOOST_CHECK(imported.seeded);

    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    const auto pub = modelnet::ResearchIdentityId(pk);
    BOOST_REQUIRE(modelnet::GlobalSafety().PinPublisher(pub.Hex(), "vendor", err));

    UniValue extra(UniValue::VOBJ);
    extra.pushKV("target_kind", modelnet::SAFETY_TARGET_MODEL);
    extra.pushKV("target_id", imported.model_id.Hex());
    extra.pushKV("severity", modelnet::SAFETY_MALWARE);
    extra.pushKV("reason_code", 1);
    extra.pushKV("content_sha384", std::string(96, '0'));
    extra.pushKV("note", "malware");
    UniValue body(UniValue::VOBJ);
    modelnet::FillRecordCommon(body, 1, pub, 1700000000, modelnet::DAY_SECONDS);
    for (const auto& k : extra.getKeys()) body.pushKV(k, extra[k]);
    std::vector<unsigned char> payload, sig;
    modelnet::Digest48 rid;
    BOOST_REQUIRE(modelnet::SignTypedRecord(modelnet::RECORD_SAFETY_ADVISORY, body, sk, payload, sig, rid, err));
    UniValue decoded;
    modelnet::Digest48 got;
    BOOST_REQUIRE(modelnet::VerifyTypedRecord(modelnet::RECORD_SAFETY_ADVISORY, payload, sig, pk, 1700000000, decoded, got, err));

    bool applied = false;
    BOOST_REQUIRE(modelnet::GlobalSafety().IngestSigned(decoded, pub.Hex(), rid.Hex(), 1700000000, applied, err));
    BOOST_CHECK(applied);
    BOOST_CHECK(modelnet::GlobalSafety().SubjectBlocked(imported.model_id.Hex()));

    std::string serr;
    BOOST_CHECK(!cat.Seed(imported.model_id, true, serr));
}

BOOST_AUTO_TEST_CASE(safety_advisory_rejects_provider_signer_class)
{
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    UniValue body(UniValue::VOBJ);
    modelnet::FillRecordCommon(body, 1, modelnet::ProviderId(pk), 1700000000, modelnet::DAY_SECONDS);
    body.pushKV("target_kind", modelnet::SAFETY_TARGET_MODEL);
    body.pushKV("target_id", std::string(96, 'a'));
    body.pushKV("severity", modelnet::SAFETY_MALWARE);
    body.pushKV("reason_code", 1);
    body.pushKV("content_sha384", std::string(96, '0'));
    body.pushKV("note", "x");
    std::vector<unsigned char> payload, sig;
    modelnet::Digest48 rid;
    BOOST_REQUIRE(modelnet::SignTypedRecord(modelnet::RECORD_SAFETY_ADVISORY, body, sk, payload, sig, rid, err));
    UniValue decoded;
    modelnet::Digest48 got;
    BOOST_CHECK(!modelnet::VerifyTypedRecord(modelnet::RECORD_SAFETY_ADVISORY, payload, sig, pk, 1700000000, decoded, got, err));
}

BOOST_AUTO_TEST_CASE(operator_report_stops_grant_issue)
{
    SafetyReset reset;
    const fs::path tmp = m_path_root / "safety-grant";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    auto imported = ImportTiny(cat);
    modelnet::EnsureSafetyBound(tmp);
    std::string err;
    BOOST_REQUIRE(modelnet::GlobalSafety().LocalReport(imported.model_id.Hex(), modelnet::SAFETY_TARGET_MODEL,
                                                       modelnet::SAFETY_MALWARE, "operator", 1700000000, err));
    (void)cat.Seed(imported.model_id, false, err);

    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = "/btx-model/2/ext/free/grant";
    nreq.body = std::string("{\"model_id\":\"") + imported.model_id.Hex() + "\"}";
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 404);
}

BOOST_AUTO_TEST_CASE(unix_rpc_pins_publisher)
{
    SafetyReset reset;
    const fs::path tmp = m_path_root / "safety-rpc";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    const std::string pid(96, 'd');
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "addmodelsafetypublisher");
    UniValue params(UniValue::VARR);
    params.push_back(pid);
    params.push_back("av-vendor");
    req.pushKV("params", params);
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, req, result, code, err, nullptr));
    BOOST_CHECK(modelnet::GlobalSafety().PublisherPinned(pid));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(result["consensus"].isFalse());
}

BOOST_AUTO_TEST_CASE(trust_bundle_still_fail_closed)
{
    modelnet::ModelAcl acl;
    acl.ObserveProtocolFault("x");
    BOOST_CHECK(acl.Quarantined("x"));
    BOOST_CHECK(!acl.ClearQuarantineFromTrustBundle("x"));
    BOOST_CHECK(acl.Quarantined("x"));
    BOOST_CHECK(!modelnet::SubscribedWarningIsAutomaticDeny());
}

BOOST_AUTO_TEST_CASE(fetching_does_not_demand_seed_or_advertise)
{
    SafetyReset reset;
    modelnet::PreservationPolicy p;
    p.storage_quota_bytes = 1 << 20;
    p.seed_mode = modelnet::SeedMode::AUTO;
    BOOST_CHECK(!modelnet::ShouldDemandSeed(p, modelnet::AdmissionLevel::FETCHING));
    BOOST_CHECK(!modelnet::ShouldDemandSeed(p, modelnet::AdmissionLevel::FAILED));
    BOOST_CHECK(modelnet::ShouldDemandSeed(p, modelnet::AdmissionLevel::STRUCTURE_VERIFIED));

    const fs::path tmp = m_path_root / "safety-fetch";
    modelnet::ModelCatalog src{tmp / "src-cat", 1 << 20};
    auto imported = ImportTiny(src);
    UniValue man;
    std::string err;
    BOOST_REQUIRE(src.GetManifest(imported.model_id, man, err));
    modelnet::ModelCatalog dst{tmp / "dst-cat", 1 << 20};
    BOOST_REQUIRE(dst.InstallFromManifest(man, err, /*complete=*/false));
    modelnet::CatalogEntry got;
    BOOST_REQUIRE(dst.Find(imported.model_id, got));
    BOOST_CHECK(!got.seeded);
    BOOST_CHECK(got.incomplete);

    modelnet::NativeRequest req;
    modelnet::NativeResponse resp;
    req.method = "POST";
    req.path = "/btx-model/2/availability";
    req.body = "{}";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(dst, req, resp));
    UniValue body;
    BOOST_REQUIRE(body.read(resp.body));
    BOOST_REQUIRE(body["local"]["models"].isArray());
    BOOST_CHECK_EQUAL(body["local"]["models"].size(), 0);
}

BOOST_AUTO_TEST_CASE(import_requires_weights_and_cleans_failed_staging)
{
    SafetyReset reset;
    const fs::path tmp = m_path_root / "safety-import";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    const fs::path json_only = tmp / "json-only";
    fs::create_directories(json_only);
    {
        std::ofstream out(json_only / "vocab.json");
        out << "{\"a\":1}\n";
    }
    modelnet::CatalogEntry imported;
    std::string err;
    BOOST_CHECK(!cat.ImportPath(fs::PathToString(json_only), true, imported, err));
    BOOST_CHECK(err.find("weight") != std::string::npos);

    const fs::path mixed = tmp / "mixed";
    fs::create_directories(mixed);
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    {
        std::ofstream out(mixed / "a.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    {
        std::ofstream out(mixed / "z.txt", std::ios::binary);
        out << "#!/bin/sh\n";
    }
    BOOST_CHECK(!cat.ImportPath(fs::PathToString(mixed), true, imported, err));
    const fs::path arts = cat.Store().Root() / "artifacts";
    size_t leftover = 0;
    if (fs::exists(arts)) {
        for (const auto& ent : fs::directory_iterator(arts)) {
            if (ent.is_directory()) ++leftover;
        }
    }
    BOOST_CHECK_EQUAL(leftover, 0);
    BOOST_CHECK_EQUAL(cat.UsedBytes(), 0);
}

BOOST_AUTO_TEST_CASE(addpeer_cap_is_visible)
{
    SafetyReset reset;
    const fs::path tmp = m_path_root / "safety-peers";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    for (int i = 0; i < 64; ++i) {
        BOOST_REQUIRE(cat.AddPeer("192.0.2." + std::to_string(i) + ":29447"));
    }
    BOOST_CHECK(!cat.AddPeer("198.51.100.1:29447"));
    BOOST_CHECK_EQUAL(cat.Peers().size(), 64);

    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "addmodelnode");
    UniValue params(UniValue::VARR);
    params.push_back("203.0.113.9:29447");
    req.pushKV("params", params);
    UniValue result;
    std::string code, rpc_err;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, req, result, code, rpc_err, nullptr));
    BOOST_CHECK(result["ok"].isFalse());
    BOOST_CHECK(result["added"].isFalse());
}

BOOST_AUTO_TEST_SUITE_END()
