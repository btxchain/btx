// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// V11 matrix id -> BOOST_AUTO_TEST_CASE
// V11-MIG-01  mig_exportmodelpath_never_starts_runtime (IDs unchanged via URI)
// V11-MIG-03  mig_exportmodelpath_never_starts_runtime (safe path; no PQ1 listener)
// V11-MIG-04  mig_identities_json_not_wallet_dump
// V11-MIG-05  mig_seed_preserve_flags_persist
// V11-DOC-03  doc_capabilities_match_disclosure
// V11-DOC-04  doc_native_fallback_never_true

#include <crypto/common.h>
#include <crypto/sha384.h>
#include <modelnet/catalog.h>
#include <modelnet/cores.h>
#include <modelnet/firstrun.h>
#include <modelnet/helper.h>
#include <modelnet/http_bridge.h>
#include <modelnet/identity.h>
#include <modelnet/policy.h>
#include <modelnet/pq1_runtime.h>
#include <modelnet/protocol.h>
#include <modelnet/resource_uri.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <span.h>

#include <boost/test/unit_test.hpp>

#include <cctype>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_mig_doc_tests, BasicTestingSetup)

namespace {

bool IEquals(std::string_view a, std::string_view b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

const UniValue* FindKeyCI(const UniValue& obj, std::string_view name)
{
    if (!obj.isObject()) return nullptr;
    for (const auto& key : obj.getKeys()) {
        if (IEquals(key, name)) return &obj[key];
    }
    return nullptr;
}

bool LooksLikeWalletDump(std::string_view text)
{
    const std::string lower = ToLower(std::string{text});
    static const char* kNeedles[] = {
        "# wallet dump created by",
        "# end of dump",
        "extended private masterkey",
        "hdseed=1",
        "inactivehdseed=1",
        "reserve=1",
        "change=1",
        "script=1",
        "dumpwallet",
        "importwallet",
        "dumpprivkey",
    };
    for (const char* n : kNeedles) {
        if (lower.find(n) != std::string::npos) return true;
    }
    return false;
}

void NativeFallbackNeverTrue(const UniValue& v)
{
    if (v.isObject()) {
        for (const auto& key : v.getKeys()) {
            const UniValue& child = v[key];
            if (IEquals(key, "native_fallback")) {
                BOOST_CHECK(child.isBool());
                BOOST_CHECK_EQUAL(child.get_bool(), false);
            }
            NativeFallbackNeverTrue(child);
        }
        return;
    }
    if (v.isArray()) {
        for (const auto& child : v.getValues()) NativeFallbackNeverTrue(child);
    }
}

UniValue ParseBridgeBody(const modelnet::BrowserBridgeResponse& br)
{
    BOOST_CHECK_EQUAL(br.content_type, "application/json");
    UniValue obj;
    BOOST_REQUIRE(obj.read(br.body));
    BOOST_REQUIRE(obj.isObject());
    NativeFallbackNeverTrue(obj);
    const UniValue* nf = FindKeyCI(obj, "native_fallback");
    BOOST_REQUIRE(nf);
    BOOST_CHECK(nf->isBool());
    BOOST_CHECK_EQUAL(nf->get_bool(), false);
    return obj;
}

std::vector<unsigned char> MinimalSafeTensors()
{
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    return st;
}

modelnet::CatalogEntry ImportSample(modelnet::ModelCatalog& cat, const fs::path& src_dir)
{
    fs::create_directories(src_dir);
    const auto st = MinimalSafeTensors();
    {
        std::ofstream out(src_dir / "model.safetensors", std::ios::binary);
        BOOST_REQUIRE(out);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::CatalogEntry imported;
    std::string err;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(src_dir), /*pin=*/true, imported, err), err);
    return imported;
}

UniValue Rpc(const std::string& method, const UniValue& params = UniValue(UniValue::VARR))
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", method);
    req.pushKV("params", params);
    return req;
}

bool Dispatch(modelnet::ModelCatalog& cat, const UniValue& req, UniValue& result, std::string& code, std::string& err)
{
    return modelnet::DispatchHelperRpc(cat, req, result, code, err);
}

/** Reuse FirstRun Save/Load. Create firstrun.json on miss; never clobber an existing file.
 *  LoadFirstRunConsent zeros `out` on miss, so load into a scratch object. */
bool LoadOrCreateSettings(const fs::path& datadir, modelnet::FirstRunConsent& settings, std::string& err)
{
    const fs::path path = modelnet::FirstRunConsentPath(datadir);
    modelnet::FirstRunConsent existing;
    if (modelnet::LoadFirstRunConsent(path, existing, err)) {
        settings = existing;
        return true;
    }
    if (!modelnet::SaveFirstRunConsent(path, settings, err)) return false;
    return modelnet::LoadFirstRunConsent(path, settings, err);
}

} // namespace

BOOST_AUTO_TEST_CASE(mig_exportmodelpath_never_starts_runtime)
{
    const fs::path tmp = m_path_root / "mig-export";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto imported = ImportSample(cat, tmp / "src");

    std::string uri, err;
    BOOST_REQUIRE(modelnet::EncodeResource(modelnet::ResourceKind::MODEL, imported.model_id, uri, err));
    modelnet::Resource decoded;
    BOOST_REQUIRE(modelnet::DecodeResource(uri, decoded, err));
    BOOST_CHECK(decoded.digest == imported.model_id);
    BOOST_CHECK(decoded.kind == modelnet::ResourceKind::MODEL);

    const int inbound0 = modelnet::GlobalConnLimits().Inbound();
    const int outbound0 = modelnet::GlobalConnLimits().Outbound();
    BOOST_CHECK(!fs::exists(tmp / "modeld.sock"));
    BOOST_CHECK(!fs::exists(tmp / "tls" / "cert.pem"));

    UniValue params(UniValue::VARR);
    params.push_back(uri);
    UniValue result;
    std::string code;
    BOOST_REQUIRE_MESSAGE(Dispatch(cat, Rpc("exportmodelpath", params), result, code, err), err);
    BOOST_CHECK_EQUAL(result["inference"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["model_id"].get_str(), imported.model_id.Hex());
    BOOST_CHECK_EQUAL(result["artifact_id"].get_str(), imported.artifact_id.Hex());
    BOOST_CHECK_EQUAL(result["store_root"].get_str(), fs::PathToString(cat.Store().Root()));
    BOOST_CHECK_EQUAL(result["runtime_started"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["runtime_exec"].get_bool(), false);
    BOOST_REQUIRE(result.exists("files"));
    BOOST_CHECK(result["note"].get_str().find("never starts a runtime") != std::string::npos);

    UniValue hex_params(UniValue::VARR);
    hex_params.push_back(imported.artifact_id.Hex());
    UniValue via_hex;
    BOOST_REQUIRE_MESSAGE(Dispatch(cat, Rpc("exportmodelpath", hex_params), via_hex, code, err), err);
    BOOST_CHECK_EQUAL(via_hex["model_id"].get_str(), imported.model_id.Hex());
    BOOST_CHECK_EQUAL(via_hex["artifact_id"].get_str(), imported.artifact_id.Hex());
    BOOST_CHECK_EQUAL(via_hex["inference"].get_bool(), false);

    BOOST_CHECK_EQUAL(modelnet::GlobalConnLimits().Inbound(), inbound0);
    BOOST_CHECK_EQUAL(modelnet::GlobalConnLimits().Outbound(), outbound0);
    BOOST_CHECK(!fs::exists(tmp / "modeld.sock"));
    BOOST_CHECK(!fs::exists(tmp / "tls" / "cert.pem"));

    UniValue missing_params(UniValue::VARR);
    missing_params.push_back(std::string(96, '0'));
    UniValue missing;
    BOOST_CHECK(!Dispatch(cat, Rpc("exportmodelpath", missing_params), missing, code, err));
    BOOST_CHECK_EQUAL(code, "NOT_FOUND");
    BOOST_CHECK_EQUAL(modelnet::GlobalConnLimits().Inbound(), inbound0);
    BOOST_CHECK_EQUAL(modelnet::GlobalConnLimits().Outbound(), outbound0);
}

BOOST_AUTO_TEST_CASE(mig_identities_json_not_wallet_dump)
{
    const fs::path tmp = m_path_root / "mig-ident";
    modelnet::ModelCatalog cat{tmp, 8 << 20};

    UniValue create_params(UniValue::VARR);
    create_params.push_back("lab-contact");
    UniValue created;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(Dispatch(cat, Rpc("createmodelidentity", create_params), created, code, err), err);
    BOOST_CHECK_EQUAL(created["class"].get_str(), "RESEARCH_PUBLISHER");
    BOOST_CHECK_EQUAL(created["label"].get_str(), "lab-contact");
    BOOST_CHECK(created["note"].get_str().find("never a wallet") != std::string::npos);
    BOOST_CHECK(!created.exists("hdseed"));
    BOOST_CHECK(!created.exists("address"));
    BOOST_CHECK(!created.exists("wif"));

    UniValue listed;
    BOOST_REQUIRE_MESSAGE(Dispatch(cat, Rpc("listmodelidentities"), listed, code, err), err);
    BOOST_REQUIRE(listed["identities"].isArray());
    BOOST_REQUIRE_EQUAL(listed["identities"].size(), 1U);
    BOOST_CHECK_EQUAL(listed["identities"][0]["id"].get_str(), created["id"].get_str());
    BOOST_CHECK(!LooksLikeWalletDump(listed.write()));

    const fs::path ident_path = cat.Store().Root().parent_path() / "identities.json";
    const std::string ident_str = fs::PathToString(ident_path);
    BOOST_CHECK(ident_str.find("/wallet/") == std::string::npos);
    BOOST_CHECK(ident_str.find("/chainstate/") == std::string::npos);
    BOOST_REQUIRE(fs::exists(ident_path));
    std::ifstream in{ident_path};
    BOOST_REQUIRE(in);
    const std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    BOOST_CHECK(!LooksLikeWalletDump(raw));
    UniValue store;
    BOOST_REQUIRE(store.read(raw));
    BOOST_REQUIRE(store.isObject());
    BOOST_REQUIRE(store["identities"].isArray());
    BOOST_REQUIRE_EQUAL(store["identities"].size(), 1U);
    BOOST_CHECK_EQUAL(store["identities"][0]["class"].get_str(), "RESEARCH_PUBLISHER");
    BOOST_CHECK(store["identities"][0]["pubkey_hex"].get_str().size() == 2 * modelnet::MLDSA44_PK);
    BOOST_CHECK(!store["identities"][0].exists("secret"));
    BOOST_CHECK(!store["identities"][0].exists("secret_hex"));
    BOOST_CHECK(!store["identities"][0].exists("wif"));

    modelnet::IdentityStore idstore;
    BOOST_CHECK(!idstore.RequiresWallet());
    modelnet::ModelIdentity ident;
    ident.cls = modelnet::IdentityClass::RESEARCH_PUBLISHER;
    const auto pk = TryParseHex<unsigned char>(created["pubkey_hex"].get_str());
    BOOST_REQUIRE(pk);
    ident.pubkey = *pk;
    ident.local_label = "lab-contact";
    BOOST_REQUIRE(idstore.Insert(ident, {}, err));
    BOOST_CHECK(!idstore.AdoptSpendingAddress("btx1qexample-spending-address"));
    BOOST_CHECK(!modelnet::SpendingAddressIsResearchIdentity("btx1qexample-spending-address"));
    const auto pub = idstore.PublicExport();
    BOOST_REQUIRE_EQUAL(pub.size(), 1U);
    BOOST_CHECK(pub[0].pubkey == *pk);
    const auto bak = idstore.SecretBackup();
    BOOST_CHECK(!bak.contains_wallet_material);
    BOOST_CHECK(!bak.contains_tls_secrets);
    BOOST_CHECK(!bak.contains_payment_credentials);
    modelnet::ModelIdentity wallet;
    wallet.cls = modelnet::IdentityClass::MONETARY_WALLET;
    wallet.pubkey.assign(modelnet::MLDSA44_PK, 0x22);
    BOOST_CHECK(!idstore.Insert(wallet, {}, err));
}

BOOST_AUTO_TEST_CASE(mig_seed_preserve_flags_persist)
{
    const fs::path datadir = m_path_root / "mig-settings";
    std::string err;

    BOOST_CHECK_EQUAL(fs::PathToString(modelnet::FirstRunConsentPath(datadir)),
                      fs::PathToString(datadir / "modelnet" / "firstrun.json"));
    BOOST_CHECK(fs::PathToString(modelnet::FirstRunConsentPath(datadir)).find("/wallet/") == std::string::npos);

    modelnet::FirstRunConsent created;
    created.storage_bytes = 80ULL << 30;
    created.seed = modelnet::SeedMode::OFF;
    created.preserve_rare = true;
    created.consented_unix = 1'700'000'001;
    BOOST_REQUIRE_MESSAGE(LoadOrCreateSettings(datadir, created, err), err);
    BOOST_CHECK(created.seed == modelnet::SeedMode::OFF);
    BOOST_CHECK(created.preserve_rare);
    BOOST_CHECK_EQUAL(created.storage_bytes, 80ULL << 30);

    modelnet::FirstRunConsent again;
    again.seed = modelnet::SeedMode::AUTO;
    again.preserve_rare = false;
    again.storage_bytes = 1;
    BOOST_REQUIRE_MESSAGE(LoadOrCreateSettings(datadir, again, err), err);
    BOOST_CHECK(again.seed == modelnet::SeedMode::OFF);
    BOOST_CHECK(again.preserve_rare);
    BOOST_CHECK_EQUAL(again.storage_bytes, 80ULL << 30);
    BOOST_CHECK_EQUAL(again.consented_unix, 1'700'000'001);

    modelnet::FirstRunConsent reloaded;
    BOOST_REQUIRE_MESSAGE(modelnet::LoadFirstRunConsent(modelnet::FirstRunConsentPath(datadir), reloaded, err), err);
    BOOST_CHECK(reloaded.seed == modelnet::SeedMode::OFF);
    BOOST_CHECK(reloaded.preserve_rare);

    modelnet::PreservationPolicy policy;
    policy.seed_mode = modelnet::SeedMode::OFF;
    policy.seed_upon_download = false;
    policy.preserve_rare = true;
    policy.storage_quota_bytes = 80ULL << 30;
    const UniValue dumped = modelnet::PolicyToJson(policy);
    BOOST_CHECK_EQUAL(dumped["seed"].get_str(), "off");
    BOOST_CHECK_EQUAL(dumped["preserve_rare"].get_bool(), true);
    BOOST_CHECK_EQUAL(dumped["automatic_spend_atoms"].getInt<int64_t>(), 0);
    modelnet::PreservationPolicy parsed;
    BOOST_REQUIRE_MESSAGE(modelnet::PolicyFromJson(dumped, parsed, err), err);
    BOOST_CHECK(parsed.seed_mode == modelnet::SeedMode::OFF);
    BOOST_CHECK(parsed.preserve_rare);

    const fs::path tmp = m_path_root / "mig-policy";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    UniValue patch(UniValue::VOBJ);
    patch.pushKV("seed", "off");
    patch.pushKV("preserve_rare", true);
    UniValue set_params(UniValue::VARR);
    set_params.push_back(patch);
    UniValue set_result;
    std::string code;
    BOOST_REQUIRE_MESSAGE(Dispatch(cat, Rpc("setmodelpolicy", set_params), set_result, code, err), err);
    BOOST_CHECK_EQUAL(set_result["seed"].get_str(), "off");
    BOOST_CHECK_EQUAL(set_result["preserve_rare"].get_bool(), true);

    UniValue got;
    BOOST_REQUIRE_MESSAGE(Dispatch(cat, Rpc("getmodelpolicy"), got, code, err), err);
    BOOST_CHECK_EQUAL(got["seed"].get_str(), "off");
    BOOST_CHECK_EQUAL(got["preserve_rare"].get_bool(), true);

    std::ifstream pin{cat.Store().Root().parent_path() / "policy.json"};
    BOOST_REQUIRE(pin);
    std::string praw((std::istreambuf_iterator<char>(pin)), std::istreambuf_iterator<char>());
    UniValue on_disk;
    BOOST_REQUIRE(on_disk.read(praw));
    modelnet::PreservationPolicy from_disk;
    BOOST_REQUIRE_MESSAGE(modelnet::PolicyFromJson(on_disk, from_disk, err), err);
    BOOST_CHECK(from_disk.seed_mode == modelnet::SeedMode::OFF);
    BOOST_CHECK(from_disk.preserve_rare);
}

BOOST_AUTO_TEST_CASE(doc_capabilities_match_disclosure)
{
    const UniValue caps = modelnet::CapabilitiesObject();
    BOOST_REQUIRE(caps.isObject());

    const UniValue* paid = FindKeyCI(caps, "paid_chain_verify");
    BOOST_REQUIRE(paid);
    BOOST_CHECK(paid->isBool());
    BOOST_CHECK_EQUAL(paid->get_bool(), false);

    const UniValue* cuda_qual = FindKeyCI(caps, "cuda_qualification");
    BOOST_REQUIRE(cuda_qual);
    BOOST_CHECK(cuda_qual->isBool());
    BOOST_CHECK_EQUAL(cuda_qual->get_bool(), true);
    if (const UniValue* cuda = FindKeyCI(caps, "cuda")) {
        BOOST_CHECK(cuda->isBool());
        BOOST_CHECK_EQUAL(cuda->get_bool(), false);
    }

    const UniValue* bridge = FindKeyCI(caps, "browser_bridge");
    BOOST_REQUIRE(bridge);
    BOOST_CHECK(bridge->isBool());
    BOOST_CHECK_EQUAL(bridge->get_bool(), false);

    const UniValue* spend_atoms = FindKeyCI(caps, "automatic_spend_atoms");
    BOOST_REQUIRE(spend_atoms);
    BOOST_CHECK_EQUAL(spend_atoms->getInt<int64_t>(), 0);
    if (const UniValue* spend = FindKeyCI(caps, "automatic_spend")) {
        BOOST_CHECK_EQUAL(spend->getInt<int64_t>(), 0);
    }

    const UniValue* remote = FindKeyCI(caps, "remote_inference");
    BOOST_REQUIRE(remote);
    BOOST_CHECK_EQUAL(remote->get_bool(), false);

    const fs::path tmp = m_path_root / "doc-caps";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    UniValue info;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(Dispatch(cat, Rpc("getmodelnetworkinfo"), info, code, err), err);
    const UniValue& via_rpc = info["capabilities"];
    BOOST_CHECK_EQUAL(via_rpc["paid_chain_verify"].get_bool(), false);
    BOOST_CHECK_EQUAL(via_rpc["cuda_qualification"].get_bool(), true);
    BOOST_CHECK_EQUAL(via_rpc["browser_bridge"].get_bool(), false);
    BOOST_CHECK_EQUAL(via_rpc["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(info["automatic_spend_atoms"].getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(doc_native_fallback_never_true)
{
    std::string uri, err;
    modelnet::Digest48 digest;
    BOOST_REQUIRE(modelnet::Digest48::FromHex(
        "711fa03c1e73844f3fb90569034fec047637ebc45d6420dc4c9a66ac54585544616b54134234be6e442cc000b804754e",
        digest, err));
    BOOST_REQUIRE(modelnet::EncodeResource(modelnet::ResourceKind::MODEL, digest, uri, err));
    const std::string token = uri.substr(6);

    const char* paths[] = {
        "/health",
        "/not-a-token",
        "/open?uri=",
        "/open?uri=not-a-token",
        "/",
        "/wallet",
        "/dump",
        "/dumpwallet",
        "/sign",
    };
    for (const char* p : paths) {
        modelnet::BrowserBridgeResponse br;
        BOOST_REQUIRE(modelnet::HandleBridgeGet(p, br));
        ParseBridgeBody(br);
    }

    modelnet::BrowserBridgeResponse ok;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/" + token, ok));
    BOOST_CHECK_EQUAL(ok.http_status, 200);
    ParseBridgeBody(ok);

    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri, ok));
    BOOST_CHECK_EQUAL(ok.http_status, 200);
    ParseBridgeBody(ok);
}

BOOST_AUTO_TEST_CASE(doc_01_b0_markdown_sha384_matches_cited)
{
    const std::string cited =
        "dcc94d534964bca13fccb9a87c2b78808608d0a6bdcf3a72d3c22203bee5cb4b"
        "a8039f650a05e25730ec55c24c285e1c";
#ifdef MODELNET_B0_SPEC_PATH
    const char* path = MODELNET_B0_SPEC_PATH;
    if (path && path[0] != '\0') {
        std::ifstream in{path, std::ios::binary};
        BOOST_REQUIRE_MESSAGE(in, path);
        const std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        BOOST_REQUIRE(!raw.empty());
        CSHA384 hasher;
        hasher.Write(reinterpret_cast<const unsigned char*>(raw.data()), raw.size());
        unsigned char out[CSHA384::OUTPUT_SIZE];
        hasher.Finalize(out);
        BOOST_CHECK_EQUAL(HexStr(Span<const unsigned char>{out, sizeof(out)}), cited);
        BOOST_CHECK(raw.find("BTX-SPEC-0347-MODELS-PQ") != std::string::npos);
        BOOST_CHECK(raw.find("Revision 2") != std::string::npos);
        return;
    }
#endif
    BOOST_TEST_MESSAGE("MODELNET_B0_SPEC_PATH unset; cited SHA-384 length still checked");
    BOOST_CHECK_EQUAL(cited.size(), 96U);
}

BOOST_AUTO_TEST_CASE(mig_02_b0_hello_and_cores_unchanged)
{
    const fs::path tmp = m_path_root / "mig-hello";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    modelnet::NativeRequest req;
    req.method = "POST";
    req.path = std::string(modelnet::MODEL_HTTP_ROOT) + "hello";
    modelnet::NativeResponse resp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, req, resp));
    BOOST_CHECK_EQUAL(resp.status, 200);
    UniValue hello;
    BOOST_REQUIRE(hello.read(resp.body));
    BOOST_CHECK_EQUAL(hello["protocol"].getInt<int>(), 2);
    BOOST_CHECK_EQUAL(hello["suite"].get_str(), "pq1");
    BOOST_CHECK_EQUAL(hello["group"].get_str(), "MLKEM768");
    BOOST_CHECK_EQUAL(hello["cipher"].get_str(), "TLS_AES_256_GCM_SHA384");
    BOOST_CHECK_EQUAL(hello["sigalg"].get_str(), "mldsa44");
    BOOST_CHECK(!hello.exists("ext_version"));
    BOOST_CHECK(!hello.exists("collection"));
    BOOST_CHECK(!hello.exists("alias"));

    std::ifstream in{MODELNET_B0_CODEC_VECTORS_PATH};
    BOOST_REQUIRE(in);
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue vec;
    BOOST_REQUIRE(vec.read(raw));
    modelnet::ModelCore core;
    core.version = 2;
    core.format_profile = 1;
    core.execution_profile = 0;
    std::string err;
    BOOST_REQUIRE(modelnet::Digest48::FromHex(vec["model-core"]["object"]["config_sha384"].get_str(), core.config_sha384, err));
    BOOST_REQUIRE(modelnet::Digest48::FromHex(vec["model-core"]["object"]["tokenizer_sha384"].get_str(), core.tokenizer_sha384, err));
    modelnet::CoreFile f;
    f.path = vec["model-core"]["object"]["files"][0]["path"].get_str();
    f.role = modelnet::FileRole::WEIGHTS;
    f.size = vec["model-core"]["object"]["files"][0]["size"].getInt<uint64_t>();
    BOOST_REQUIRE(modelnet::Digest48::FromHex(vec["model-core"]["object"]["files"][0]["sha384"].get_str(), f.sha384, err));
    BOOST_REQUIRE(modelnet::Digest48::FromHex(vec["model-core"]["object"]["files"][0]["pieces_root"].get_str(), f.pieces_root, err));
    core.files.push_back(f);
    std::vector<unsigned char> canonical;
    BOOST_REQUIRE(modelnet::EncodeModelCore(core, canonical, err));
    BOOST_CHECK_EQUAL(HexStr(canonical), vec["model-core"]["canonical_hex"].get_str());
}

BOOST_AUTO_TEST_SUITE_END()
