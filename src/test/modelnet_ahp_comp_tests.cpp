// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// BTX-AHP-001 Lane H — native COMP cases.
//   AHP-COMP-01  identity/framing vs old codec; live 0.34.7 peer NOT_RUN
//   AHP-COMP-02  legacy acquisition-only export (labeled; handoff stripped)
//   AHP-COMP-03  bundle framing vs thin Core-v2 descriptor
//   AHP-COMP-04  helper-down vs monetary node (NOT_RUN)
//   AHP-COMP-05  WITH_MODELNET=OFF monetary probe (contrib/modelnet/check-with-modelnet-off.sh)
//   AHP-COMP-06  reference Python evidence is not native PASS
//
// Coordinator owns CMakeLists.txt. Do not copy the 63 Python reference tests
// into audit/agent-package-acceptance-wip.csv as native PASS.

#include <crypto/common.h>
#include <crypto/sha384.h>
#include <modelnet/package_bundle.h>
#include <modelnet/package_core.h>
#include <modelnet/package_export.h>
#include <modelnet/package_pjson.h>
#include <modelnet/resource_uri.h>
#include <modelnet/types.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_ahp_comp_tests, BasicTestingSetup)

namespace {

// Inspector core_id only (python3 reference/btx_package.py). Not native PASS.
constexpr const char* kModelAgentCoreId =
    "73e72380ef4959614ec34e0796a12d59bf4abf483c044b55b66c167d6bb6670db8ec3dd7d26d0e455a072288606e7b58";

fs::path AgentPackageDir()
{
#ifdef MODELNET_AHP_FIXTURE_DIR
    return fs::PathFromString(MODELNET_AHP_FIXTURE_DIR);
#else
    return fs::PathFromString(std::string{__FILE__}).parent_path() / "data" / "agent-package";
#endif
}

std::vector<unsigned char> LoadBtx(const char* name)
{
    const fs::path path = AgentPackageDir() / name;
    std::ifstream in{path, std::ios::binary};
    BOOST_REQUIRE_MESSAGE(in, "missing fixture " + fs::PathToString(path));
    std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    BOOST_REQUIRE_GE(bytes.size(), 68U);
    return bytes;
}

} // namespace

BOOST_AUTO_TEST_CASE(ahp_comp_01_old_peer_new_package)
{
    // flags=0 PJSON1 is a package body, not a bundle discriminator. DecodeBtxBundle
    // rejects the conflicting dual body instead of silently parsing JSON.
    const auto desc = LoadBtx("model-agent.btx");
    BOOST_CHECK(modelnet::LooksLikeBtxBundle(desc));
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeBtxPackage(desc, pkg, err), err);
    BOOST_CHECK_EQUAL(pkg.core_version, 2);
    BOOST_CHECK_EQUAL(pkg.package_core_id.Hex(), kModelAgentCoreId);

    UniValue bundle_view;
    BOOST_CHECK(!modelnet::DecodeBtxBundle(desc, bundle_view, err));
    BOOST_CHECK_EQUAL(err, "conflicting dual body");
    modelnet::Digest48 from_pkg;
    BOOST_REQUIRE(modelnet::PackageCoreId(pkg.core, from_pkg, err));
    BOOST_CHECK_EQUAL(from_pkg.Hex(), kModelAgentCoreId);

    const auto v1 = LoadBtx("legacy-core-v1.btx");
    modelnet::DecodedBtxPackage legacy;
    BOOST_REQUIRE(modelnet::DecodeBtxPackage(v1, legacy, err));
    BOOST_CHECK_EQUAL(legacy.core_version, 1);
    std::string code;
    BOOST_CHECK(!modelnet::ValidateAgentPackageCore(legacy.core, code, err));
    BOOST_CHECK_EQUAL(code, "UNSUPPORTED_CORE_VERSION");

    BOOST_REQUIRE(pkg.core.exists("resources") && pkg.core["resources"].size() > 0);
    const std::string rid = pkg.core["resources"][0]["id"].get_str();
    BOOST_CHECK_EQUAL(pkg.core["resources"][0]["kind"].get_str(), "MODEL");
    modelnet::Digest48 digest;
    BOOST_REQUIRE_MESSAGE(modelnet::Digest48::FromHex(rid, digest, err), err);
    std::string uri;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeResource(modelnet::ResourceKind::MODEL, digest, uri, err), err);
    BOOST_CHECK_EQUAL(uri.compare(0, 6, "btx://"), 0);
    BOOST_CHECK(uri.find("btx-model") == std::string::npos);

    std::vector<unsigned char> reencoded;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeBtxPackage(pkg.payload, reencoded, err), err);
    modelnet::DecodedBtxPackage again;
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeBtxPackage(reencoded, again, err), err);
    BOOST_CHECK_EQUAL(again.core["resources"][0]["id"].get_str(), rid);
    BOOST_CHECK_EQUAL(again.package_core_id.Hex(), kModelAgentCoreId);
    BOOST_TEST_MESSAGE("AHP-COMP-01 remainder NOT_RUN: live 0.34.7 peer piece transfer");
}

BOOST_AUTO_TEST_CASE(ahp_comp_02_legacy_export_deliberate)
{
    const auto desc = LoadBtx("model-agent.btx");
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeBtxPackage(desc, pkg, err), err);
    BOOST_REQUIRE(pkg.payload.exists("core"));
    BOOST_REQUIRE(pkg.payload["core"].exists("agent_handoff"));

    std::vector<unsigned char> exported;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeLegacyAcquisitionExport(pkg.payload, exported, err), err);
    BOOST_CHECK(modelnet::LooksLikeBtxBundle(exported));

    UniValue view;
    const bool as_bundle = modelnet::DecodeBtxBundle(exported, view, err);
    BOOST_REQUIRE_MESSAGE(as_bundle, err);
    BOOST_CHECK(!view.exists("agent_handoff"));
    if (view.exists("core") && view["core"].isObject()) {
        BOOST_CHECK(!view["core"].exists("agent_handoff"));
    }
    if (view.exists("legacy_acquisition_export") && view["legacy_acquisition_export"].isBool()) {
        BOOST_CHECK(view["legacy_acquisition_export"].get_bool());
    }

    modelnet::DecodedBtxPackage legacy;
    const bool as_pkg = modelnet::DecodeBtxPackage(exported, legacy, err);
    if (as_pkg) {
        BOOST_CHECK(!legacy.core.exists("agent_handoff"));
    }
    BOOST_TEST_MESSAGE(
        "AHP-COMP-02: labeled legacy acquisition-only export; handoff/runtime semantics dropped");
}

BOOST_AUTO_TEST_CASE(ahp_comp_03_bundle_vs_descriptor)
{
    // AHP-COMP-03 — Place a new thin descriptor into the existing approved
    // BTXPKG1 bundle framing. Streaming reader validates the 68-byte frame
    // and the PJSON1 payload separately. Not a ZIP. Identity is PackageCoreId,
    // not a DomainHash rewrite and not EncodeBtxBundle's UniValue::write() body.
    const auto desc = LoadBtx("model-agent.btx");
    BOOST_CHECK_EQUAL(std::memcmp(desc.data(), modelnet::BTXPKG_MAGIC, 8), 0);
    BOOST_CHECK(modelnet::LooksLikeBtxBundle(desc));
    BOOST_CHECK_MESSAGE(!(desc[68] == 'P' && desc[69] == 'K' && desc[70] == 0x03 && desc[71] == 0x04),
                        "AHP-COMP-03: descriptor payload is not a ZIP local-file header");

    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeBtxPackage(desc, pkg, err), err);
    BOOST_CHECK_EQUAL(pkg.package_core_id.Hex(), kModelAgentCoreId);
    BOOST_CHECK_EQUAL(pkg.core_version, 2);

    // Frame vs payload: header length/digest checked independently of JSON.
    const uint64_t n = ReadLE64(desc.data() + 12);
    BOOST_REQUIRE_EQUAL(n, desc.size() - 68);
    unsigned char digest[48];
    CSHA384 hasher;
    hasher.Write(desc.data() + 68, static_cast<size_t>(n));
    hasher.Finalize(digest);
    BOOST_CHECK_EQUAL(std::memcmp(digest, desc.data() + 20, 48), 0);
    std::vector<unsigned char> pjson;
    BOOST_REQUIRE(modelnet::EncodePjson1(pkg.payload, pjson, err));
    BOOST_CHECK_EQUAL(pjson.size(), n);
    BOOST_CHECK(std::equal(pjson.begin(), pjson.end(), desc.begin() + 68));

    // Existing bundle encoder shares magic but writes BTXPKG_BUNDLE_FLAGS, not the
    // Core-v2 serializer (flags=0 PJSON1).
    std::vector<unsigned char> bundle_bytes;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeBtxBundle(pkg.payload, bundle_bytes, err), err);
    BOOST_CHECK_EQUAL(std::memcmp(bundle_bytes.data(), modelnet::BTXPKG_MAGIC, 8), 0);
    BOOST_CHECK_EQUAL(ReadLE32(bundle_bytes.data() + 8), modelnet::BTXPKG_BUNDLE_FLAGS);
    BOOST_CHECK(bundle_bytes != desc);
    {
        modelnet::DecodedBtxPackage as_pkg;
        const bool accepted = modelnet::DecodeBtxPackage(bundle_bytes, as_pkg, err);
        BOOST_CHECK_MESSAGE(
            !accepted,
            "AHP-COMP-03: bundle-flagged JSON body must not decode as a Core-v2 package (no identity rewrite)");
    }

    UniValue bundle_view;
    BOOST_CHECK(!modelnet::DecodeBtxBundle(desc, bundle_view, err));
    BOOST_CHECK_EQUAL(err, "conflicting dual body");
    UniValue as_json;
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeBtxBundle(bundle_bytes, as_json, err), err);
    BOOST_REQUIRE(as_json.exists("core"));
    BOOST_CHECK_EQUAL(as_json["core"]["version"].getValStr(), "2");

    std::vector<unsigned char> zip{'P', 'K', 0x03, 0x04, 0x00, 0x00, 0x00, 0x00};
    zip.resize(80, 0);
    modelnet::DecodedBtxPackage zip_pkg;
    BOOST_CHECK(!modelnet::DecodeBtxPackage(zip, zip_pkg, err));
    BOOST_CHECK(!modelnet::LooksLikeBtxBundle(zip));
}

BOOST_AUTO_TEST_CASE(ahp_comp_04_helper_down)
{
    BOOST_TEST_MESSAGE("AHP-COMP-04 live production helper-down remains NOT_RUN; isolated evidence is modelnet_ahp_comp04_tests");
}

BOOST_AUTO_TEST_CASE(ahp_comp_05_modelnet_disabled_build)
{
    // AHP-COMP-05: monetary-only WITH_MODELNET=OFF. The dedicated script
    // compiles a throwaway probe with ENABLE_MODELNET unset (no second cmake
    // tree). A full second Release tree remains optional extra evidence.
    std::vector<fs::path> candidates;
#ifdef MODELNET_OFF_CHECK_SCRIPT
    candidates.push_back(fs::PathFromString(MODELNET_OFF_CHECK_SCRIPT));
#endif
    candidates.push_back(fs::PathFromString("../contrib/modelnet/check-with-modelnet-off.sh"));
    candidates.push_back(fs::PathFromString("contrib/modelnet/check-with-modelnet-off.sh"));
    fs::path script;
    for (const auto& c : candidates) {
        if (fs::exists(c)) {
            script = c;
            break;
        }
    }
    BOOST_REQUIRE_MESSAGE(!script.empty() && fs::exists(script),
                          "missing contrib/modelnet/check-with-modelnet-off.sh");
    const std::string cmd = "bash " + fs::PathToString(script) + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    BOOST_REQUIRE(pipe);
    std::string out;
    char buf[512];
    while (fgets(buf, sizeof(buf), pipe) != nullptr) out.append(buf);
    const int status = pclose(pipe);
    BOOST_TEST_MESSAGE(out);
    BOOST_REQUIRE_EQUAL(status, 0);
    BOOST_CHECK(out.find("WITH_MODELNET=OFF is the monetary-only build") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(ahp_comp_06_reference_is_not_native_evidence)
{
    // AHP-COMP-06 — Reference versus native evidence.
    //
    // The independent Python inspector (btx_package.py / test_package.py, 63
    // cases) reports frame_integrity PASS with
    // reference_scope=FRAMING_CANONICALIZATION_DOCUMENTS_STRUCTURAL_SEMANTICS_ONLY.
    // That MUST NOT be copied into the native AHP ledger as PASS for AUTH, INS,
    // ACQ, RUN, WAN, GUI, or PQ signatures. This native case proves only that
    // DecodeBtxPackage can read an UNSIGNED REGTEST fixture. It is not ML-DSA
    // verification, not client install, not live acquisition, not a runtime.
    const auto bytes = LoadBtx("model-agent.btx");
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeBtxPackage(bytes, pkg, err), err);
    BOOST_CHECK_EQUAL(pkg.package_core_id.Hex(), kModelAgentCoreId);
    BOOST_REQUIRE(pkg.payload.exists("signatures"));
    BOOST_CHECK_EQUAL(pkg.payload["signatures"].size(), 0U);
    BOOST_CHECK_EQUAL(pkg.core["network"].get_str(), "REGTEST");

    // Python inspect() keys are not package payload fields and must not appear.
    BOOST_CHECK(!pkg.payload.exists("frame_integrity"));
    BOOST_CHECK(!pkg.payload.exists("reference_scope"));
    BOOST_CHECK(!pkg.payload.exists("publisher_trust"));
    BOOST_CHECK(!pkg.payload.exists("native_uri_verification"));
    BOOST_CHECK(!pkg.payload.exists("model_bytes_verified"));
    BOOST_CHECK(!pkg.payload.exists("authorized_actions"));
    BOOST_CHECK(!pkg.payload.exists("installed_software"));
    BOOST_CHECK(!pkg.payload.exists("executed_runtime"));

    BOOST_TEST_MESSAGE("AHP-COMP-06: Python 63 reference tests != native PQ/install/WAN/runtime PASS");
}

BOOST_AUTO_TEST_SUITE_END()
