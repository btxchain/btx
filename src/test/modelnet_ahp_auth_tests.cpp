// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// AHP-AUTH-01..10 native ML-DSA-44 over the 48-byte package_core_id.
// Cryptographic PASS is never publisher_trust or software-distribution trust.

#include <crypto/hex_base.h>
#include <modelnet/identity.h>
#include <modelnet/package_core.h>
#include <modelnet/package_install.h>
#include <modelnet/package_runtime.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <iterator>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_ahp_auth_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> ReadBytes(const fs::path& p)
{
    std::ifstream in{p, std::ios::binary};
    BOOST_REQUIRE(in);
    const std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return std::vector<unsigned char>(raw.begin(), raw.end());
}

fs::path FixtureDir()
{
#ifdef MODELNET_AHP_FIXTURE_DIR
    return fs::PathFromString(MODELNET_AHP_FIXTURE_DIR);
#else
    return fs::PathFromString(std::string{__FILE__}).parent_path() / "data" / "agent-package";
#endif
}

Span<const unsigned char> CoreMsg(const modelnet::Digest48& core_id)
{
    return Span<const unsigned char>{core_id.data.data(), core_id.data.size()};
}

UniValue SignCoreBytes(const modelnet::Digest48& core_id, const std::vector<unsigned char>& pk,
                       const std::vector<unsigned char>& sk, std::vector<unsigned char>& sig)
{
    std::string err;
    BOOST_REQUIRE(modelnet::SignMlDsa44(sk, CoreMsg(core_id), sig, err));
    UniValue s(UniValue::VOBJ);
    s.pushKV("scope", "PACKAGE_CORE");
    s.pushKV("algorithm", "ML-DSA-44");
    s.pushKV("signer_id", modelnet::PublisherId(pk).Hex());
    s.pushKV("public_key_hex", HexStr(pk));
    s.pushKV("signature_hex", HexStr(sig));
    return s;
}

UniValue SignCore(const modelnet::Digest48& core_id, const std::vector<unsigned char>& pk,
                  const std::vector<unsigned char>& sk)
{
    std::vector<unsigned char> sig;
    return SignCoreBytes(core_id, pk, sk, sig);
}

UniValue WithFirstResourceField(const UniValue& core, const char* field, const std::string& value)
{
    UniValue r = core["resources"][0];
    r.pushKV(field, value);
    UniValue resources(UniValue::VARR);
    resources.push_back(r);
    UniValue out = core;
    out.pushKV("resources", resources);
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(ahp_auth_01_real_signature_vector)
{
    const auto bytes = ReadBytes(FixtureDir() / "model-agent.btx");
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE(modelnet::DecodeBtxPackage(bytes, pkg, err));
    std::vector<unsigned char> pk, sk;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    BOOST_CHECK_EQUAL(pk.size(), modelnet::MLDSA44_PK);
    BOOST_CHECK_EQUAL(sk.size(), modelnet::MLDSA44_SK);
    const UniValue sig = SignCore(pkg.package_core_id, pk, sk);
    BOOST_CHECK_EQUAL(sig["public_key_hex"].get_str().size(), modelnet::MLDSA44_PK * 2);
    BOOST_CHECK_EQUAL(sig["signature_hex"].get_str().size(), modelnet::MLDSA44_SIG * 2);
    std::string code;
    BOOST_REQUIRE_MESSAGE(modelnet::VerifyPackageCoreSignature(pkg.package_core_id, sig, code, err), err);
}

BOOST_AUTO_TEST_CASE(ahp_auth_02_signed_document_mutation)
{
    const auto bytes = ReadBytes(FixtureDir() / "model-agent.btx");
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE(modelnet::DecodeBtxPackage(bytes, pkg, err));
    std::vector<unsigned char> pk, sk;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    const UniValue sig = SignCore(pkg.package_core_id, pk, sk);
    UniValue mutated = pkg.core;
    pkg.core.pushKV("label", mutated["label"].get_str() + "x");
    modelnet::Digest48 new_id;
    BOOST_REQUIRE(modelnet::PackageCoreId(pkg.core, new_id, err));
    BOOST_CHECK(new_id.Hex() != pkg.package_core_id.Hex());
    std::string code;
    BOOST_CHECK(!modelnet::VerifyPackageCoreSignature(new_id, sig, code, err));
    BOOST_CHECK_EQUAL(code, "SIGNATURE_INVALID");
}

BOOST_AUTO_TEST_CASE(ahp_auth_03_signer_identity_mismatch)
{
    const auto bytes = ReadBytes(FixtureDir() / "model-agent.btx");
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE(modelnet::DecodeBtxPackage(bytes, pkg, err));
    std::vector<unsigned char> pk, sk;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    UniValue sig = SignCore(pkg.package_core_id, pk, sk);
    sig.pushKV("signer_id", std::string(96, 'a'));
    std::string code;
    BOOST_CHECK(!modelnet::VerifyPackageCoreSignature(pkg.package_core_id, sig, code, err));
    BOOST_CHECK_EQUAL(code, "SIGNER_IDENTITY_MISMATCH");
}

BOOST_AUTO_TEST_CASE(ahp_auth_04_unknown_self_signed_author)
{
    const auto bytes = ReadBytes(FixtureDir() / "model-agent.btx");
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE(modelnet::DecodeBtxPackage(bytes, pkg, err));
    std::vector<unsigned char> pk, sk;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    const UniValue sig = SignCore(pkg.package_core_id, pk, sk);
    std::string code;
    BOOST_REQUIRE(modelnet::VerifyPackageCoreSignature(pkg.package_core_id, sig, code, err));
    BOOST_CHECK(!pkg.payload.exists("publisher_trust"));
    BOOST_CHECK(!pkg.payload.exists("verified"));
    BOOST_CHECK_EQUAL(sig["signer_id"].get_str(), modelnet::PublisherId(pk).Hex());

    const fs::path dest = m_path_root / "ahp-auth-04-must-not-create";
    BOOST_CHECK(!fs::exists(dest));
    UniValue policy(UniValue::VOBJ);
    policy.pushKV("platform", "linux-x86_64");
    policy.pushKV("installation_directory", dest.utf8string());
    policy.pushKV("privileges", "USER_ONLY");
    policy.pushKV("expires_at_ms", "4102444800000");
    modelnet::InstallPlan install;
    BOOST_CHECK(!modelnet::PlanBtxClientInstall(pkg.core, UniValue(UniValue::VOBJ), policy, install, code, err));
    BOOST_CHECK(code == "CLIENT_TRUST_REQUIRED" || code == "TRUST_REQUIRED");
    BOOST_CHECK(install.trust_required);
    BOOST_CHECK(!fs::exists(dest));

    modelnet::RuntimePlan runtime;
    BOOST_CHECK(!modelnet::PlanBtxRuntime(pkg.core, UniValue(UniValue::VOBJ), UniValue(UniValue::VOBJ), runtime, code,
                                          err));
    BOOST_CHECK(!runtime.executes);
    BOOST_CHECK_MESSAGE(code != "SIGNATURE_INVALID",
                        "AHP-AUTH-04: cryptographic PASS is not publisher trust or install/run authority");
}

BOOST_AUTO_TEST_CASE(ahp_auth_05_observations_outside_core)
{
    const auto bytes = ReadBytes(FixtureDir() / "model-agent.btx");
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE(modelnet::DecodeBtxPackage(bytes, pkg, err));
    const modelnet::Digest48 id = pkg.package_core_id;
    UniValue obs(UniValue::VOBJ);
    obs.pushKV("funding", "stale");
    pkg.payload.pushKV("observations", UniValue(UniValue::VARR));
    pkg.payload.getKeys();
    UniValue observations(UniValue::VARR);
    observations.push_back(obs);
    pkg.payload.pushKV("observations", observations);
    modelnet::Digest48 again;
    BOOST_REQUIRE(modelnet::PackageCoreId(pkg.core, again, err));
    BOOST_CHECK_EQUAL(again.Hex(), id.Hex());
}

BOOST_AUTO_TEST_CASE(ahp_auth_06_provenance_not_authorship)
{
    const auto bytes = ReadBytes(FixtureDir() / "model-agent.btx");
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE(modelnet::DecodeBtxPackage(bytes, pkg, err));

    std::vector<unsigned char> lab_pk, lab_sk, mirror_pk, mirror_sk;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(lab_pk, lab_sk, err));
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(mirror_pk, mirror_sk, err));
    const modelnet::Digest48 lab_id = modelnet::PublisherId(lab_pk);
    const modelnet::Digest48 packager_id = modelnet::PublisherId(mirror_pk);
    BOOST_CHECK(lab_id.Hex() != packager_id.Hex());

    UniValue ah = pkg.core["agent_handoff"];
    UniValue channel_ref(UniValue::VOBJ);
    channel_ref.pushKV("publisher_id", lab_id.Hex());
    channel_ref.pushKV("channel", "lab.latest");
    ah.pushKV("channel_ref", channel_ref);
    pkg.core.pushKV("agent_handoff", ah);
    modelnet::Digest48 core_id;
    BOOST_REQUIRE(modelnet::PackageCoreId(pkg.core, core_id, err));

    std::vector<unsigned char> lab_self_sig;
    BOOST_REQUIRE(modelnet::SignMlDsa44(lab_sk, lab_pk, lab_self_sig, err));
    BOOST_CHECK(modelnet::VerifyMlDsa44(lab_pk, lab_pk, lab_self_sig));
    BOOST_CHECK(!modelnet::VerifyMlDsa44(mirror_pk, lab_pk, lab_self_sig));

    std::vector<unsigned char> mirror_sig;
    const UniValue sig = SignCoreBytes(core_id, mirror_pk, mirror_sk, mirror_sig);
    std::string code;
    BOOST_REQUIRE_MESSAGE(modelnet::VerifyPackageCoreSignature(core_id, sig, code, err), err);
    BOOST_CHECK(modelnet::VerifyMlDsa44(mirror_pk, CoreMsg(core_id), mirror_sig));
    BOOST_CHECK(!modelnet::VerifyMlDsa44(lab_pk, CoreMsg(core_id), mirror_sig));

    BOOST_CHECK_EQUAL(sig["signer_id"].get_str(), packager_id.Hex());
    BOOST_CHECK_EQUAL(pkg.core["agent_handoff"]["channel_ref"]["publisher_id"].get_str(), lab_id.Hex());
    BOOST_CHECK(sig["signer_id"].get_str() != pkg.core["agent_handoff"]["channel_ref"]["publisher_id"].get_str());
    BOOST_CHECK_EQUAL(pkg.core["resources"][0]["id"].get_str().size(), 96U);
    BOOST_CHECK(pkg.core["resources"][0]["id"].get_str() != packager_id.Hex());
    BOOST_CHECK(!pkg.payload.exists("publisher_trust"));
}

BOOST_AUTO_TEST_CASE(ahp_auth_07_root_substitution)
{
    const auto bytes = ReadBytes(FixtureDir() / "model-agent.btx");
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE(modelnet::DecodeBtxPackage(bytes, pkg, err));

    std::vector<unsigned char> attacker_pk, attacker_sk, distributor_pk, distributor_sk;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(attacker_pk, attacker_sk, err));
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(distributor_pk, distributor_sk, err));
    BOOST_CHECK(modelnet::PublisherId(attacker_pk).Hex() != modelnet::PublisherId(distributor_pk).Hex());

    UniValue notes(UniValue::VOBJ);
    notes.pushKV("client_binary_sha384", std::string(96, 'e'));
    notes.pushKV("matching_key_hex", HexStr(attacker_pk));

    std::vector<unsigned char> attacker_sig;
    const UniValue sig = SignCoreBytes(pkg.package_core_id, attacker_pk, attacker_sk, attacker_sig);
    std::string code;
    BOOST_REQUIRE_MESSAGE(modelnet::VerifyPackageCoreSignature(pkg.package_core_id, sig, code, err), err);
    BOOST_CHECK_MESSAGE(!modelnet::VerifyMlDsa44(distributor_pk, CoreMsg(pkg.package_core_id), attacker_sig),
                        "AHP-AUTH-07: package PASS is not software-distribution trust; installer remains TRUST_REQUIRED");

    std::vector<unsigned char> distributor_root_sig;
    BOOST_REQUIRE(modelnet::SignMlDsa44(distributor_sk, distributor_pk, distributor_root_sig, err));
    BOOST_CHECK(modelnet::VerifyMlDsa44(distributor_pk, distributor_pk, distributor_root_sig));
    BOOST_CHECK(!modelnet::VerifyMlDsa44(attacker_pk, distributor_pk, distributor_root_sig));
    BOOST_CHECK(notes["matching_key_hex"].get_str() == HexStr(attacker_pk));
    BOOST_CHECK(notes["matching_key_hex"].get_str() != HexStr(distributor_pk));
    BOOST_CHECK(!pkg.payload.exists("publisher_trust"));
}

BOOST_AUTO_TEST_CASE(ahp_auth_08_finite_multi_stage_authority)
{
    const auto bytes = ReadBytes(FixtureDir() / "model-agent.btx");
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE(modelnet::DecodeBtxPackage(bytes, pkg, err));
    std::vector<unsigned char> pk, sk, sig_bytes;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    const UniValue sig = SignCoreBytes(pkg.package_core_id, pk, sk, sig_bytes);
    std::string code;
    BOOST_REQUIRE(modelnet::VerifyPackageCoreSignature(pkg.package_core_id, sig, code, err));
    BOOST_REQUIRE(modelnet::VerifyPackageCoreSignature(pkg.package_core_id, sig, code, err));
    BOOST_CHECK(modelnet::VerifyMlDsa44(pk, CoreMsg(pkg.package_core_id), sig_bytes));

    modelnet::Digest48 changed_resource;
    BOOST_REQUIRE(modelnet::PackageCoreId(WithFirstResourceField(pkg.core, "id", std::string(96, 'f')),
                                          changed_resource, err));
    BOOST_CHECK(changed_resource.Hex() != pkg.package_core_id.Hex());
    BOOST_CHECK(!modelnet::VerifyPackageCoreSignature(changed_resource, sig, code, err));
    BOOST_CHECK_EQUAL(code, "SIGNATURE_INVALID");

    modelnet::Digest48 changed_bytes;
    BOOST_REQUIRE(modelnet::PackageCoreId(WithFirstResourceField(pkg.core, "size_bytes", "9999999999"),
                                          changed_bytes, err));
    BOOST_CHECK(changed_bytes.Hex() != pkg.package_core_id.Hex());
    BOOST_CHECK(changed_bytes.Hex() != changed_resource.Hex());
    BOOST_CHECK(!modelnet::VerifyPackageCoreSignature(changed_bytes, sig, code, err));
    BOOST_CHECK_EQUAL(code, "SIGNATURE_INVALID");
}

BOOST_AUTO_TEST_CASE(ahp_auth_09_unsigned_preview)
{
    const auto bytes = ReadBytes(FixtureDir() / "model-agent.btx");
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE(modelnet::DecodeBtxPackage(bytes, pkg, err));
    BOOST_REQUIRE(pkg.payload.exists("signatures"));
    BOOST_CHECK_EQUAL(pkg.payload["signatures"].size(), 0U);
    BOOST_CHECK(!pkg.payload.exists("publisher_trust"));
    BOOST_CHECK(!pkg.payload.exists("verified"));
    BOOST_CHECK(!pkg.payload.exists("installed_software"));
    BOOST_CHECK(!pkg.payload.exists("authorized_actions"));

    modelnet::Digest48 again;
    BOOST_REQUIRE(modelnet::PackageCoreId(pkg.core, again, err));
    BOOST_CHECK_EQUAL(again.Hex(), pkg.package_core_id.Hex());

    UniValue empty(UniValue::VOBJ);
    std::string code;
    BOOST_CHECK(!modelnet::VerifyPackageCoreSignature(pkg.package_core_id, empty, code, err));
    BOOST_CHECK_EQUAL(code, "SIGNATURE_INVALID");
}

BOOST_AUTO_TEST_CASE(ahp_auth_10_key_rotation_boundaries)
{
    const auto bytes = ReadBytes(FixtureDir() / "model-agent.btx");
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE(modelnet::DecodeBtxPackage(bytes, pkg, err));

    std::vector<unsigned char> author_pk, author_sk, publisher_pk, publisher_sk, successor_pk, successor_sk,
        distributor_pk, distributor_sk, attacker_pk, attacker_sk;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(author_pk, author_sk, err));
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(publisher_pk, publisher_sk, err));
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(successor_pk, successor_sk, err));
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(distributor_pk, distributor_sk, err));
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(attacker_pk, attacker_sk, err));

    const modelnet::Digest48 author_id = modelnet::PublisherId(author_pk);
    const modelnet::Digest48 publisher_id = modelnet::PublisherId(publisher_pk);
    const modelnet::Digest48 successor_id = modelnet::PublisherId(successor_pk);
    const modelnet::Digest48 distributor_id = modelnet::PublisherId(distributor_pk);
    const modelnet::Digest48 attacker_id = modelnet::PublisherId(attacker_pk);
    BOOST_CHECK(author_id.Hex() != publisher_id.Hex());
    BOOST_CHECK(publisher_id.Hex() != successor_id.Hex());
    BOOST_CHECK(publisher_id.Hex() != distributor_id.Hex());
    BOOST_CHECK(successor_id.Hex() != distributor_id.Hex());
    BOOST_CHECK(attacker_id.Hex() != distributor_id.Hex());

    std::vector<unsigned char> author_pkg_sig;
    const UniValue author_sig = SignCoreBytes(pkg.package_core_id, author_pk, author_sk, author_pkg_sig);
    std::string code;
    BOOST_REQUIRE(modelnet::VerifyPackageCoreSignature(pkg.package_core_id, author_sig, code, err));

    std::vector<unsigned char> rotation_sig;
    BOOST_REQUIRE(modelnet::SignMlDsa44(publisher_sk, successor_pk, rotation_sig, err));
    BOOST_CHECK(modelnet::VerifyMlDsa44(publisher_pk, successor_pk, rotation_sig));
    BOOST_CHECK(!modelnet::VerifyMlDsa44(publisher_pk, attacker_pk, rotation_sig));
    BOOST_CHECK(!modelnet::VerifyMlDsa44(distributor_pk, successor_pk, rotation_sig));
    BOOST_CHECK(!modelnet::VerifyMlDsa44(publisher_pk, distributor_pk, rotation_sig));

    std::vector<unsigned char> successor_pkg_sig;
    const UniValue successor_sig = SignCoreBytes(pkg.package_core_id, successor_pk, successor_sk, successor_pkg_sig);
    BOOST_REQUIRE(modelnet::VerifyPackageCoreSignature(pkg.package_core_id, successor_sig, code, err));
    BOOST_CHECK_EQUAL(successor_sig["signer_id"].get_str(), successor_id.Hex());
    BOOST_CHECK(successor_sig["signer_id"].get_str() != distributor_id.Hex());

    std::vector<unsigned char> distributor_root_sig;
    BOOST_REQUIRE(modelnet::SignMlDsa44(distributor_sk, distributor_pk, distributor_root_sig, err));
    BOOST_CHECK(modelnet::VerifyMlDsa44(distributor_pk, distributor_pk, distributor_root_sig));
    BOOST_CHECK(!modelnet::VerifyMlDsa44(successor_pk, distributor_pk, distributor_root_sig));
    BOOST_CHECK(!modelnet::VerifyMlDsa44(attacker_pk, distributor_pk, distributor_root_sig));

    std::vector<unsigned char> attacker_pkg_sig;
    const UniValue attacker_sig = SignCoreBytes(pkg.package_core_id, attacker_pk, attacker_sk, attacker_pkg_sig);
    BOOST_REQUIRE(modelnet::VerifyPackageCoreSignature(pkg.package_core_id, attacker_sig, code, err));
    BOOST_CHECK(!modelnet::VerifyMlDsa44(publisher_pk, attacker_pk, rotation_sig));
    BOOST_CHECK(!modelnet::VerifyMlDsa44(distributor_pk, CoreMsg(pkg.package_core_id), attacker_pkg_sig));
    BOOST_CHECK_EQUAL(modelnet::PublisherId(distributor_pk).Hex(), distributor_id.Hex());
    BOOST_CHECK(!pkg.payload.exists("publisher_trust"));
}

BOOST_AUTO_TEST_SUITE_END()
