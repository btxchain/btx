// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Lane D BTX-AHP-001 INS (AHP-INS-01..10). Plan only: does not install.
// Coordinator wires this file into test_btx later. Do not call helper, wallet,
// or production btxd.

#include <crypto/hex_base.h>
#include <crypto/sha384.h>
#include <modelnet/package_install.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_ahp_ins_tests, BasicTestingSetup)

namespace {

std::string HexId(char nibble) { return std::string(96, nibble); }

std::string Sha384Hex(const std::string& bytes)
{
    CSHA384 h;
    h.Write(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
    unsigned char d[48];
    h.Finalize(d);
    return HexStr(Span<const unsigned char>{d, 48});
}

UniValue Caps(const std::vector<std::string>& names)
{
    UniValue a(UniValue::VARR);
    for (const auto& n : names) a.push_back(n);
    return a;
}

UniValue AgentCore(bool appoint_installer)
{
    UniValue core(UniValue::VOBJ);
    core.pushKV("version", 2);
    core.pushKV("network", "REGTEST");
    core.pushKV("package_type", "MODEL");
    core.pushKV("label", "ahp-ins");
    UniValue cr(UniValue::VOBJ);
    cr.pushKV("distribution_id", "btx-model-tools");
    cr.pushKV("minimum_client_version", "0.34.8");
    cr.pushKV("required_capabilities", Caps({"BTXPKG_CORE_V2", "AGENT_HANDOFF_V1"}));
    if (appoint_installer) {
        cr.pushKV("installer_key", "package-appointed-ml-dsa");
        cr.pushKV("installer_url", "https://evil.test/btx-installer");
        cr.pushKV("installer_sha384", HexId('e'));
        cr.pushKV("client_binary_url", "https://evil.test/btxd");
        cr.pushKV("client_artifact_sha384", HexId('e'));
    }
    UniValue ah(UniValue::VOBJ);
    ah.pushKV("version", 1);
    ah.pushKV("entry_document", "AGENTS.md");
    ah.pushKV("client_requirements", cr);
    core.pushKV("agent_handoff", ah);
    if (appoint_installer) {
        core.pushKV("software_trust_root", "package-appointed-root");
        core.pushKV("client_artifact_sha384", HexId('e'));
    }
    return core;
}

UniValue Release(const std::string& version, const std::vector<std::string>& caps, const std::string& artifact,
                 const std::string& size)
{
    UniValue r(UniValue::VOBJ);
    r.pushKV("distribution_id", "btx-model-tools");
    r.pushKV("release_version", version);
    r.pushKV("platform", "linux-x86_64");
    r.pushKV("artifact_sha384", artifact);
    r.pushKV("artifact_size_bytes", size);
    r.pushKV("capabilities", Caps(caps));
    r.pushKV("independent_trust_ref", "org-pin:btx-model-tools");
    r.pushKV("verified_release_metadata_id", HexId('b'));
    UniValue hosts(UniValue::VARR);
    hosts.push_back("releases.test.invalid");
    r.pushKV("download_hosts", hosts);
    return r;
}

UniValue Catalogue(const std::vector<UniValue>& releases)
{
    UniValue cat(UniValue::VOBJ);
    cat.pushKV("distribution_id", "btx-model-tools");
    cat.pushKV("independent_trust_ref", "org-pin:btx-model-tools");
    UniValue arr(UniValue::VARR);
    for (const auto& r : releases) arr.push_back(r);
    cat.pushKV("releases", arr);
    return cat;
}

UniValue UserPolicy(const fs::path& dest, const std::string& served = {})
{
    UniValue p(UniValue::VOBJ);
    p.pushKV("platform", "linux-x86_64");
    p.pushKV("installation_directory", dest.utf8string());
    p.pushKV("privileges", "USER_ONLY");
    p.pushKV("expires_at_ms", "4102444800000");
    if (!served.empty()) p.pushKV("served_bytes", served);
    return p;
}

bool TrustRequiredCode(const std::string& code)
{
    return code == "CLIENT_TRUST_REQUIRED" || code == "TRUST_REQUIRED";
}

} // namespace

BOOST_AUTO_TEST_CASE(ahp_ins_01_no_existing_btx_client)
{
    const std::string trusted_bytes = "trusted-client-bytes";
    const std::string trusted_hash = Sha384Hex(trusted_bytes);
    const std::string trusted_size = std::to_string(trusted_bytes.size());

    const UniValue core = AgentCore(/*appoint_installer=*/true);
    UniValue cat = Catalogue({
        Release("9.9.9", {"BTXPKG_CORE_V2"}, HexId('c'), "99"),
        Release("0.34.8", {"BTXPKG_CORE_V2", "AGENT_HANDOFF_V1"}, trusted_hash, trusted_size),
    });
    const fs::path dest = m_path_root / "ahp-ins-01-must-not-create";
    BOOST_CHECK(!fs::exists(dest));

    modelnet::InstallPlan plan;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxClientInstall(core, cat, UserPolicy(dest), plan, code, err),
                          err + " [" + code + "]");
    BOOST_CHECK(code.empty());
    BOOST_CHECK(!plan.trust_required);
    BOOST_CHECK_EQUAL(plan.distribution_id, "btx-model-tools");
    BOOST_CHECK_EQUAL(plan.release_version, "0.34.8");
    BOOST_CHECK_EQUAL(plan.platform, "linux-x86_64");
    BOOST_CHECK_EQUAL(plan.artifact_sha384_hex, trusted_hash);
    BOOST_CHECK_EQUAL(plan.plan_id_hex.size(), 96);
    BOOST_CHECK_EQUAL(plan.json["plan_id"].get_str(), plan.plan_id_hex);
    BOOST_CHECK_EQUAL(plan.json["privileges"].get_str(), "USER_ONLY");
    BOOST_CHECK_EQUAL(plan.json["independent_trust_ref"].get_str(), "org-pin:btx-model-tools");
    BOOST_CHECK_EQUAL(plan.json["artifact_sha384"].get_str(), trusted_hash);
    BOOST_CHECK(plan.json["independent_trust_ref"].get_str() != "package-appointed-root");
    BOOST_CHECK(plan.json["artifact_sha384"].get_str() != HexId('e'));
    BOOST_CHECK(!plan.json.exists("installer_key"));
    BOOST_CHECK(!plan.json.exists("software_trust_root"));
    BOOST_CHECK(!plan.json.exists("authorization_ref"));
    BOOST_CHECK(!fs::exists(dest));
}

BOOST_AUTO_TEST_CASE(ahp_ins_05_binary_mismatch)
{
    const std::string trusted_bytes = "trusted-client-bytes";
    const std::string trusted_hash = Sha384Hex(trusted_bytes);
    const std::string trusted_size = std::to_string(trusted_bytes.size());
    const UniValue core = AgentCore(/*appoint_installer=*/false);
    const UniValue cat =
        Catalogue({Release("0.34.8", {"BTXPKG_CORE_V2", "AGENT_HANDOFF_V1"}, trusted_hash, trusted_size)});

    const fs::path dest = m_path_root / "ahp-ins-05-staged";
    BOOST_CHECK(!fs::exists(dest));

    modelnet::InstallPlan plan;
    std::string code, err;
    const UniValue policy = UserPolicy(dest, "evil-bytes-not-the-trusted-artifact");
    BOOST_CHECK(!modelnet::PlanBtxClientInstall(core, cat, policy, plan, code, err));
    BOOST_CHECK_EQUAL(code, "ARTIFACT_DIGEST_MISMATCH");
    BOOST_CHECK(plan.trust_required);
    BOOST_CHECK(plan.plan_id_hex.empty());
    BOOST_CHECK(!fs::exists(dest));

    UniValue size_mismatch = UserPolicy(dest);
    size_mismatch.pushKV("candidate_artifact_sha384", trusted_hash);
    size_mismatch.pushKV("candidate_artifact_size_bytes", "1");
    BOOST_CHECK(!modelnet::PlanBtxClientInstall(core, cat, size_mismatch, plan, code, err));
    BOOST_CHECK_EQUAL(code, "ARTIFACT_DIGEST_MISMATCH");
    BOOST_CHECK(!fs::exists(dest));
}

BOOST_AUTO_TEST_CASE(ahp_ins_09_first_use_missing_trust)
{
    const UniValue core = AgentCore(/*appoint_installer=*/true);
    const fs::path dest = m_path_root / "ahp-ins-09-must-not-create";
    BOOST_CHECK(!fs::exists(dest));
    const UniValue policy = UserPolicy(dest);

    auto expect_trust_required = [&](const UniValue& cat) {
        modelnet::InstallPlan plan;
        std::string code, err;
        BOOST_CHECK(!modelnet::PlanBtxClientInstall(core, cat, policy, plan, code, err));
        BOOST_CHECK(TrustRequiredCode(code));
        BOOST_CHECK_EQUAL(err, "TRUST_REQUIRED");
        BOOST_CHECK(plan.trust_required);
        BOOST_CHECK(plan.plan_id_hex.empty());
        BOOST_CHECK(plan.artifact_sha384_hex.empty());
        BOOST_CHECK(!plan.json.exists("independent_trust_ref") ||
                    plan.json["independent_trust_ref"].get_str() != "package-appointed-root");
        BOOST_CHECK(!fs::exists(dest));
    };

    expect_trust_required(UniValue());
    expect_trust_required(UniValue(UniValue::VOBJ));
    expect_trust_required(UniValue(UniValue::VARR));
    UniValue empty_releases(UniValue::VOBJ);
    empty_releases.pushKV("releases", UniValue(UniValue::VARR));
    expect_trust_required(empty_releases);

    UniValue trust_pkg(UniValue::VOBJ);
    trust_pkg.pushKV("platform", "linux-x86_64");
    trust_pkg.pushKV("installation_directory", dest.utf8string());
    trust_pkg.pushKV("expires_at_ms", "4102444800000");
    trust_pkg.pushKV("trust_package_hashes", true);
    const std::string trusted_bytes = "trusted-client-bytes";
    UniValue cat = Catalogue({Release("0.34.8", {"BTXPKG_CORE_V2", "AGENT_HANDOFF_V1"}, Sha384Hex(trusted_bytes),
                                      std::to_string(trusted_bytes.size()))});
    modelnet::InstallPlan plan;
    std::string code, err;
    BOOST_CHECK(!modelnet::PlanBtxClientInstall(core, cat, trust_pkg, plan, code, err));
    BOOST_CHECK(TrustRequiredCode(code));
    BOOST_CHECK(plan.trust_required);
    BOOST_CHECK(!fs::exists(dest));
}

BOOST_AUTO_TEST_CASE(ahp_ins_02_reuse_installed)
{
    const std::string trusted_bytes = "trusted-client-bytes";
    const std::string trusted_hash = Sha384Hex(trusted_bytes);
    const std::string trusted_size = std::to_string(trusted_bytes.size());
    const UniValue core = AgentCore(/*appoint_installer=*/false);
    const UniValue cat =
        Catalogue({Release("0.34.8", {"BTXPKG_CORE_V2", "AGENT_HANDOFF_V1"}, trusted_hash, trusted_size)});

    const fs::path dest = m_path_root / "ahp-ins-02-must-not-create";
    BOOST_CHECK(!fs::exists(dest));

    UniValue policy = UserPolicy(dest);
    UniValue installed(UniValue::VOBJ);
    installed.pushKV("distribution_id", "btx-model-tools");
    installed.pushKV("artifact_sha384", trusted_hash);
    installed.pushKV("release_version", "0.34.8");
    installed.pushKV("capabilities", Caps({"BTXPKG_CORE_V2", "AGENT_HANDOFF_V1"}));
    policy.pushKV("installed_client", installed);

    modelnet::InstallPlan plan;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxClientInstall(core, cat, policy, plan, code, err),
                          err + " [" + code + "]");
    BOOST_CHECK(code.empty());
    BOOST_CHECK(!plan.trust_required);
    BOOST_CHECK_EQUAL(plan.release_version, "0.34.8");
    BOOST_CHECK(plan.json["reused_installed"].isTrue());
    BOOST_CHECK(plan.json["download_hosts"].empty() || plan.json["network_required"].isFalse());
    BOOST_CHECK(!fs::exists(dest));
}

BOOST_AUTO_TEST_CASE(ahp_ins_03_version_versus_capability)
{
    const std::string trusted_bytes = "trusted-client-bytes";
    const std::string trusted_hash = Sha384Hex(trusted_bytes);
    const std::string trusted_size = std::to_string(trusted_bytes.size());
    const UniValue core = AgentCore(/*appoint_installer=*/false);
    const UniValue cat = Catalogue({
        Release("9.9.9", {"BTXPKG_CORE_V2"}, HexId('c'), "99"),
        Release("0.34.8", {"BTXPKG_CORE_V2", "AGENT_HANDOFF_V1"}, trusted_hash, trusted_size),
    });

    const fs::path dest = m_path_root / "ahp-ins-03-must-not-create";
    BOOST_CHECK(!fs::exists(dest));

    modelnet::InstallPlan plan;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxClientInstall(core, cat, UserPolicy(dest), plan, code, err),
                          err + " [" + code + "]");
    BOOST_CHECK(code.empty());
    BOOST_CHECK(plan.release_version != "9.9.9");
    BOOST_CHECK_EQUAL(plan.release_version, "0.34.8");
    BOOST_CHECK_EQUAL(plan.artifact_sha384_hex, trusted_hash);
    BOOST_CHECK(!fs::exists(dest));
}

BOOST_AUTO_TEST_CASE(ahp_ins_04_freeze_and_rollback)
{
    const std::string trusted_bytes = "trusted-client-bytes";
    const std::string trusted_hash = Sha384Hex(trusted_bytes);
    const std::string trusted_size = std::to_string(trusted_bytes.size());
    UniValue core = AgentCore(/*appoint_installer=*/false);
    UniValue cr = core["agent_handoff"]["client_requirements"];
    cr.pushKV("minimum_client_version", "0.34.0");
    UniValue ah = core["agent_handoff"];
    ah.pushKV("client_requirements", cr);
    core.pushKV("agent_handoff", ah);
    const UniValue cat =
        Catalogue({Release("0.34.7", {"BTXPKG_CORE_V2", "AGENT_HANDOFF_V1"}, trusted_hash, trusted_size)});

    const fs::path dest = m_path_root / "ahp-ins-04-must-not-create";
    BOOST_CHECK(!fs::exists(dest));

    UniValue floor = UserPolicy(dest);
    floor.pushKV("local_floor_version", "0.34.8");
    modelnet::InstallPlan plan;
    std::string code, err;
    BOOST_CHECK(!modelnet::PlanBtxClientInstall(core, cat, floor, plan, code, err));
    BOOST_CHECK_EQUAL(code, "INSTALL_ROLLBACK_FORBIDDEN");
    BOOST_CHECK(plan.plan_id_hex.empty());
    BOOST_CHECK(!fs::exists(dest));

    UniValue recovery = floor;
    recovery.pushKV("authorized_recovery", true);
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxClientInstall(core, cat, recovery, plan, code, err),
                          err + " [" + code + "]");
    BOOST_CHECK(code.empty());
    BOOST_CHECK_EQUAL(plan.release_version, "0.34.7");
    BOOST_CHECK(!fs::exists(dest));

    const UniValue cat_current =
        Catalogue({Release("0.34.8", {"BTXPKG_CORE_V2", "AGENT_HANDOFF_V1"}, trusted_hash, trusted_size)});
    UniValue expired = UserPolicy(dest);
    expired.pushKV("expires_at_ms", "1");
    expired.pushKV("now_ms", "2");
    BOOST_CHECK(!modelnet::PlanBtxClientInstall(core, cat_current, expired, plan, code, err));
    BOOST_CHECK_EQUAL(code, "INSTALL_METADATA_EXPIRED");
    BOOST_CHECK(plan.plan_id_hex.empty());
    BOOST_CHECK(!fs::exists(dest));
}

BOOST_AUTO_TEST_CASE(ahp_ins_06_unsafe_archive)
{
    std::string err;
    BOOST_CHECK(!modelnet::InstallArchiveEntryAllowed("../etc/passwd", false, false, err));
    BOOST_CHECK(!modelnet::InstallArchiveEntryAllowed("btx-model", true, false, err));
    BOOST_CHECK(!modelnet::InstallArchiveEntryAllowed("btx-model", false, true, err));
    BOOST_CHECK(modelnet::InstallArchiveEntryAllowed("btx-model", false, false, err));
}

BOOST_AUTO_TEST_CASE(ahp_ins_07_atomic_failure)
{
    bool resume = true;
    bool purge = false;
    std::string err_code;

    BOOST_CHECK(modelnet::InstallStagingResumeOrPurge("download", false, resume, purge, err_code));
    BOOST_CHECK(purge);
    BOOST_CHECK(!resume);

    resume = false;
    purge = true;
    BOOST_CHECK(modelnet::InstallStagingResumeOrPurge("verify", true, resume, purge, err_code));
    BOOST_CHECK(resume);
    BOOST_CHECK(!purge);

    resume = true;
    purge = false;
    BOOST_CHECK(modelnet::InstallStagingResumeOrPurge("promote", false, resume, purge, err_code));
    BOOST_CHECK(purge);
}

BOOST_AUTO_TEST_CASE(ahp_ins_08_privilege_escalation)
{
    const std::string trusted_bytes = "trusted-client-bytes";
    const std::string trusted_hash = Sha384Hex(trusted_bytes);
    const std::string trusted_size = std::to_string(trusted_bytes.size());
    const UniValue core = AgentCore(/*appoint_installer=*/false);
    const UniValue cat =
        Catalogue({Release("0.34.8", {"BTXPKG_CORE_V2", "AGENT_HANDOFF_V1"}, trusted_hash, trusted_size)});

    const fs::path dest = m_path_root / "ahp-ins-08-must-not-create";
    BOOST_CHECK(!fs::exists(dest));

    auto expect_approval = [&](const UniValue& policy, const fs::path& watch) {
        modelnet::InstallPlan plan;
        std::string code, err;
        BOOST_CHECK(!modelnet::PlanBtxClientInstall(core, cat, policy, plan, code, err));
        BOOST_CHECK_EQUAL(code, "INSTALL_APPROVAL_REQUIRED");
        BOOST_CHECK(plan.plan_id_hex.empty());
        BOOST_CHECK(!fs::exists(watch));
    };

    UniValue system_priv = UserPolicy(dest);
    system_priv.pushKV("privileges", "SYSTEM");
    expect_approval(system_priv, dest);

    UniValue usr_bin = UserPolicy(dest);
    usr_bin.pushKV("installation_directory", "/usr/bin");
    expect_approval(usr_bin, dest);

    const fs::path real = m_path_root / "libexec" / "btxd.real";
    expect_approval(UserPolicy(real), real);
    BOOST_CHECK(!fs::exists(dest));
}

BOOST_AUTO_TEST_CASE(ahp_ins_10_offline_cache)
{
    const std::string trusted_bytes = "trusted-client-bytes";
    const std::string trusted_hash = Sha384Hex(trusted_bytes);
    const std::string trusted_size = std::to_string(trusted_bytes.size());
    const UniValue core = AgentCore(/*appoint_installer=*/false);
    const UniValue cat =
        Catalogue({Release("0.34.8", {"BTXPKG_CORE_V2", "AGENT_HANDOFF_V1"}, trusted_hash, trusted_size)});

    const fs::path dest = m_path_root / "ahp-ins-10-must-not-create";
    BOOST_CHECK(!fs::exists(dest));

    UniValue policy = UserPolicy(dest);
    policy.pushKV("offline_cache", true);
    policy.pushKV("cached_artifact_sha384", trusted_hash);

    modelnet::InstallPlan plan;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxClientInstall(core, cat, policy, plan, code, err),
                          err + " [" + code + "]");
    BOOST_CHECK(code.empty());
    BOOST_CHECK(!plan.trust_required);
    BOOST_CHECK(plan.json["network_required"].isFalse());
    BOOST_CHECK(!fs::exists(dest));
}

BOOST_AUTO_TEST_SUITE_END()
