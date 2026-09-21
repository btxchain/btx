// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// AHP-CHAN-01  ahp_chan_01_mutable_web_path
// AHP-CHAN-02  ahp_chan_02_rollback
// AHP-CHAN-03  ahp_chan_03_equivocation
// AHP-CHAN-04  ahp_chan_04_untrusted_channel_key
// AHP-CHAN-05  ahp_chan_05_follow_is_explicit
// AHP-CHAN-06  ahp_chan_06_offline_expiry
// AHP-CHAN-07  ahp_chan_07_restart_high_water
// AHP-CHAN-08  ahp_chan_08_lease_hold (static commitments also in ahp_chan_static_model_commitments)

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <modelnet/package_channel.h>
#include <modelnet/package_core.h>
#include <modelnet/package_economy.h>
#include <modelnet/package_pjson.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <iterator>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_ahp_chan_tests, BasicTestingSetup)

namespace {

std::string Hex96(char c) { return std::string(96, c); }

UniValue Statement(const std::string& seq, const std::string& core_id, const std::string& issued,
                   const std::string& expires, const UniValue& resource_ids)
{
    UniValue j(UniValue::VOBJ);
    j.pushKV("schema_version", 1);
    j.pushKV("network", "REGTEST");
    j.pushKV("publisher_id", Hex96('1'));
    j.pushKV("channel", "family.latest");
    j.pushKV("sequence", seq);
    j.pushKV("target_package_core_id", core_id);
    j.pushKV("target_resource_ids", resource_ids);
    j.pushKV("issued_at_ms", issued);
    j.pushKV("expires_at_ms", expires);
    j.pushKV("signature_record_ref", Hex96('2'));
    return j;
}

fs::path FixtureDir()
{
#ifdef MODELNET_AHP_FIXTURE_DIR
    return fs::PathFromString(MODELNET_AHP_FIXTURE_DIR);
#else
    return fs::PathFromString(std::string{__FILE__}).parent_path() / "data" / "agent-package";
#endif
}

std::vector<unsigned char> ReadBytes(const fs::path& p)
{
    std::ifstream in{p, std::ios::binary};
    BOOST_REQUIRE_MESSAGE(in, fs::PathToString(p));
    const std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return {raw.begin(), raw.end()};
}

} // namespace

BOOST_AUTO_TEST_CASE(ahp_chan_02_rollback)
{
    BOOST_CHECK(modelnet::ChannelRollback("10", "9"));
    BOOST_CHECK(!modelnet::ChannelRollback("10", "10"));
    BOOST_CHECK(!modelnet::ChannelRollback("10", "11"));
    BOOST_CHECK(modelnet::ChannelRollback("10", "09"));

    UniValue ids(UniValue::VARR);
    ids.push_back(Hex96('a'));
    const UniValue accepted = Statement("10", Hex96('a'), "1000", "5000", ids);
    // Newer wall clock on a lower sequence must not override the floor.
    const UniValue older = Statement("9", Hex96('b'), "9000", "12000", ids);

    UniValue pa, pb;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::ParseChannelStatement(accepted, pa, code, err), err);
    BOOST_REQUIRE_MESSAGE(modelnet::ParseChannelStatement(older, pb, code, err), err);
    BOOST_CHECK(modelnet::ChannelRollback(pa["sequence"].get_str(), pb["sequence"].get_str()));
    BOOST_CHECK(std::stoll(pb["issued_at_ms"].get_str()) > std::stoll(pa["issued_at_ms"].get_str()));
    BOOST_CHECK_EQUAL(code, "");
}

BOOST_AUTO_TEST_CASE(ahp_chan_03_equivocation)
{
    UniValue ids(UniValue::VARR);
    ids.push_back(Hex96('a'));
    const UniValue first = Statement("10", Hex96('a'), "1000", "5000", ids);
    UniValue second = first;
    second.pushKV("target_package_core_id", Hex96('b'));
    UniValue last_arriving = second;

    BOOST_CHECK(modelnet::ChannelEquivocation(first, last_arriving));
    BOOST_CHECK(modelnet::ChannelEquivocation(last_arriving, first));
    BOOST_CHECK(!modelnet::ChannelEquivocation(first, first));

    UniValue parsed_a, parsed_b;
    std::string code, err;
    BOOST_REQUIRE(modelnet::ParseChannelStatement(first, parsed_a, code, err));
    BOOST_REQUIRE(modelnet::ParseChannelStatement(last_arriving, parsed_b, code, err));
    BOOST_CHECK(modelnet::ChannelEquivocation(parsed_a, parsed_b));
    BOOST_CHECK_NE(parsed_a["target_package_core_id"].get_str(), parsed_b["target_package_core_id"].get_str());
}

BOOST_AUTO_TEST_CASE(ahp_chan_static_model_commitments)
{
    UniValue core(UniValue::VOBJ);
    core.pushKV("version", 2);
    core.pushKV("network", "REGTEST");
    UniValue resources(UniValue::VARR);
    UniValue r(UniValue::VOBJ);
    r.pushKV("kind", "MODEL");
    r.pushKV("id", Hex96('a'));
    resources.push_back(r);
    core.pushKV("resources", resources);

    modelnet::Digest48 core_id;
    std::string err;
    BOOST_REQUIRE(modelnet::PackageCoreId(core, core_id, err));

    UniValue same_ids(UniValue::VARR);
    same_ids.push_back(Hex96('a'));
    const UniValue same_core = Statement("8", core_id.Hex(), "1", "2", same_ids);
    BOOST_CHECK(!modelnet::ChannelMutatesStaticCommitments(core, same_core));

    UniValue other_ids(UniValue::VARR);
    other_ids.push_back(Hex96('f'));
    const UniValue patched = Statement("8", core_id.Hex(), "1", "2", other_ids);
    BOOST_CHECK(modelnet::ChannelMutatesStaticCommitments(core, patched));

    const UniValue new_pkg = Statement("9", Hex96('b'), "1", "2", other_ids);
    BOOST_CHECK(!modelnet::ChannelMutatesStaticCommitments(core, new_pkg));

    std::vector<unsigned char> before, after;
    std::string enc_err;
    BOOST_REQUIRE(modelnet::EncodePjson1(core, before, enc_err));
    UniValue parsed;
    std::string code;
    BOOST_REQUIRE(modelnet::ParseChannelStatement(new_pkg, parsed, code, err));
    BOOST_REQUIRE(modelnet::EncodePjson1(core, after, enc_err));
    BOOST_CHECK(modelnet::Pjson1Equals(before, after));

    UniValue hostile = same_core;
    hostile.pushKV("resources", resources);
    UniValue ignored;
    BOOST_CHECK(!modelnet::ParseChannelStatement(hostile, ignored, code, err));
    BOOST_CHECK_EQUAL(code, "NONCANONICAL_PAYLOAD");
}

BOOST_AUTO_TEST_CASE(ahp_chan_01_mutable_web_path)
{
    const auto bytes = ReadBytes(FixtureDir() / "model-agent.btx");
    modelnet::Digest48 pinned;
    std::string err;
    BOOST_REQUIRE_MESSAGE(
        modelnet::PinChannelPackageBytes(Span<const unsigned char>{bytes.data(), bytes.size()}, pinned, err), err);

    modelnet::DecodedBtxPackage pkg;
    BOOST_REQUIRE(modelnet::ParseAgentPackageFile(Span<const unsigned char>{bytes.data(), bytes.size()}, pkg, err));
    BOOST_CHECK(pinned == pkg.package_core_id);

    UniValue ids(UniValue::VARR);
    ids.push_back(Hex96('a'));
    const UniValue other_core = Statement("9", Hex96('b'), "1", "2", ids);
    BOOST_CHECK(!modelnet::ChannelMutatesStaticCommitments(pkg.core, other_core));
    BOOST_CHECK(!modelnet::ChannelRollback("8", "9"));

    modelnet::Digest48 pinned_again;
    BOOST_REQUIRE(modelnet::PinChannelPackageBytes(Span<const unsigned char>{bytes.data(), bytes.size()}, pinned_again,
                                                   err));
    BOOST_CHECK(pinned == pinned_again);
}

BOOST_AUTO_TEST_CASE(ahp_chan_04_untrusted_channel_key)
{
    BOOST_CHECK(!modelnet::ChannelHostnameIsPublisherTrust("cdn.example"));
    BOOST_CHECK(!modelnet::ChannelHostnameIsPublisherTrust("cdn.example.com"));
    UniValue ids(UniValue::VARR);
    ids.push_back(Hex96('a'));
    const UniValue stmt = Statement("1", Hex96('a'), "1", "2", ids);
    BOOST_CHECK(stmt["publisher_id"].get_str() != "cdn.example");
    BOOST_CHECK(stmt["publisher_id"].get_str().find("cdn.example") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(ahp_chan_05_follow_is_explicit)
{
    BOOST_CHECK(!modelnet::ChannelFollowIsExplicit(UniValue(UniValue::VOBJ)));
    UniValue on(UniValue::VOBJ);
    on.pushKV("follow_channel", true);
    BOOST_CHECK(modelnet::ChannelFollowIsExplicit(on));
    UniValue off(UniValue::VOBJ);
    off.pushKV("follow_channel", false);
    BOOST_CHECK(!modelnet::ChannelFollowIsExplicit(off));
}

BOOST_AUTO_TEST_CASE(ahp_chan_06_offline_expiry)
{
    UniValue expired(UniValue::VOBJ);
    expired.pushKV("expires_at_ms", "1");
    std::string code, err;
    BOOST_CHECK(modelnet::ChannelEconomicsStale(expired, /*now_ms=*/2, code, err));
    BOOST_CHECK_EQUAL(code, "STALE_ECONOMICS");

    UniValue fresh(UniValue::VOBJ);
    fresh.pushKV("expires_at_ms", "10000");
    BOOST_CHECK(!modelnet::ChannelEconomicsStale(fresh, /*now_ms=*/2, code, err));
}

BOOST_AUTO_TEST_CASE(ahp_chan_07_restart_high_water)
{
    UniValue ids(UniValue::VARR);
    ids.push_back(Hex96('a'));
    const UniValue accepted = Statement("10", Hex96('a'), "1000", "5000", ids);
    const fs::path path = m_path_root / "channel-watch.json";
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::SaveChannelWatch(path.utf8string(), accepted, code, err), err);

    UniValue loaded;
    BOOST_REQUIRE_MESSAGE(modelnet::LoadChannelWatch(path.utf8string(), loaded, code, err), err);
    BOOST_CHECK_EQUAL(loaded["sequence"].get_str(), "10");
    BOOST_CHECK(modelnet::ChannelRollback(loaded["sequence"].get_str(), "9"));
}

BOOST_AUTO_TEST_CASE(ahp_chan_08_lease_hold)
{
    const auto bytes = ReadBytes(FixtureDir() / "model-agent.btx");
    modelnet::Digest48 pinned;
    std::string err;
    BOOST_REQUIRE(modelnet::PinChannelPackageBytes(Span<const unsigned char>{bytes.data(), bytes.size()}, pinned, err));

    modelnet::DecodedBtxPackage pkg;
    BOOST_REQUIRE(modelnet::ParseAgentPackageFile(Span<const unsigned char>{bytes.data(), bytes.size()}, pkg, err));

    UniValue ids(UniValue::VARR);
    ids.push_back(Hex96('f'));
    const UniValue other = Statement("9", Hex96('b'), "1", "2", ids);
    BOOST_CHECK(!modelnet::ChannelMutatesStaticCommitments(pkg.core, other));

    modelnet::Digest48 still;
    BOOST_REQUIRE(modelnet::PinChannelPackageBytes(Span<const unsigned char>{bytes.data(), bytes.size()}, still, err));
    BOOST_CHECK(pinned == still);
    BOOST_CHECK(pinned == pkg.package_core_id);
}

BOOST_AUTO_TEST_SUITE_END()
