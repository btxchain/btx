// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/realm_channel.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <sstream>
#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_wan_tests, BasicTestingSetup)

namespace {

std::string FileText(const fs::path& path)
{
    std::ifstream in(path, std::ios::in);
    std::ostringstream text;
    text << in.rdbuf();
    return text.str();
}

} // namespace

BOOST_AUTO_TEST_CASE(quorum_shrink_rejection)
{
    modelnet::RealmRollout roll;
    std::string err;
    BOOST_CHECK(!roll.SetPolicy("realm", 0, {"a", "b", "c"}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_THRESHOLD");
    BOOST_CHECK(!roll.Quorum("realm", {"a", "b"}));
    BOOST_CHECK_EQUAL(roll.Threshold("realm"), 0);

    BOOST_REQUIRE(roll.SetPolicy("realm", 2, {"a", "b", "c"}, err));
    BOOST_CHECK_EQUAL(roll.Threshold("realm"), 2);
    BOOST_CHECK(roll.Quorum("realm", {"a", "b"}));
    BOOST_CHECK(!roll.Quorum("realm", {"a", "a"}));

    BOOST_REQUIRE(roll.RevokeAttestor("realm", "a", err));
    BOOST_CHECK_EQUAL(roll.Threshold("realm"), 2);
    // {a, b} used to meet threshold 2. After one revocation a shrunk threshold of 1
    // would still accept it, and {b} alone would meet that shrunk threshold. Both fail.
    BOOST_CHECK(!roll.Quorum("realm", {"a", "b"}));
    BOOST_CHECK(!roll.Quorum("realm", {"b"}));
    BOOST_CHECK(roll.Quorum("realm", {"b", "c"}));

    BOOST_CHECK(!roll.SetPolicy("realm", 1, {"b", "c"}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_THRESHOLD");
    BOOST_CHECK_EQUAL(roll.Threshold("realm"), 2);
    BOOST_CHECK(!roll.Quorum("realm", {"b"}));
}

BOOST_AUTO_TEST_CASE(wrong_realm)
{
    modelnet::RealmRollout roll;
    std::string err;
    BOOST_CHECK(roll.Attest("alpha", "signer-1", "alpha", err));
    BOOST_CHECK(!roll.Attest("alpha", "signer-1", "beta", err));
    BOOST_CHECK_EQUAL(err, "BTX035_REALM");
    BOOST_CHECK(!roll.Attest("", "signer-1", "", err));
    BOOST_CHECK_EQUAL(err, "BTX035_REALM");
}

BOOST_AUTO_TEST_CASE(stale_channel)
{
    modelnet::RealmRollout roll;
    std::string err;
    BOOST_CHECK(!roll.PublishChannel("realm", 1, "h1", err));
    BOOST_CHECK_EQUAL(err, "BTX035_GAP");
    BOOST_CHECK_EQUAL(roll.ChannelSequence("realm"), static_cast<int64_t>(-1));

    BOOST_REQUIRE(roll.PublishChannel("realm", 0, "h0", err));
    BOOST_REQUIRE(roll.PublishChannel("realm", 1, "h1", err));
    BOOST_CHECK_EQUAL(roll.ChannelSequence("realm"), static_cast<int64_t>(1));

    BOOST_CHECK(!roll.PublishChannel("realm", 1, "other", err));
    BOOST_CHECK_EQUAL(err, "BTX035_STALE");
    BOOST_CHECK_EQUAL(roll.ChannelSequence("realm"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(roll.ChannelBody("realm"), "h1");

    BOOST_CHECK(!roll.PublishChannel("realm", 0, "h0", err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    BOOST_CHECK(!roll.PublishChannel("realm", 3, "h3", err));
    BOOST_CHECK_EQUAL(err, "BTX035_GAP");
    BOOST_CHECK_EQUAL(roll.ChannelSequence("realm"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(roll.ChannelBody("realm"), "h1");

    BOOST_CHECK(roll.PublishChannel("realm", 2, "h2", err));
    BOOST_CHECK_EQUAL(roll.ChannelSequence("realm"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(roll.ChannelBody("realm"), "h2");
}

BOOST_AUTO_TEST_CASE(unknown_endpoint_counted)
{
    modelnet::RealmRollout roll;
    std::string err;
    BOOST_REQUIRE(roll.Observe("edge-1", "HEALTHY", err));
    BOOST_REQUIRE(roll.Observe("edge-2", "UNHEALTHY", err));
    BOOST_REQUIRE(roll.Observe("device-not-in-inventory", "UNKNOWN", err));
    BOOST_CHECK(!roll.Observe("ghost", "OFFLINE", err));
    BOOST_CHECK_EQUAL(err, "BTX035_OBSERVE");
    BOOST_CHECK(!roll.Observe("", "UNKNOWN", err));
    BOOST_CHECK_EQUAL(err, "BTX035_OBSERVE");

    const modelnet::FleetCounts st = roll.FleetStatus();
    BOOST_CHECK_EQUAL(st.healthy, 1);
    BOOST_CHECK_EQUAL(st.unhealthy, 1);
    BOOST_CHECK_EQUAL(st.unknown, 1);
    BOOST_CHECK_EQUAL(st.healthy + st.unhealthy + st.unknown, 3);
}

BOOST_AUTO_TEST_CASE(offline_cannot_advance)
{
    modelnet::RealmRollout roll;
    std::string err;
    BOOST_CHECK(!roll.AdvanceRingFromOffline(err));
    BOOST_CHECK_EQUAL(err, "BTX035_OFFLINE");
    BOOST_CHECK_EQUAL(roll.RingGeneration("realm"), static_cast<int64_t>(0));

    BOOST_CHECK(!roll.AdvanceRing("realm", "frozen-a", "current-b", 0, err));
    BOOST_CHECK_EQUAL(err, "BTX035_POLICY");
    BOOST_CHECK(!roll.AdvanceRing("realm", "policy", "policy", 2, err));
    BOOST_CHECK_EQUAL(err, "BTX035_HEALTH");
    BOOST_CHECK_EQUAL(roll.RingGeneration("realm"), static_cast<int64_t>(0));

    BOOST_REQUIRE(roll.AdvanceRing("realm", "policy", "policy", 0, err));
    BOOST_CHECK_EQUAL(roll.RingGeneration("realm"), static_cast<int64_t>(1));

    BOOST_REQUIRE(roll.ActivateOffline(9, 4, err));
    BOOST_CHECK(roll.OfflineRecorded());
    BOOST_CHECK_EQUAL(roll.OfflineBundleGeneration(), static_cast<int64_t>(9));
    BOOST_CHECK_EQUAL(roll.OfflineChannelSequence(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(roll.RingGeneration("realm"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(roll.ChannelSequence("realm"), static_cast<int64_t>(-1));

    BOOST_CHECK(!roll.AdvanceRingFromOffline(err));
    BOOST_CHECK_EQUAL(err, "BTX035_OFFLINE");
    BOOST_CHECK_EQUAL(roll.RingGeneration("realm"), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(backup_restore_refusal)
{
    modelnet::RealmRollout roll;
    std::string err;
    BOOST_REQUIRE(roll.PublishChannel("realm", 0, "h0", err));
    BOOST_REQUIRE(roll.PublishChannel("realm", 1, "h1", err));
    BOOST_REQUIRE(roll.PublishChannel("realm", 2, "h2", err));

    BOOST_CHECK(!roll.RestoreBackup(1, 2, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    BOOST_CHECK_EQUAL(roll.CurrentSequence(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(roll.ChannelSequence("realm"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(roll.ChannelBody("realm"), "h2");

    BOOST_CHECK(roll.RestoreBackup(2, 2, err));
    BOOST_CHECK_EQUAL(roll.CurrentSequence(), static_cast<int64_t>(2));
    BOOST_CHECK(!roll.RestoreBackup(0, 2, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    BOOST_CHECK_EQUAL(roll.CurrentSequence(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(roll.ChannelSequence("realm"), static_cast<int64_t>(2));
}

BOOST_AUTO_TEST_CASE(split_authority)
{
    modelnet::RealmRollout roll;
    std::string err;
    BOOST_REQUIRE(roll.RecordPromotion("source-exporter", "dest-approver", err));
    BOOST_CHECK_EQUAL(roll.SourceExporter(), "source-exporter");
    BOOST_CHECK_EQUAL(roll.DestinationApprover(), "dest-approver");
    BOOST_CHECK(roll.ApprovePromotion(err));

    modelnet::RealmRollout same;
    BOOST_REQUIRE(same.RecordPromotion("solo", "solo", err));
    BOOST_CHECK(!same.ApprovePromotion(err));
    BOOST_CHECK_EQUAL(err, "BTX035_AUTHORITY");
    BOOST_CHECK_EQUAL(same.SourceExporter(), "solo");
    BOOST_CHECK_EQUAL(same.DestinationApprover(), "solo");

    modelnet::RealmRollout empty_source;
    BOOST_REQUIRE(empty_source.RecordPromotion("", "dest-approver", err));
    BOOST_CHECK(!empty_source.ApprovePromotion(err));
    BOOST_CHECK_EQUAL(err, "BTX035_AUTHORITY");

    modelnet::RealmRollout empty_dest;
    BOOST_REQUIRE(empty_dest.RecordPromotion("source-exporter", "", err));
    BOOST_CHECK(!empty_dest.ApprovePromotion(err));
    BOOST_CHECK_EQUAL(err, "BTX035_AUTHORITY");
}

BOOST_AUTO_TEST_CASE(offline_bundle_reload)
{
    modelnet::RealmRollout roll;
    std::string err;
    const fs::path bundle = m_path_root / "wan-offline-bundle.txt";
    BOOST_CHECK(!roll.WriteOfflineBundle(bundle, "alpha", err));
    BOOST_CHECK_EQUAL(err, "BTX035_REALM");
    BOOST_CHECK(!fs::exists(bundle));

    BOOST_REQUIRE(roll.SetPolicy("alpha", 2, {"c", "a", "b"}, err));
    BOOST_REQUIRE(roll.RevokeAttestor("alpha", "b", err));
    BOOST_REQUIRE(roll.PublishChannel("alpha", 0, "h0", err));
    BOOST_REQUIRE(roll.PublishChannel("alpha", 1, "body-hash", err));
    BOOST_REQUIRE(roll.AdvanceRing("alpha", "policy", "policy", 0, err));
    BOOST_CHECK_EQUAL(roll.RingGeneration("alpha"), static_cast<int64_t>(1));

    BOOST_REQUIRE(roll.WriteOfflineBundle(bundle, "alpha", err));
    const std::string expected =
        "BTX035-OFFLINE-1\n"
        "realm=alpha\n"
        "threshold=2\n"
        "pinned=3\n"
        "a\n"
        "b\n"
        "c\n"
        "revoked=1\n"
        "b\n"
        "channel=1\n"
        "body=body-hash\n";
    BOOST_CHECK_EQUAL(FileText(bundle), expected);
    BOOST_CHECK_EQUAL(roll.RingGeneration("alpha"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(roll.ChannelSequence("alpha"), static_cast<int64_t>(1));

    modelnet::RealmRollout loaded;
    BOOST_REQUIRE(loaded.ReadOfflineBundle(bundle, "alpha", err));
    BOOST_CHECK_EQUAL(loaded.Threshold("alpha"), 2);
    BOOST_CHECK(loaded.Quorum("alpha", {"a", "c"}));
    BOOST_CHECK(!loaded.Quorum("alpha", {"a", "b"}));
    BOOST_CHECK(!loaded.Quorum("alpha", {"a"}));
    BOOST_CHECK_EQUAL(loaded.ChannelSequence("alpha"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(loaded.ChannelBody("alpha"), "body-hash");
    BOOST_CHECK_EQUAL(loaded.RingGeneration("alpha"), static_cast<int64_t>(0));
    BOOST_CHECK(!loaded.AdvanceRingFromOffline(err));
    BOOST_CHECK_EQUAL(err, "BTX035_OFFLINE");
    BOOST_CHECK_EQUAL(loaded.RingGeneration("alpha"), static_cast<int64_t>(0));

    const fs::path again = m_path_root / "wan-offline-bundle-again.txt";
    BOOST_REQUIRE(loaded.WriteOfflineBundle(again, "alpha", err));
    BOOST_CHECK_EQUAL(FileText(again), expected);

    modelnet::RealmRollout kept;
    BOOST_REQUIRE(kept.AdvanceRing("alpha", "policy", "policy", 0, err));
    BOOST_CHECK_EQUAL(kept.RingGeneration("alpha"), static_cast<int64_t>(1));
    BOOST_REQUIRE(kept.ReadOfflineBundle(bundle, "alpha", err));
    BOOST_CHECK_EQUAL(kept.Threshold("alpha"), 2);
    BOOST_CHECK_EQUAL(kept.ChannelSequence("alpha"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(kept.ChannelBody("alpha"), "body-hash");
    BOOST_CHECK_EQUAL(kept.RingGeneration("alpha"), static_cast<int64_t>(1));
    BOOST_CHECK(!kept.AdvanceRingFromOffline(err));
    BOOST_CHECK_EQUAL(err, "BTX035_OFFLINE");
    BOOST_CHECK_EQUAL(kept.RingGeneration("alpha"), static_cast<int64_t>(1));

    const std::string full = FileText(bundle);
    BOOST_REQUIRE(full.size() > 2 && full.back() == '\n');
    const std::size_t cut = full.rfind('\n', full.size() - 2);
    BOOST_REQUIRE(cut != std::string::npos);
    const fs::path truncated = m_path_root / "wan-offline-truncated.txt";
    {
        std::ofstream out(truncated, std::ios::out | std::ios::trunc);
        BOOST_REQUIRE(out.is_open());
        out << full.substr(0, cut + 1);
        BOOST_REQUIRE(out);
    }
    modelnet::RealmRollout broken;
    BOOST_REQUIRE(broken.AdvanceRing("alpha", "policy", "policy", 0, err));
    BOOST_CHECK(!broken.ReadOfflineBundle(truncated, "alpha", err));
    BOOST_CHECK_EQUAL(err, "BTX035_BUNDLE");
    BOOST_CHECK_EQUAL(broken.Threshold("alpha"), 0);
    BOOST_CHECK_EQUAL(broken.ChannelSequence("alpha"), static_cast<int64_t>(-1));
    BOOST_CHECK_EQUAL(broken.RingGeneration("alpha"), static_cast<int64_t>(1));
    BOOST_CHECK(!broken.AdvanceRingFromOffline(err));
    BOOST_CHECK_EQUAL(err, "BTX035_OFFLINE");
    BOOST_CHECK_EQUAL(broken.RingGeneration("alpha"), static_cast<int64_t>(1));

    modelnet::RealmRollout mismatch;
    BOOST_REQUIRE(mismatch.AdvanceRing("beta", "policy", "policy", 0, err));
    BOOST_CHECK(!mismatch.ReadOfflineBundle(bundle, "beta", err));
    BOOST_CHECK_EQUAL(err, "BTX035_REALM");
    BOOST_CHECK_EQUAL(mismatch.Threshold("alpha"), 0);
    BOOST_CHECK_EQUAL(mismatch.Threshold("beta"), 0);
    BOOST_CHECK_EQUAL(mismatch.RingGeneration("beta"), static_cast<int64_t>(1));
    BOOST_CHECK(!mismatch.AdvanceRingFromOffline(err));
    BOOST_CHECK_EQUAL(err, "BTX035_OFFLINE");
    BOOST_CHECK_EQUAL(mismatch.RingGeneration("beta"), static_cast<int64_t>(1));
}

// A bundle restores a realm; it does not take one back. ReadOfflineBundle
// replaced the channel, the revocations and the threshold of a realm this node
// already held with whatever the file said, so an old bundle rolled the
// channel back (and let it be published again) and undid revocations.
BOOST_AUTO_TEST_CASE(offline_bundle_does_not_take_a_realm_back)
{
    std::string err;
    modelnet::RealmRollout roll;
    BOOST_REQUIRE(roll.SetPolicy("alpha", 2, {"a", "b", "c", "d"}, err));
    BOOST_REQUIRE(roll.RevokeAttestor("alpha", "b", err));
    BOOST_REQUIRE(roll.PublishChannel("alpha", 0, "h0", err));
    const fs::path old_bundle = m_path_root / "wan-offline-old.txt";
    BOOST_REQUIRE(roll.WriteOfflineBundle(old_bundle, "alpha", err));
    BOOST_REQUIRE(roll.PublishChannel("alpha", 1, "h1", err));
    BOOST_REQUIRE(roll.PublishChannel("alpha", 2, "h2", err));

    // An older channel, with the same policy and revocations.
    BOOST_CHECK(!roll.ReadOfflineBundle(old_bundle, "alpha", err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    BOOST_CHECK_EQUAL(roll.ChannelSequence("alpha"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(roll.ChannelBody("alpha"), "h2");
    BOOST_CHECK(!roll.PublishChannel("alpha", 1, "h1", err));

    // The same channel, without a later revocation.
    const fs::path before_revoke = m_path_root / "wan-offline-before-revoke.txt";
    BOOST_REQUIRE(roll.WriteOfflineBundle(before_revoke, "alpha", err));
    BOOST_REQUIRE(roll.RevokeAttestor("alpha", "c", err));
    BOOST_CHECK(!roll.ReadOfflineBundle(before_revoke, "alpha", err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    BOOST_CHECK(!roll.Quorum("alpha", {"a", "c"}));
    BOOST_CHECK(roll.Quorum("alpha", {"a", "d"}));

    // The current bundle still loads into the realm it came from.
    const fs::path current = m_path_root / "wan-offline-current.txt";
    BOOST_REQUIRE(roll.WriteOfflineBundle(current, "alpha", err));
    BOOST_CHECK_MESSAGE(roll.ReadOfflineBundle(current, "alpha", err), err);
    BOOST_CHECK_EQUAL(roll.ChannelSequence("alpha"), static_cast<int64_t>(2));

    // Another threshold, or another body at the same sequence.
    const std::string text = FileText(current);
    const auto rewrite = [&](const std::string& from, const std::string& to, const char* name) {
        std::string changed = text;
        const auto at = changed.find(from);
        BOOST_REQUIRE(at != std::string::npos);
        changed.replace(at, from.size(), to);
        const fs::path path = m_path_root / name;
        std::ofstream out(path, std::ios::out | std::ios::trunc);
        out << changed;
        out.close();
        return path;
    };
    BOOST_CHECK(!roll.ReadOfflineBundle(rewrite("threshold=2", "threshold=1", "wan-offline-threshold.txt"), "alpha", err));
    BOOST_CHECK_EQUAL(err, "BTX035_THRESHOLD");
    BOOST_CHECK_EQUAL(roll.Threshold("alpha"), 2);
    BOOST_CHECK(!roll.ReadOfflineBundle(rewrite("body=h2", "body=hx", "wan-offline-body.txt"), "alpha", err));
    BOOST_CHECK_EQUAL(err, "BTX035_STALE");
    BOOST_CHECK_EQUAL(roll.ChannelBody("alpha"), "h2");
    // Other pins.
    BOOST_CHECK(!roll.ReadOfflineBundle(rewrite("d\nrevoked=", "e\nrevoked=", "wan-offline-pins.txt"), "alpha", err));
    BOOST_CHECK_EQUAL(err, "BTX035_POLICY");

    // A named channel, as the lab keeps them (realm, newline, name).
    modelnet::RealmRollout named;
    BOOST_REQUIRE(named.SetPolicy("beta", 1, {"a"}, err));
    BOOST_REQUIRE(named.PublishChannel("beta\nmodel", 0, "n0", err));
    const fs::path named_old = m_path_root / "wan-offline-named-old.txt";
    BOOST_REQUIRE(named.WriteOfflineBundle(named_old, "beta", err));
    BOOST_REQUIRE(FileText(named_old).find("name=model\n") != std::string::npos);
    BOOST_REQUIRE(named.PublishChannel("beta\nmodel", 1, "n1", err));
    BOOST_CHECK(!named.ReadOfflineBundle(named_old, "beta", err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    BOOST_CHECK_EQUAL(named.ChannelSequence("beta\nmodel"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(named.ChannelBody("beta\nmodel"), "n1");
    // A bundle that names another channel would leave this one out of the next export.
    std::string other_text = FileText(named_old);
    other_text.replace(other_text.find("name=model"), 10, "name=other");
    const fs::path named_other = m_path_root / "wan-offline-named-other.txt";
    {
        std::ofstream out(named_other, std::ios::out | std::ios::trunc);
        out << other_text;
    }
    BOOST_CHECK(!named.ReadOfflineBundle(named_other, "beta", err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    const fs::path named_now = m_path_root / "wan-offline-named-now.txt";
    BOOST_CHECK_MESSAGE(named.WriteOfflineBundle(named_now, "beta", err), err);
}

BOOST_AUTO_TEST_SUITE_END()
