// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <modelnet/economy.h>
#include <modelnet/identity.h>
#include <modelnet/release.h>
#include <modelnet/search.h>
#include <span.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_release_directory_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(econ_release_01_searchable_unreleased)
{
    using namespace modelnet;
    ModelSearchRecord r;
    r.model_id.data[0] = 11;
    r.display_name = "Unreleased Coder";
    r.canonical_name = "Unreleased Coder";
    r.short_description = "advanced repository maintenance and autonomous coding model";
    r.release_id = std::string(96, 'a');
    r.release_state = "FUNDING";
    r.release_target_atoms = 500 * COIN_ATOMS;
    r.expires_at = 1'000'000'000;
    SearchIndex idx;
    std::string err;
    BOOST_REQUIRE(idx.Put(r, 1, err));
    SearchQuery q;
    q.text = "repository maintenance";
    const auto hits = idx.Search(q, 1);
    BOOST_REQUIRE_EQUAL(hits.size(), 1);
    CampaignIndex camps;
    camps.IngestFromSearchRecord(r);
    const auto e = ComposeEconomyEntry(hits[0], camps.GetByModel(r.model_id), {});
    BOOST_CHECK(!e.downloadable_plaintext);
    BOOST_CHECK(e.fundable_now);
}

BOOST_AUTO_TEST_CASE(econ_release_static_signature)
{
    using namespace modelnet;
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    ReleaseCampaign c;
    c.release_id.data[0] = 1;
    c.model_id.data[0] = 2;
    c.target_atoms = 100;
    c.refund_height = 200;
    c.key_hash.data[0] = 7;
    c.pubkey = pk;
    BOOST_REQUIRE(SignReleaseCampaign(c, Span<const unsigned char>{sk.data(), sk.size()}, err));
    BOOST_CHECK(VerifyReleaseCampaign(c, err));
    auto forged = c;
    forged.target_atoms = 999;
    BOOST_CHECK(!VerifyReleaseCampaign(forged, err));
}

BOOST_AUTO_TEST_CASE(econ_cache_02_ciphertext_degraded)
{
    using namespace modelnet;
    SearchHit h;
    h.rec.display_name = "Camp";
    ReleaseCampaign c;
    c.release_id.data[0] = 4;
    c.target_atoms = 10;
    FundingObservation f;
    f.ciphertext_providers_observed = 0;
    f.funding_source = "OBSERVED_NETWORK_STATE";
    const auto e = ComposeEconomyEntry(h, &c, f);
    BOOST_CHECK(!e.ciphertext_available);
    const UniValue j = EconomyReleaseJson(e);
    BOOST_CHECK_EQUAL(j["ciphertext_providers_observed"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(econ_campaign_index_dedupe)
{
    using namespace modelnet;
    CampaignIndex idx;
    ReleaseCampaign c;
    c.release_id.data[0] = 1;
    c.model_id.data[0] = 2;
    std::string err;
    BOOST_REQUIRE(idx.Put(c, err));
    BOOST_REQUIRE(idx.Put(c, err));
    BOOST_CHECK_EQUAL(idx.Size(), 1);
}

namespace {
modelnet::Digest48 Id(uint16_t n)
{
    modelnet::Digest48 d;
    d.data[0] = static_cast<unsigned char>(n & 0xff);
    d.data[1] = static_cast<unsigned char>(n >> 8);
    return d;
}
modelnet::ModelSearchRecord ReleaseRecord(uint16_t model, uint16_t release)
{
    modelnet::ModelSearchRecord r;
    r.model_id = Id(model);
    r.release_id = Id(release).Hex();
    return r;
}
} // namespace

BOOST_AUTO_TEST_CASE(econ_campaign_index_bounded)
{
    using namespace modelnet;
    std::string err;
    // A campaign this node created (the caller's predicate keeps it) and a
    // peer's campaign this node pledged to (its local state keeps it).
    ReleaseCampaign local;
    local.release_id = Id(0xF0);
    local.model_id = Id(0xF0);
    ReleaseCampaign pledged;
    pledged.release_id = Id(0xE0);
    pledged.model_id = Id(0xE0);
    pledged.pledged_atoms = 5;
    const auto keep = [&](const ReleaseCampaign& c) { return c.release_id == local.release_id; };

    CampaignIndex idx;
    idx.SetCap(4);
    BOOST_REQUIRE(idx.Put(local, err));
    BOOST_REQUIRE(idx.Put(pledged, err));
    idx.IngestFromSearchRecord(ReleaseRecord(1, 1), keep);
    idx.IngestFromSearchRecord(ReleaseRecord(2, 2), keep);
    idx.IngestFromSearchRecord(ReleaseRecord(1, 1), keep); // named again: now the newest
    idx.IngestFromSearchRecord(ReleaseRecord(3, 3), keep);
    BOOST_CHECK_EQUAL(idx.Size(), 4U);
    BOOST_CHECK(idx.GetByRelease(Id(1)));
    BOOST_CHECK(!idx.GetByRelease(Id(2))); // named least recently: dropped first
    for (uint8_t i = 10; i < 30; ++i) {
        idx.IngestFromSearchRecord(ReleaseRecord(i, i), keep);
        BOOST_CHECK_LE(idx.Size(), 4U);
    }
    BOOST_CHECK(idx.GetByRelease(local.release_id));
    BOOST_CHECK(idx.GetByRelease(pledged.release_id));
    BOOST_CHECK(idx.GetByRelease(Id(29)));
    BOOST_CHECK(idx.GetByRelease(Id(28)));

    // When every campaign is kept, a new one is skipped.
    CampaignIndex full;
    full.SetCap(1);
    BOOST_REQUIRE(full.Put(local, err));
    full.IngestFromSearchRecord(ReleaseRecord(1, 1), keep);
    BOOST_CHECK_EQUAL(full.Size(), 1U);
    BOOST_CHECK(full.GetByRelease(local.release_id));

    // A newer record for the same model replaces the campaign learned from
    // its older record...
    CampaignIndex re;
    re.IngestFromSearchRecord(ReleaseRecord(7, 1));
    re.IngestFromSearchRecord(ReleaseRecord(7, 2));
    BOOST_CHECK_EQUAL(re.Size(), 1U);
    BOOST_CHECK(!re.GetByRelease(Id(1)));
    BOOST_REQUIRE(re.GetByModel(Id(7)));
    BOOST_CHECK(re.GetByModel(Id(7))->release_id == Id(2));
    // ...but not one this node added state to.
    ReleaseCampaign funded;
    funded.release_id = Id(3);
    funded.model_id = Id(8);
    funded.funding_outpoints.push_back({});
    BOOST_REQUIRE(re.Put(funded, err));
    re.IngestFromSearchRecord(ReleaseRecord(8, 4));
    BOOST_CHECK(re.GetByRelease(Id(3)));
    BOOST_REQUIRE(re.GetByModel(Id(8)));
    BOOST_CHECK(re.GetByModel(Id(8))->release_id == Id(4));
}

BOOST_AUTO_TEST_CASE(econ_campaign_index_kept_scan_bounded)
{
    using namespace modelnet;
    constexpr uint16_t CAP{1000};
    constexpr uint16_t NEW{CAP + 1};
    size_t calls{0};

    // At the cap with every campaign kept (as while local_releases.json is
    // damaged), an insert asks about at most CAMPAIGN_INDEX_KEPT_SCAN of them
    // and skips the new campaign.
    CampaignIndex all;
    all.SetCap(CAP);
    for (uint16_t i = 1; i <= CAP; ++i) all.IngestFromSearchRecord(ReleaseRecord(i, i));
    BOOST_REQUIRE_EQUAL(all.Size(), size_t{CAP});
    all.IngestFromSearchRecord(ReleaseRecord(NEW, NEW), [&](const ReleaseCampaign&) { ++calls; return true; });
    BOOST_CHECK_LE(calls, CAMPAIGN_INDEX_KEPT_SCAN);
    BOOST_CHECK_EQUAL(all.Size(), size_t{CAP});
    BOOST_CHECK(!all.GetByRelease(Id(NEW)));

    // The kept campaigns an insert passes over move to the newest end, so
    // when the record is ingested again (as the economy RPCs do) the insert
    // gets past them and drops the oldest campaign that may go.
    const auto keep_ids_1_to_100 = [&](const ReleaseCampaign& c) {
        ++calls;
        return c.release_id.data[1] == 0 && c.release_id.data[0] <= 100;
    };
    CampaignIndex some;
    some.SetCap(CAP);
    for (uint16_t i = 1; i <= CAP; ++i) some.IngestFromSearchRecord(ReleaseRecord(i, i));
    for (int pass = 0; pass < 2; ++pass) {
        calls = 0;
        some.IngestFromSearchRecord(ReleaseRecord(NEW, NEW), keep_ids_1_to_100);
        BOOST_CHECK_LE(calls, CAMPAIGN_INDEX_KEPT_SCAN);
    }
    BOOST_CHECK_EQUAL(some.Size(), size_t{CAP});
    BOOST_CHECK(some.GetByRelease(Id(NEW)));
    BOOST_CHECK(!some.GetByRelease(Id(101)));
    for (uint16_t i = 1; i <= 100; ++i) BOOST_CHECK(some.GetByRelease(Id(i)));
}

BOOST_AUTO_TEST_SUITE_END()
