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

BOOST_AUTO_TEST_SUITE_END()
