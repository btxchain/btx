// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <modelnet/crypto.h>
#include <modelnet/economy.h>
#include <modelnet/identity.h>
#include <modelnet/search.h>
#include <span.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_search_economy_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(econ_search_01_description_only)
{
    using namespace modelnet;
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    ModelSearchRecord r;
    r.model_id.data[0] = 0xA1;
    r.canonical_name = "A17";
    r.display_name = "A17";
    r.short_description = "A specialized model for coding agents and repository tool use.";
    r.pubkey = pk;
    BOOST_REQUIRE(SignSearchRecord(r, Span<const unsigned char>{sk.data(), sk.size()}, err));
    r.signed_ok = true;
    SearchIndex idx;
    BOOST_REQUIRE(idx.Put(r, 1, err));
    SearchQuery q;
    q.text = "coding agent";
    const auto hits = idx.Search(q, 1);
    BOOST_REQUIRE_EQUAL(hits.size(), 1);
    BOOST_CHECK_EQUAL(hits[0].rec.canonical_name, "A17");
}

BOOST_AUTO_TEST_CASE(econ_search_02_network_runtime_description)
{
    using namespace modelnet;
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    ModelSearchRecord r;
    r.model_id.data[0] = 0xA2;
    r.canonical_name = "Lab";
    r.display_name = "Lab";
    r.short_description = "A specialized model for coding agents and repository tool use.";
    r.pubkey = pk;
    BOOST_REQUIRE(SignSearchRecord(r, Span<const unsigned char>{sk.data(), sk.size()}, err));
    r.signed_ok = true;
    SearchIndex publisher, searcher;
    BOOST_REQUIRE(publisher.Put(r, 1, err));
    SearchRuntime rt;
    rt.Bind(&searcher);
    SearchQuery q;
    q.text = "coding agent";
    q.scope = SearchScope::NETWORK;
    const auto job = rt.Start(q, {&publisher}, 1);
    BOOST_REQUIRE_GE(job.hits.size(), 1);
    BOOST_CHECK_EQUAL(job.hits[0].rec.canonical_name, "Lab");
}

BOOST_AUTO_TEST_CASE(econ_search_03_public_and_funding_mix)
{
    using namespace modelnet;
    SearchIndex idx;
    std::string err;
    ModelSearchRecord a;
    a.model_id.data[0] = 1;
    a.canonical_name = "PubCoder";
    a.display_name = "PubCoder";
    a.short_description = "coding";
    a.release_state = "PUBLIC";
    BOOST_REQUIRE(idx.Put(a, 1, err));
    ModelSearchRecord b;
    b.model_id.data[0] = 2;
    b.canonical_name = "FundCoder";
    b.display_name = "FundCoder";
    b.short_description = "coding";
    b.release_id = std::string(96, 'b');
    b.release_state = "FUNDING";
    b.release_target_atoms = 500;
    BOOST_REQUIRE(idx.Put(b, 1, err));
    SearchQuery q;
    q.text = "coding";
    const auto hits = idx.Search(q, 1);
    BOOST_CHECK_EQUAL(hits.size(), 2);
    bool saw_pub = false, saw_fund = false;
    for (const auto& h : hits) {
        const auto e = ComposeEconomyEntry(h, nullptr, {});
        if (e.result_type == ModelResultType::PUBLIC_MODEL) saw_pub = true;
        if (e.result_type == ModelResultType::RELEASE_CAMPAIGN) saw_fund = true;
    }
    BOOST_CHECK(saw_pub);
    BOOST_CHECK(saw_fund);
}

BOOST_AUTO_TEST_CASE(econ_search_sig_v2_covers_description_and_tags)
{
    using namespace modelnet;
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    ModelSearchRecord r;
    r.model_id.data[0] = 3;
    r.canonical_name = "Sig";
    r.display_name = "Sig";
    r.short_description = "coding tool model";
    r.tags = {"tools"};
    r.languages = {"ja"};
    r.pubkey = pk;
    BOOST_REQUIRE(SignSearchRecord(r, Span<const unsigned char>{sk.data(), sk.size()}, err));
    BOOST_CHECK_EQUAL(r.record_version, 2);
    BOOST_CHECK(VerifySearchRecord(r, 1, err));
    auto mut = r;
    mut.short_description = "medical model";
    BOOST_CHECK(!VerifySearchRecord(mut, 1, err));
    auto mut_tag = r;
    mut_tag.tags = {"medical"};
    BOOST_CHECK(!VerifySearchRecord(mut_tag, 1, err));
    BOOST_CHECK(!PublisherFieldCoveredByV1("tags"));
    BOOST_CHECK(PublisherFieldCoveredByV1("short_description"));
}

BOOST_AUTO_TEST_CASE(econ_search_usecase_phrases)
{
    using namespace modelnet;
    SearchIndex idx;
    std::string err;
    const char* phrases[][2] = {
        {"tool use", "A model for coding agents and repository tool use."},
        {"Japanese coding", "Japanese coding assistant for legal drafts."},
        {"scientific reasoning", "scientific reasoning model for lab work"},
        {"vision OCR", "vision OCR document reader"},
        {"legal Japanese", "legal Japanese contract helper"},
        {"small model laptop", "small model laptop GGUF"},
        {"large context coder", "large context coder for repos"},
    };
    unsigned char tag = 1;
    for (const auto& p : phrases) {
        ModelSearchRecord r;
        r.model_id.data[0] = tag++;
        r.canonical_name = std::string("N") + std::to_string(tag);
        r.display_name = r.canonical_name;
        r.short_description = p[1];
        BOOST_REQUIRE(idx.Put(r, 1, err));
        SearchQuery q;
        q.text = p[0];
        BOOST_CHECK_GE(idx.Search(q, 1).size(), 1);
    }
}

BOOST_AUTO_TEST_CASE(econ_search_v1_still_verifies)
{
    using namespace modelnet;
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    ModelSearchRecord r;
    r.model_id.data[0] = 9;
    r.canonical_name = "Old";
    r.display_name = "Old";
    r.short_description = "coding tool model";
    r.pubkey = pk;
    r.record_version = 1;
    r.signer_id = ResearchIdentityId(Span<const unsigned char>{pk.data(), pk.size()});
    const auto pre = SearchRecordPreimageV1(r);
    const Digest48 h = DomainHash("BTX/ModelSearchRecord/v1", Span<const unsigned char>{pre.data(), pre.size()});
    BOOST_REQUIRE(SignMlDsa44(Span<const unsigned char>{sk.data(), sk.size()},
                                Span<const unsigned char>{h.data.data(), h.data.size()}, r.sig, err));
    BOOST_CHECK(VerifySearchRecord(r, 1, err));
    auto mut = r;
    mut.tags = {"injected"};
    BOOST_CHECK(VerifySearchRecord(mut, 1, err)); // v1 does not cover tags
}

BOOST_AUTO_TEST_SUITE_END()
