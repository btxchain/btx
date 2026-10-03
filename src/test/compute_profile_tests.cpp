// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/compute_passport.h>
#include <matmul/compute_profile.h>
#include <matmul/compute_qualification.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <fstream>

BOOST_FIXTURE_TEST_SUITE(compute_profile_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(production_profile_is_deterministic_and_frozen)
{
    const auto& a = pwc::ProductionProfile();
    const auto& b = pwc::ProductionProfile();
    BOOST_CHECK_EQUAL(a.profile_name, "btx-rc-p1e-v1");
    BOOST_CHECK(!a.test_only);
    BOOST_CHECK_EQUAL(a.params.d_model, 4096u);
    BOOST_CHECK_EQUAL(a.params.rounds, 4u);
    BOOST_CHECK_EQUAL(a.params.L_lyr, 16u);
    BOOST_CHECK_EQUAL(a.params.b_seq, 16384u);
    BOOST_CHECK_EQUAL(a.params.T_leaf, 1024u);
    BOOST_CHECK_EQUAL(a.microunits_per_episode, 1000000u);
    BOOST_CHECK(a.id == b.id);
    const std::string id = pwc::ProfileIdHex(a);
    BOOST_CHECK_EQUAL(id, "5881650112bf7b69a3bfe2dbe587e781aee4b54699cd5dca2bea67773eb83b33942de50e132ac71a0b623cc452cd12c5");
    pwc::WorkProfile mutated = a;
    mutated.id = {};
    mutated.params.rounds = 5;
    BOOST_CHECK(pwc::ProfileId(mutated) != a.id);
    mutated = a;
    mutated.id = {};
    mutated.profile_name = "btx-rc-p1e-v1-gitdeadbeef";
    BOOST_CHECK(pwc::ProfileId(mutated) != a.id);
}

BOOST_AUTO_TEST_CASE(toy_profile_is_distinct_and_hidden_on_mainnet)
{
    const auto& toy = pwc::ToyProfile();
    BOOST_CHECK(toy.test_only);
    BOOST_CHECK(toy.id != pwc::ProductionProfile().id);
    std::string code;
    BOOST_CHECK(pwc::FindWorkProfile("btx-rc-p1e-toy-v1", false, code) == nullptr);
    BOOST_CHECK_EQUAL(code, "COMPUTE_TEST_PROFILE_DISABLED");
    code.clear();
    BOOST_CHECK(pwc::FindWorkProfile(pwc::ProfileIdHex(toy), true, code) == &toy);
    code.clear();
    BOOST_CHECK(pwc::FindWorkProfile("no-such", true, code) == nullptr);
    BOOST_CHECK_EQUAL(code, "COMPUTE_PROFILE_UNKNOWN");
    const UniValue json = pwc::WorkProfileJson(toy);
    BOOST_CHECK_EQUAL(json["profile_name"].get_str(), toy.profile_name);
    BOOST_CHECK_EQUAL(json["profile_id"].get_str(), pwc::ProfileIdHex(toy));
}

BOOST_AUTO_TEST_CASE(passport_rate_and_p99)
{
    std::vector<uint64_t> walls(99, 1000);
    pwc::PassportSamples samples;
    samples.profile_name = "btx-rc-p1e-toy-v1";
    samples.wall_us = walls;
    samples.cpu_fallbacks = 0;
    UniValue passport;
    std::string err;
    BOOST_CHECK(pwc::BuildPassport(samples, passport, err));
    BOOST_CHECK(!passport["p99_claimable"].get_bool());
    samples.wall_us.push_back(1000);
    BOOST_CHECK(pwc::BuildPassport(samples, passport, err));
    BOOST_CHECK(passport["p99_claimable"].get_bool());
    BOOST_CHECK(passport["public_evidence"]["host_identity_omitted"].get_bool());
    BOOST_CHECK(!passport.exists("hostname"));
    uint64_t rate = 0;
    BOOST_CHECK(pwc::MicrounitsPerHour(1, 1000000, rate, err));
    BOOST_CHECK_EQUAL(rate, 3600000000ull);
    BOOST_CHECK(!pwc::MicrounitsPerHour(0, 1, rate, err));
}

BOOST_AUTO_TEST_CASE(qualification_header_binds_challenge_and_episode)
{
    pwc::QualificationFreshness a;
    a.network = "regtest";
    a.profile_name = "btx-rc-p1e-toy-v1";
    a.subject.fill(1);
    a.issuer_nonce.fill(2);
    a.issued_at_ms = 10;
    a.expires_at_ms = 20;
    a.episode_count = 2;
    a.anchor_height = 1;
    const auto id1 = pwc::ChallengeId(a);
    const auto id2 = pwc::ChallengeId(a);
    BOOST_CHECK(id1 == id2);
    a.subject.fill(3);
    const auto id3 = pwc::ChallengeId(a);
    BOOST_CHECK(id1 != id3);
    const auto h0 = pwc::EpisodeHeader(id1, 0);
    const auto h0b = pwc::EpisodeHeader(id1, 0);
    const auto h1 = pwc::EpisodeHeader(id1, 1);
    BOOST_CHECK(h0.seed_a == h0b.seed_a);
    BOOST_CHECK(h0.seed_a != h1.seed_a);
    BOOST_CHECK(h0.seed_b != h0.seed_a);
}

BOOST_AUTO_TEST_CASE(toy_qualification_solves_verifies_and_rejects_replay)
{
    pwc::QualificationFreshness in;
    in.network = "regtest";
    in.profile_name = "btx-rc-p1e-toy-v1";
    in.subject.fill(9);
    in.issuer_nonce.fill(4);
    in.issued_at_ms = 1'000;
    in.expires_at_ms = 1'000'000;
    in.episode_count = 1;
    UniValue challenge;
    std::string code, err;
    BOOST_REQUIRE(pwc::IssueQualification(in, true, challenge, code, err));
    UniValue response;
    BOOST_REQUIRE(pwc::SolveQualification(challenge, /*time_budget_ms=*/60000, false, response, code, err));
    const fs::path path = m_path_root / "qual.dat";
    pwc::QualificationRegistry reg;
    BOOST_REQUIRE(reg.Open(path, err));
    BOOST_REQUIRE(reg.RememberIssued(challenge, code, err));
    UniValue summary;
    BOOST_REQUIRE(reg.Verify(challenge, response, false, 2'000, summary, code, err));
    BOOST_CHECK(summary["valid"].get_bool());
    BOOST_CHECK_EQUAL((summary["demonstrated_p1e_microunits"].getInt<uint64_t>()), 1000000u);
    BOOST_CHECK(!summary["client_timing_authoritative"].get_bool());
    BOOST_REQUIRE(reg.Verify(challenge, response, true, 2'100, summary, code, err));
    BOOST_CHECK(!reg.Verify(challenge, response, true, 2'200, summary, code, err));
    BOOST_CHECK_EQUAL(code, "COMPUTE_CHALLENGE_REDEEMED");
    pwc::QualificationRegistry again;
    BOOST_REQUIRE(again.Open(path, err));
    BOOST_CHECK(!again.Verify(challenge, response, true, 2'300, summary, code, err));
    BOOST_CHECK_EQUAL(code, "COMPUTE_CHALLENGE_REDEEMED");
}

BOOST_AUTO_TEST_CASE(qualification_rejects_bounds_expiry_and_corrupt_registry)
{
    pwc::QualificationFreshness in;
    in.network = "regtest";
    in.profile_name = "btx-rc-p1e-toy-v1";
    in.episode_count = 0;
    in.issued_at_ms = 1;
    in.expires_at_ms = 2;
    UniValue challenge;
    std::string code, err;
    BOOST_CHECK(!pwc::IssueQualification(in, true, challenge, code, err));
    in.episode_count = 17;
    BOOST_CHECK(!pwc::IssueQualification(in, true, challenge, code, err));
    in.episode_count = 1;
    in.expires_at_ms = 1;
    BOOST_CHECK(!pwc::IssueQualification(in, true, challenge, code, err));
    in.expires_at_ms = 10'000;
    in.issued_at_ms = 1'000;
    BOOST_REQUIRE(pwc::IssueQualification(in, true, challenge, code, err));
    UniValue response;
    BOOST_REQUIRE(pwc::SolveQualification(challenge, 60000, false, response, code, err));
    const fs::path path = m_path_root / "qual-expire.dat";
    pwc::QualificationRegistry reg;
    BOOST_REQUIRE(reg.Open(path, err));
    BOOST_REQUIRE(reg.RememberIssued(challenge, code, err));
    UniValue summary;
    BOOST_CHECK(!reg.Verify(challenge, response, false, 20'000, summary, code, err));
    BOOST_CHECK_EQUAL(code, "COMPUTE_CHALLENGE_EXPIRED");
    {
        std::ofstream bad(path, std::ios::trunc);
        bad << "{not-json";
    }
    pwc::QualificationRegistry broken;
    BOOST_CHECK(!broken.Open(path, err));
    BOOST_CHECK(!broken.Healthy());
    BOOST_CHECK(fs::exists(fs::PathFromString(fs::PathToString(path) + ".quarantine")));
}

BOOST_AUTO_TEST_SUITE_END()
