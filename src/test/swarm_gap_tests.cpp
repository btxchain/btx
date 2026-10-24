// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_attempt.h>
#include <modelnet/swarm_fabric.h>
#include <modelnet/swarm_follow.h>
#include <modelnet/swarm_mandate.h>
#include <pqkey.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <unistd.h>

namespace {

fs::path Scratch(const char* name)
{
    fs::path path = fs::temp_directory_path();
    path /= fs::u8path(std::string(name) + "-" + std::to_string(::getpid()));
    fs::remove_all(path);
    fs::create_directories(path);
    return path;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_mandate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(a_mandate_cannot_assign_more_than_collateral)
{
    modelnet::SwarmMandateBook book;
    std::string err;
    BOOST_REQUIRE(book.Open(1000, 100, 50, err));
    modelnet::SwarmMandate mandate;
    mandate.mandate_id = "m1";
    mandate.pool_id = "pool";
    mandate.actor = "a";
    mandate.recipients = {"w"};
    mandate.ceiling = 400;
    mandate.expiry_height = 500;
    mandate.nonce = "n1";
    BOOST_REQUIRE(book.Grant(mandate, err));
    BOOST_REQUIRE(book.Reserve("m1", "work-1", "w", 200, 10, err));
    const modelnet::SwarmConservation first = book.Conserved();
    BOOST_CHECK(first.ok);
    BOOST_CHECK_EQUAL(first.available, 650);
    BOOST_CHECK_EQUAL(first.assigned, 200);
    BOOST_REQUIRE(book.Reserve("m1", "work-1", "w", 200, 10, err));
    BOOST_CHECK_EQUAL(book.Conserved().assigned, 200);
    BOOST_CHECK(!book.Reserve("m1", "work-1", "w", 100, 10, err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK(!book.Reserve("m1", "work-2", "w", 300, 10, err));
    BOOST_CHECK_EQUAL(err, "CEILING");
    BOOST_CHECK_EQUAL(book.Conserved().available, 650);
    BOOST_REQUIRE(book.Revoke("m1", err));
    BOOST_CHECK(!book.Reserve("m1", "work-3", "w", 10, 10, err));
    BOOST_CHECK_EQUAL(err, "REVOKED");
    BOOST_CHECK_EQUAL(book.Conserved().assigned, 200);

    modelnet::SwarmMandate wide = mandate;
    wide.mandate_id = "m2";
    wide.nonce = "n2";
    wide.ceiling = 10000;
    BOOST_REQUIRE(book.Grant(wide, err));
    BOOST_CHECK(!book.Reserve("m2", "work-4", "w", 700, 10, err));
    BOOST_CHECK_EQUAL(err, "CONSERVATION");
    BOOST_CHECK_EQUAL(book.Conserved().available, 650);

    const fs::path dir = Scratch("btx-swarm-mandate");
    BOOST_REQUIRE(book.Persist(dir, err));
    modelnet::SwarmMandateBook restored;
    BOOST_REQUIRE(restored.Load(dir, err));
    BOOST_CHECK_EQUAL(restored.Conserved().assigned, 200);
    BOOST_CHECK_EQUAL(restored.Conserved().available, 650);
    fs::remove_all(dir);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(swarm_attempt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(a_batch_refuses_work_until_quiescent_and_expires)
{
    modelnet::SwarmAttemptBook book;
    std::string err;
    modelnet::SwarmAttempt attempt;
    attempt.attempt_id = "a1";
    attempt.worker_id = "w";
    attempt.checkpoint_id = "ckpt";
    attempt.recipe = "recipe";
    attempt.expiry_ms = 1000;
    attempt.batch_size = 3;
    BOOST_REQUIRE(book.Grant(attempt, 100, err));
    BOOST_CHECK_EQUAL(book.Active(100), 1);
    BOOST_CHECK(!book.AcceptOne("a1", 100, err));
    BOOST_CHECK_EQUAL(err, "QUIESCENT");
    BOOST_REQUIRE(book.Heartbeat("a1", 100, true, err));
    BOOST_REQUIRE(book.AcceptOne("a1", 100, err));
    BOOST_REQUIRE(book.AcceptOne("a1", 100, err));
    BOOST_REQUIRE(book.AcceptOne("a1", 100, err));
    BOOST_CHECK(!book.AcceptOne("a1", 100, err));
    BOOST_CHECK_EQUAL(err, "BATCH_FULL");
    BOOST_REQUIRE(book.Grant(attempt, 100, err));
    BOOST_CHECK_EQUAL(book.Find("a1")->accepted, 3);
    attempt.batch_size = 4;
    BOOST_CHECK(!book.Grant(attempt, 100, err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(book.Active(1000), 0);
    BOOST_CHECK(!book.AcceptOne("a1", 1000, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_REQUIRE(book.Heartbeat("a1", 100, false, err));
    BOOST_CHECK(!book.AcceptOne("a1", 100, err));
    BOOST_CHECK_EQUAL(err, "QUIESCENT");

    const fs::path dir = Scratch("btx-swarm-attempt");
    BOOST_REQUIRE(book.Persist(dir, err));
    modelnet::SwarmAttemptBook restored;
    BOOST_REQUIRE(restored.Load(dir, err));
    BOOST_CHECK_EQUAL(restored.Active(100), 1);
    BOOST_CHECK_EQUAL(restored.Find("a1")->accepted, 3);
    fs::remove_all(dir);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(swarm_fabric_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(prefix_mismatch_is_not_an_absent_engine)
{
    modelnet::SwarmPrefix held;
    held.fingerprint = "fp";
    held.parent_fingerprint = "parent";
    held.length = 4;
    held.causal = true;
    modelnet::SwarmPrefix wanted = held;
    std::string err;
    BOOST_CHECK(modelnet::SwarmPrefixCompatible(held, wanted, err));
    wanted.fingerprint = "other";
    BOOST_CHECK(!modelnet::SwarmPrefixCompatible(held, wanted, err));
    BOOST_CHECK_EQUAL(err, "PREFIX_MISMATCH");
    wanted = held;
    wanted.causal = false;
    BOOST_CHECK(!modelnet::SwarmPrefixCompatible(held, wanted, err));
    BOOST_CHECK_EQUAL(err, "CAUSAL_GAP");

    const modelnet::SwarmPrefetch absent = modelnet::SwarmPrefetchPages(false, held, held, err);
    BOOST_CHECK(!absent.bytes_moved);
    BOOST_CHECK_EQUAL(absent.code, "ENGINE_ABSENT");
    const modelnet::SwarmPrefetch local = modelnet::SwarmPrefetchPages(true, held, held, err);
    BOOST_CHECK(!local.bytes_moved);
    BOOST_CHECK_EQUAL(local.code, "LOCAL");
    wanted.fingerprint = "other";
    wanted.causal = true;
    const modelnet::SwarmPrefetch mismatch = modelnet::SwarmPrefetchPages(false, held, wanted, err);
    BOOST_CHECK(!mismatch.bytes_moved);
    BOOST_CHECK(mismatch.code.empty());
    BOOST_CHECK_EQUAL(err, "PREFIX_MISMATCH");
}

BOOST_AUTO_TEST_CASE(a_lan_card_advertises_only_a_public_mapping)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    modelnet::SwarmLanCard card;
    card.artifact_id = std::string(96, 'a');
    card.lineage_id = std::string(96, 'b');
    card.public_mapping = true;
    card.pubkey = key.GetPubKey();
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(modelnet::SwarmLanCardHash(card), sig));
    card.signature_hex = HexStr(sig);
    std::string err;
    BOOST_CHECK(modelnet::SwarmAcceptLanCard(card, err));
    card.public_mapping = false;
    BOOST_CHECK(!modelnet::SwarmAcceptLanCard(card, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_MEMBERSHIP");
    card.public_mapping = true;
    card.artifact_id = std::string(96, 'c');
    BOOST_CHECK(!modelnet::SwarmAcceptLanCard(card, err));
    BOOST_CHECK_EQUAL(err, "CARD_SIGNATURE");
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(swarm_follow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(follow_stages_a_compatible_head_and_pin_does_not)
{
    std::string active = "old";
    std::string staged;
    bool staged_now = false;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmStagePolicy(active, staged, "Follow", "new", "ckpt", "recipe", "other", "recipe", staged_now, err));
    BOOST_CHECK_EQUAL(err, "INCOMPATIBLE");
    BOOST_CHECK_EQUAL(active, "old");
    BOOST_CHECK(staged.empty());
    BOOST_REQUIRE(modelnet::SwarmStagePolicy(active, staged, "Pin", "new", "ckpt", "recipe", "ckpt", "recipe", staged_now, err));
    BOOST_CHECK(!staged_now);
    BOOST_CHECK(staged.empty());
    BOOST_CHECK_EQUAL(active, "old");
    BOOST_REQUIRE(modelnet::SwarmStagePolicy(active, staged, "Refuse", "new", "ckpt", "recipe", "ckpt", "recipe", staged_now, err));
    BOOST_CHECK(!staged_now);
    BOOST_REQUIRE(modelnet::SwarmStagePolicy(active, staged, "Follow", "new", "ckpt", "recipe", "ckpt", "recipe", staged_now, err));
    BOOST_CHECK(staged_now);
    BOOST_CHECK_EQUAL(staged, "new");
    BOOST_CHECK_EQUAL(active, "old");
}

BOOST_AUTO_TEST_SUITE_END()
