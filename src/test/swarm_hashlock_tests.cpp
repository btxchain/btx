// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hashlock.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_hashlock_tests, BasicTestingSetup)

static modelnet::SwarmHashlockRequest NotedHashlock()
{
    modelnet::SwarmHashlockRequest hashlock;
    hashlock.invoice_id = "invoice-hashlock";
    hashlock.hash_len = 32;
    hashlock.preimage_len = 32;
    hashlock.want_qualify = false;
    return hashlock;
}

static void ExpectUnqualified(const modelnet::SwarmHashlockResult& result)
{
    BOOST_CHECK(!result.qualified);
}

BOOST_AUTO_TEST_CASE(empty_invoice_id_is_hash)
{
    modelnet::SwarmHashlockRequest hashlock = NotedHashlock();
    hashlock.invoice_id.clear();
    std::string err = "prior";
    const modelnet::SwarmHashlockResult result = modelnet::SwarmNoteHashlock(hashlock, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "HASH");
    BOOST_CHECK_EQUAL(err, "HASH");
}

BOOST_AUTO_TEST_CASE(negative_hash_len_is_hash)
{
    modelnet::SwarmHashlockRequest hashlock = NotedHashlock();
    hashlock.hash_len = -1;
    std::string err = "prior";
    const modelnet::SwarmHashlockResult result = modelnet::SwarmNoteHashlock(hashlock, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "HASH");
    BOOST_CHECK_EQUAL(err, "HASH");
}

BOOST_AUTO_TEST_CASE(negative_preimage_len_is_hash)
{
    modelnet::SwarmHashlockRequest hashlock = NotedHashlock();
    hashlock.preimage_len = -1;
    std::string err = "prior";
    const modelnet::SwarmHashlockResult result = modelnet::SwarmNoteHashlock(hashlock, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "HASH");
    BOOST_CHECK_EQUAL(err, "HASH");
}

BOOST_AUTO_TEST_CASE(empty_invoice_id_wins_over_lengths_and_want_qualify)
{
    modelnet::SwarmHashlockRequest hashlock = NotedHashlock();
    hashlock.invoice_id.clear();
    hashlock.hash_len = 16;
    hashlock.preimage_len = 16;
    hashlock.want_qualify = true;
    std::string err = "prior";
    const modelnet::SwarmHashlockResult result = modelnet::SwarmNoteHashlock(hashlock, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "HASH");
    BOOST_CHECK_EQUAL(err, "HASH");
}

BOOST_AUTO_TEST_CASE(negative_hash_len_wins_over_want_qualify)
{
    modelnet::SwarmHashlockRequest hashlock = NotedHashlock();
    hashlock.hash_len = -1;
    hashlock.want_qualify = true;
    std::string err = "prior";
    const modelnet::SwarmHashlockResult result = modelnet::SwarmNoteHashlock(hashlock, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "HASH");
    BOOST_CHECK_EQUAL(err, "HASH");
}

BOOST_AUTO_TEST_CASE(negative_preimage_len_wins_over_preimage_code)
{
    modelnet::SwarmHashlockRequest hashlock = NotedHashlock();
    hashlock.preimage_len = -1;
    hashlock.want_qualify = true;
    std::string err = "prior";
    const modelnet::SwarmHashlockResult result = modelnet::SwarmNoteHashlock(hashlock, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "HASH");
    BOOST_CHECK_EQUAL(err, "HASH");
}

BOOST_AUTO_TEST_CASE(zero_hash_len_is_hash_len)
{
    modelnet::SwarmHashlockRequest hashlock = NotedHashlock();
    hashlock.hash_len = 0;
    std::string err = "prior";
    const modelnet::SwarmHashlockResult result = modelnet::SwarmNoteHashlock(hashlock, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "HASH_LEN");
    BOOST_CHECK_EQUAL(err, "HASH_LEN");
}

BOOST_AUTO_TEST_CASE(short_hash_len_is_hash_len)
{
    modelnet::SwarmHashlockRequest hashlock = NotedHashlock();
    hashlock.hash_len = 31;
    std::string err = "prior";
    const modelnet::SwarmHashlockResult result = modelnet::SwarmNoteHashlock(hashlock, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "HASH_LEN");
    BOOST_CHECK_EQUAL(err, "HASH_LEN");
}

BOOST_AUTO_TEST_CASE(long_hash_len_is_hash_len)
{
    modelnet::SwarmHashlockRequest hashlock = NotedHashlock();
    hashlock.hash_len = 33;
    std::string err = "prior";
    const modelnet::SwarmHashlockResult result = modelnet::SwarmNoteHashlock(hashlock, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "HASH_LEN");
    BOOST_CHECK_EQUAL(err, "HASH_LEN");
}

BOOST_AUTO_TEST_CASE(hash_len_wins_when_want_qualify_is_true)
{
    modelnet::SwarmHashlockRequest hashlock = NotedHashlock();
    hashlock.hash_len = 31;
    hashlock.want_qualify = true;
    std::string err = "prior";
    const modelnet::SwarmHashlockResult result = modelnet::SwarmNoteHashlock(hashlock, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "HASH_LEN");
    BOOST_CHECK_EQUAL(err, "HASH_LEN");
}

BOOST_AUTO_TEST_CASE(hash_len_wins_over_preimage_len)
{
    modelnet::SwarmHashlockRequest hashlock = NotedHashlock();
    hashlock.hash_len = 16;
    hashlock.preimage_len = 16;
    hashlock.want_qualify = true;
    std::string err = "prior";
    const modelnet::SwarmHashlockResult result = modelnet::SwarmNoteHashlock(hashlock, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "HASH_LEN");
    BOOST_CHECK_EQUAL(err, "HASH_LEN");
}

BOOST_AUTO_TEST_CASE(zero_preimage_len_is_preimage)
{
    modelnet::SwarmHashlockRequest hashlock = NotedHashlock();
    hashlock.preimage_len = 0;
    std::string err = "prior";
    const modelnet::SwarmHashlockResult result = modelnet::SwarmNoteHashlock(hashlock, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "PREIMAGE");
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
}

BOOST_AUTO_TEST_CASE(short_preimage_len_is_preimage)
{
    modelnet::SwarmHashlockRequest hashlock = NotedHashlock();
    hashlock.preimage_len = 31;
    std::string err = "prior";
    const modelnet::SwarmHashlockResult result = modelnet::SwarmNoteHashlock(hashlock, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "PREIMAGE");
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
}

BOOST_AUTO_TEST_CASE(long_preimage_len_is_preimage)
{
    modelnet::SwarmHashlockRequest hashlock = NotedHashlock();
    hashlock.preimage_len = 33;
    std::string err = "prior";
    const modelnet::SwarmHashlockResult result = modelnet::SwarmNoteHashlock(hashlock, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "PREIMAGE");
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
}

BOOST_AUTO_TEST_CASE(preimage_wins_when_want_qualify_is_true)
{
    modelnet::SwarmHashlockRequest hashlock = NotedHashlock();
    hashlock.preimage_len = 31;
    hashlock.want_qualify = true;
    std::string err = "prior";
    const modelnet::SwarmHashlockResult result = modelnet::SwarmNoteHashlock(hashlock, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "PREIMAGE");
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
}

BOOST_AUTO_TEST_CASE(want_qualify_with_32_byte_lengths_is_held)
{
    modelnet::SwarmHashlockRequest hashlock = NotedHashlock();
    hashlock.hash_len = 32;
    hashlock.preimage_len = 32;
    hashlock.want_qualify = true;
    std::string err = "prior";
    const modelnet::SwarmHashlockResult result = modelnet::SwarmNoteHashlock(hashlock, err);
    ExpectUnqualified(result);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(thirty_two_byte_lengths_without_qualify_is_noted)
{
    modelnet::SwarmHashlockRequest hashlock = NotedHashlock();
    hashlock.hash_len = 32;
    hashlock.preimage_len = 32;
    hashlock.want_qualify = false;
    std::string err = "prior";
    const modelnet::SwarmHashlockResult result = modelnet::SwarmNoteHashlock(hashlock, err);
    ExpectUnqualified(result);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
