// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsigsize.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notsigsize_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_witness_id_is_witness)
{
    modelnet::SwarmNotSigSize note;
    std::string err = "prior";
    const modelnet::SwarmNotSigSizeResult result = modelnet::SwarmNoteNotSigSize(note, err);
    BOOST_CHECK_EQUAL(result.verified, false);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.code, "WITNESS");
    BOOST_CHECK_EQUAL(err, "WITNESS");
}

BOOST_AUTO_TEST_CASE(sig_bytes_one_is_size_only)
{
    modelnet::SwarmNotSigSize note;
    note.witness_id = "witness-1";
    note.sig_bytes = 1;
    note.want_verify = false;
    std::string err = "prior";
    const modelnet::SwarmNotSigSizeResult result = modelnet::SwarmNoteNotSigSize(note, err);
    BOOST_CHECK_EQUAL(result.verified, false);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.code, "SIZE_ONLY");
    BOOST_CHECK_EQUAL(err, "SIZE_ONLY");
}

BOOST_AUTO_TEST_CASE(sig_bytes_zero_want_verify_is_size_only)
{
    modelnet::SwarmNotSigSize note;
    note.witness_id = "witness-1";
    note.sig_bytes = 0;
    note.want_verify = true;
    std::string err = "prior";
    const modelnet::SwarmNotSigSizeResult result = modelnet::SwarmNoteNotSigSize(note, err);
    BOOST_CHECK_EQUAL(result.verified, false);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.code, "SIZE_ONLY");
    BOOST_CHECK_EQUAL(err, "SIZE_ONLY");
}

BOOST_AUTO_TEST_CASE(sig_bytes_zero_plain_is_noted)
{
    modelnet::SwarmNotSigSize note;
    note.witness_id = "witness-1";
    note.sig_bytes = 0;
    note.want_verify = false;
    std::string err = "prior";
    const modelnet::SwarmNotSigSizeResult result = modelnet::SwarmNoteNotSigSize(note, err);
    BOOST_CHECK_EQUAL(result.verified, false);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
