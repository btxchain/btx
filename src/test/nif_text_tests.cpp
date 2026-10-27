// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_text/nif_text.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(nif_text_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(id_one_is_special)
{
    modelnet::NifText text;

    BOOST_CHECK(text.Special(static_cast<int64_t>(1)));
    BOOST_CHECK(!text.Special(static_cast<int64_t>(0)));
    BOOST_CHECK(!text.Special(static_cast<int64_t>(2)));
    BOOST_CHECK_EQUAL(text.id(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(text.committed_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(!text.launched());
    BOOST_CHECK(!text.gpu());
    BOOST_CHECK(!text.broadcast());
    BOOST_CHECK_EQUAL(text.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(text.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

BOOST_AUTO_TEST_CASE(eos_text_is_lookalike_and_not_id_one)
{
    modelnet::NifText text;
    std::string err;

    BOOST_CHECK(text.Special(static_cast<int64_t>(1)));
    BOOST_CHECK(!text.Text("<eos>", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_TEXT_LOOKALIKE);
    BOOST_CHECK_EQUAL(err, "LOOKALIKE");
    BOOST_CHECK(text.id() != static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(text.id(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(text.lookalike(), "<eos>");
    BOOST_CHECK(text.committed().empty());
    BOOST_CHECK_EQUAL(text.committed_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(text.Special(static_cast<int64_t>(1)));
}

BOOST_AUTO_TEST_CASE(empty_text_is_text_other_text_appends)
{
    modelnet::NifText text;
    std::string err;

    BOOST_CHECK(!text.Text("", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_TEXT_TEXT);
    BOOST_CHECK_EQUAL(err, "TEXT");
    BOOST_CHECK_EQUAL(text.committed_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(text.id() != static_cast<int64_t>(1));

    BOOST_CHECK(text.Text("alpha", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(text.committed(), "alpha");
    BOOST_CHECK_EQUAL(text.committed_bytes(), static_cast<int64_t>(5));
    BOOST_CHECK(text.id() != static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(lone_lead_and_leading_continuation_are_boundary)
{
    modelnet::NifText text;
    std::string err;
    const std::vector<unsigned char> lone{0xC3};
    const std::vector<unsigned char> continuation{0xA9};

    BOOST_CHECK(!text.PushUtf8(lone, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_TEXT_BOUNDARY);
    BOOST_CHECK_EQUAL(err, "BOUNDARY");
    BOOST_CHECK_EQUAL(text.committed_bytes(), static_cast<int64_t>(0));

    BOOST_CHECK(!text.PushUtf8(continuation, err));
    BOOST_CHECK_EQUAL(err, "BOUNDARY");
    BOOST_CHECK_EQUAL(text.committed_bytes(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(eacute_commits_two_incomplete_does_not_add_again)
{
    modelnet::NifText text;
    std::string err;
    const std::vector<unsigned char> eacute{0xC3, 0xA9};
    const std::vector<unsigned char> lone{0xC3};
    const std::vector<unsigned char> next{'Z'};

    BOOST_CHECK(text.PushUtf8(eacute, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(text.committed_bytes(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(text.committed().size(), 2U);
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(text.committed()[0]), static_cast<unsigned char>(0xC3));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(text.committed()[1]), static_cast<unsigned char>(0xA9));

    BOOST_CHECK(!text.PushUtf8(lone, err));
    BOOST_CHECK_EQUAL(err, "BOUNDARY");
    BOOST_CHECK_EQUAL(text.committed_bytes(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(text.committed().size(), 2U);

    BOOST_CHECK(text.PushUtf8(next, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(text.committed_bytes(), static_cast<int64_t>(3));
}

BOOST_AUTO_TEST_CASE(split_mid_codepoint_does_not_grow)
{
    modelnet::NifText text;
    std::string err;
    const std::vector<unsigned char> eacute{0xC3, 0xA9};
    const std::vector<unsigned char> mid{0x61, 0xC3};

    BOOST_CHECK(!text.Split(mid, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_TEXT_BOUNDARY);
    BOOST_CHECK_EQUAL(err, "BOUNDARY");
    BOOST_CHECK_EQUAL(text.committed_bytes(), static_cast<int64_t>(0));

    BOOST_CHECK(text.PushUtf8(eacute, err));
    BOOST_CHECK_EQUAL(text.committed_bytes(), static_cast<int64_t>(2));

    BOOST_CHECK(!text.Split(mid, err));
    BOOST_CHECK_EQUAL(err, "BOUNDARY");
    BOOST_CHECK_EQUAL(text.committed_bytes(), static_cast<int64_t>(2));

    const std::vector<unsigned char> whole{0x61, 0xC3, 0xA9};
    BOOST_CHECK(text.Split(whole, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(text.committed_bytes(), static_cast<int64_t>(5));
}

BOOST_AUTO_TEST_SUITE_END()
