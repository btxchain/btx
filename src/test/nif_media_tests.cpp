// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_media/nif_media.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(nif_media_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unbound_acquire_is_purpose)
{
    modelnet::NifMedia media;
    std::string err;
    const std::vector<unsigned char> plain{'m', 'e', 'd', 'i', 'a'};

    BOOST_CHECK(!media.Acquire("clip", plain, true, true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_MEDIA_PURPOSE);
    BOOST_CHECK_EQUAL(err, "PURPOSE");
    BOOST_CHECK(media.purpose().empty());
    BOOST_CHECK(!media.stored("clip"));
    BOOST_CHECK(media.body("clip").empty());
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(media.stored_bytes(), static_cast<int64_t>(0));

    BOOST_CHECK(!media.Acquire("", plain, true, true, err));
    BOOST_CHECK_EQUAL(err, "PURPOSE");
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(0));
    BOOST_CHECK(!media.executable());
    BOOST_CHECK(!media.qualified());
}

BOOST_AUTO_TEST_CASE(bad_purpose_stores_nothing_and_valid_bind_replaces)
{
    modelnet::NifMedia media;
    std::string err;

    BOOST_CHECK(!media.Bind("serving", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_MEDIA_PURPOSE);
    BOOST_CHECK_EQUAL(err, "PURPOSE");
    BOOST_CHECK(media.purpose().empty());
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(0));

    BOOST_CHECK(!media.Bind("Inference", err));
    BOOST_CHECK_EQUAL(err, "PURPOSE");
    BOOST_CHECK(media.purpose().empty());

    BOOST_CHECK(!media.Bind("", err));
    BOOST_CHECK_EQUAL(err, "PURPOSE");
    BOOST_CHECK(media.purpose().empty());

    BOOST_CHECK(media.Bind("inference", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(media.purpose(), "inference");

    BOOST_CHECK(!media.Bind("inference ", err));
    BOOST_CHECK_EQUAL(err, "PURPOSE");
    BOOST_CHECK_EQUAL(media.purpose(), "inference");

    BOOST_CHECK(media.Bind("training", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(media.purpose(), "training");
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(media.stored_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(!media.qualified());
}

BOOST_AUTO_TEST_CASE(remote_download_writes_nothing)
{
    modelnet::NifMedia media;
    std::string err;
    const std::vector<unsigned char> plain{'m', 'e', 'd', 'i', 'a'};
    const std::vector<unsigned char> elf{0x7f, 'E', 'L', 'F'};

    BOOST_CHECK(media.Bind("inference", err));
    BOOST_CHECK(!media.Acquire("clip", plain, true, false, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_MEDIA_DOWNLOAD);
    BOOST_CHECK_EQUAL(err, "DOWNLOAD");
    BOOST_CHECK(!media.stored("clip"));
    BOOST_CHECK(media.body("clip").empty());
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(media.stored_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(media.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!media.Acquire("clip", elf, false, false, err));
    BOOST_CHECK_EQUAL(err, "DOWNLOAD");
    BOOST_CHECK(!media.stored("clip"));
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(0));

    BOOST_CHECK(media.Acquire("clip", plain, true, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(media.stored("clip"));
    BOOST_CHECK(media.body("clip") == plain);
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(media.stored_bytes(), static_cast<int64_t>(plain.size()));
    BOOST_CHECK(!media.executable());
}

BOOST_AUTO_TEST_CASE(unauthorized_writes_nothing)
{
    modelnet::NifMedia media;
    std::string err;
    const std::vector<unsigned char> plain{'m', 'e', 'd', 'i', 'a'};
    const std::vector<unsigned char> elf{0x7f, 'E', 'L', 'F', 'x'};

    BOOST_CHECK(media.Bind("training", err));
    BOOST_CHECK(!media.Acquire("clip", plain, false, true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_MEDIA_DENIED);
    BOOST_CHECK_EQUAL(err, "DENIED");
    BOOST_CHECK(!media.stored("clip"));
    BOOST_CHECK(media.body("clip").empty());
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(media.stored_bytes(), static_cast<int64_t>(0));

    BOOST_CHECK(!media.Acquire("clip", elf, false, true, err));
    BOOST_CHECK_EQUAL(err, "DENIED");
    BOOST_CHECK(!media.stored("clip"));
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(media.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!media.executable());
}

BOOST_AUTO_TEST_CASE(elf_and_pickle_write_nothing)
{
    modelnet::NifMedia media;
    std::string err;
    const char marker[] = "PYTHON_PICKLE";

    BOOST_CHECK(media.Bind("inference", err));

    const std::vector<unsigned char> elf{0x7f, 'E', 'L', 'F', 'x'};
    BOOST_CHECK(!media.Acquire("elf", elf, true, true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_MEDIA_CODE);
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK(!media.stored("elf"));
    BOOST_CHECK(media.body("elf").empty());
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(media.stored_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(!media.executable());

    const std::vector<unsigned char> elf_only{0x7f, 'E', 'L', 'F'};
    BOOST_CHECK(!media.Acquire("elf", elf_only, true, true, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK(!media.stored("elf"));
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(0));

    std::vector<unsigned char> pickle{'a'};
    pickle.insert(pickle.end(), marker, marker + sizeof(marker) - 1);
    pickle.push_back('z');
    BOOST_CHECK(!media.Acquire("pickle", pickle, true, true, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK(!media.stored("pickle"));
    BOOST_CHECK(media.body("pickle").empty());
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(0));
    BOOST_CHECK(!media.executable());

    const std::vector<unsigned char> pickle_only(marker, marker + sizeof(marker) - 1);
    BOOST_CHECK(!media.Acquire("pickle", pickle_only, true, true, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK(!media.stored("pickle"));
    BOOST_CHECK_EQUAL(media.stored_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(media.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(empty_id_is_media_and_one_local_body_is_stored)
{
    modelnet::NifMedia media;
    std::string err;
    const std::vector<unsigned char> plain{'l', 'o', 'c', 'a', 'l'};
    const std::vector<unsigned char> short_prefix{0x7f, 'E', 'L'};

    BOOST_CHECK(media.Bind("inference", err));
    BOOST_CHECK(!media.Acquire("", plain, true, true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_MEDIA_MEDIA);
    BOOST_CHECK_EQUAL(err, "MEDIA");
    BOOST_CHECK(!media.stored(""));
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(media.stored_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(media.purpose(), "inference");

    BOOST_CHECK(media.Acquire("clip", plain, true, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(media.stored("clip"));
    BOOST_CHECK(media.body("clip") == plain);
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(media.stored_bytes(), static_cast<int64_t>(plain.size()));
    BOOST_CHECK(!media.executable());
    BOOST_CHECK(!media.qualified());
    BOOST_CHECK_EQUAL(media.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(media.Acquire("prefix", short_prefix, true, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(media.body("prefix") == short_prefix);
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(media.stored_bytes(), static_cast<int64_t>(plain.size() + short_prefix.size()));
    BOOST_CHECK(!media.executable());

    BOOST_CHECK(media.Bind("training", err));
    BOOST_CHECK_EQUAL(media.purpose(), "training");
    BOOST_CHECK(media.body("clip") == plain);
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(2));
    BOOST_CHECK(!media.qualified());
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first_body)
{
    modelnet::NifMedia media;
    std::string err;
    const std::vector<unsigned char> first{'f', 'i', 'r', 's', 't'};
    const std::vector<unsigned char> elf{0x7f, 'E', 'L', 'F', 'x'};
    const char marker[] = "PYTHON_PICKLE";
    const std::vector<unsigned char> pickle(marker, marker + sizeof(marker) - 1);
    const std::vector<unsigned char> other{'o', 't', 'h', 'e', 'r'};

    BOOST_CHECK(media.Bind("training", err));
    BOOST_CHECK(media.Acquire("clip", first, true, true, err));
    BOOST_CHECK(media.body("clip") == first);
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(media.stored_bytes(), static_cast<int64_t>(first.size()));

    BOOST_CHECK(!media.Acquire("clip", elf, true, false, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(media.body("clip") == first);
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(media.stored_bytes(), static_cast<int64_t>(first.size()));
    BOOST_CHECK(!media.executable());

    BOOST_CHECK(!media.Acquire("clip", elf, true, true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(media.body("clip") == first);
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(1));

    BOOST_CHECK(!media.Acquire("clip", pickle, true, true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(media.body("clip") == first);
    BOOST_CHECK_EQUAL(media.stored_bytes(), static_cast<int64_t>(first.size()));

    BOOST_CHECK(!media.Acquire("clip", other, true, true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(media.body("clip") == first);
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(media.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!media.executable());
    BOOST_CHECK(!media.qualified());
}

BOOST_AUTO_TEST_CASE(idle_flags_stay_closed)
{
    modelnet::NifMedia media;
    std::string err;
    const std::vector<unsigned char> plain{'i', 'd', 'l', 'e'};

    BOOST_CHECK_EQUAL(media.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!media.launched());
    BOOST_CHECK(!media.gpu());
    BOOST_CHECK(!media.broadcast());
    BOOST_CHECK_EQUAL(media.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(media.automatic_spend(), "0");
    BOOST_CHECK(!media.qualified());
    BOOST_CHECK(!media.executable());
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(media.stored_bytes(), static_cast<int64_t>(0));

    BOOST_CHECK(media.Bind("inference", err));
    BOOST_CHECK(media.Acquire("clip", plain, true, true, err));
    BOOST_CHECK_EQUAL(media.acquired(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(media.stored_bytes(), static_cast<int64_t>(plain.size()));
    BOOST_CHECK(media.body("clip") == plain);
    BOOST_CHECK(!media.executable());
    BOOST_CHECK_EQUAL(media.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!media.launched());
    BOOST_CHECK(!media.gpu());
    BOOST_CHECK(!media.broadcast());
    BOOST_CHECK_EQUAL(media.automatic_spend(), "0");
    BOOST_CHECK(!media.qualified());
}

BOOST_AUTO_TEST_SUITE_END()
