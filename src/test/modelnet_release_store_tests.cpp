// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h>
#include <modelnet/release.h>
#include <modelnet/types.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <csignal>
#include <string>
#include <vector>

#ifndef WIN32
#include <sys/resource.h>
#endif

using namespace modelnet;

BOOST_FIXTURE_TEST_SUITE(modelnet_release_store_tests, BasicTestingSetup)

#ifndef WIN32
// campaigns.json holds the helper's release funding campaigns (pledged and
// funded atoms, funding outpoints, whether the secret was disclosed). SaveCampaigns
// wrote it in place and reported success without checking the write; every caller
// discards its result. A save that fails only at close (a full disk) then cut the
// previous file short and was silent. RLIMIT_FSIZE stands in for the full disk.
BOOST_AUTO_TEST_CASE(savecampaigns_keeps_the_previous_file_when_a_write_is_cut_short)
{
    const fs::path dir = m_path_root / "release-campaigns-write";
    fs::create_directories(dir);
    std::string err;

    ReleaseCampaign a;
    BOOST_REQUIRE(Digest48::FromHex(std::string(96, 'a'), a.release_id, err));
    a.target_atoms = 111;
    const std::vector<ReleaseCampaign> one{a};
    BOOST_REQUIRE(SaveCampaigns(dir, one, err));
    const auto first_size = fs::file_size(dir / "campaigns.json");
    BOOST_REQUIRE_GT(first_size, 0U);

    // Round trip of the normal path.
    std::vector<ReleaseCampaign> back;
    BOOST_REQUIRE(LoadCampaigns(dir, back, err));
    BOOST_REQUIRE_EQUAL(back.size(), 1U);
    BOOST_CHECK(back[0].release_id == a.release_id);
    BOOST_CHECK_EQUAL(back[0].target_atoms, 111);

    // A larger set that does not fit under a limit set to the one-campaign size.
    ReleaseCampaign b;
    BOOST_REQUIRE(Digest48::FromHex(std::string(96, 'b'), b.release_id, err));
    b.target_atoms = 222;
    const std::vector<ReleaseCampaign> two{a, b};

    struct rlimit old_limit {};
    BOOST_REQUIRE(::getrlimit(RLIMIT_FSIZE, &old_limit) == 0);
    struct rlimit cut{old_limit};
    cut.rlim_cur = first_size;
    const auto old_handler{std::signal(SIGXFSZ, SIG_IGN)};
    BOOST_REQUIRE(::setrlimit(RLIMIT_FSIZE, &cut) == 0);
    err.clear();
    const bool saved{SaveCampaigns(dir, two, err)};
    BOOST_REQUIRE(::setrlimit(RLIMIT_FSIZE, &old_limit) == 0);
    std::signal(SIGXFSZ, old_handler);

    BOOST_CHECK_MESSAGE(!saved, "SaveCampaigns reported success although campaigns.json was not written in full");
    BOOST_CHECK(!fs::exists(dir / "campaigns.json.tmp"));

    // The file on disk still holds the first campaign.
    std::vector<ReleaseCampaign> reloaded;
    BOOST_REQUIRE(LoadCampaigns(dir, reloaded, err));
    BOOST_CHECK_MESSAGE(reloaded.size() == 1U && !reloaded.empty() && reloaded[0].release_id == a.release_id,
                        "the previous campaign was lost from campaigns.json");
}
#endif // WIN32

BOOST_AUTO_TEST_SUITE_END()
