// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_form/plane.h>
#include <modelnet/swarm_form/types.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>

BOOST_FIXTURE_TEST_SUITE(swarm_form_membership_tests, BasicTestingSetup)

namespace {

class FormTree {
public:
    explicit FormTree(fs::path path_in) : path(std::move(path_in))
    {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
        fs::create_directories(path);
    }
    ~FormTree()
    {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    FormTree(const FormTree&) = delete;
    FormTree& operator=(const FormTree&) = delete;
    fs::path path;
};

std::string ReadFile(const fs::path& file)
{
    std::ifstream in(file, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void WriteFile(const fs::path& file, const std::string& body)
{
    std::ofstream out(file, std::ios::trunc | std::ios::binary);
    out << body;
}

} // namespace

BOOST_AUTO_TEST_CASE(first_form_writes_local_membership)
{
    FormTree tree(m_path_root / "swarm-form-membership-local");
    const fs::path model = tree.path / "model";
    fs::create_directories(model);

    modelnet::FormationPlane plane;
    std::string err = "stale";
    BOOST_REQUIRE(plane.Open(model, err));
    BOOST_REQUIRE(plane.Form(err));
    BOOST_CHECK(err.empty());

    const modelnet::SwarmFormMember& member = plane.membership();
    BOOST_CHECK_EQUAL(member.node_id, "local");
    BOOST_CHECK(member.seeder);
    BOOST_CHECK(member.evaluator);
    BOOST_CHECK(member.modelnet_on);
    BOOST_CHECK(!member.training);
    BOOST_CHECK(!member.private_prompts);
    BOOST_CHECK_EQUAL(member.automatic_spend, "0");
    BOOST_CHECK_EQUAL(member.vram_mib, 0);
    BOOST_CHECK_EQUAL(member.cpu_thread_cap, 64);
    BOOST_CHECK_EQUAL(member.family_id, modelnet::kFormationFamilyId);
    BOOST_CHECK(plane.admitted("local"));

    const fs::path file = plane.directory() / modelnet::kMembershipFile;
    const std::string raw = ReadFile(file);
    BOOST_CHECK(raw.find("\"automatic_spend\":\"0\"") != std::string::npos);
    BOOST_CHECK(raw.find("\"hostname\"") == std::string::npos);
    BOOST_CHECK(raw.find("\"endpoint\"") == std::string::npos);
    BOOST_CHECK(raw.find("\"ip\"") == std::string::npos);

    UniValue root;
    BOOST_REQUIRE(root.read(raw));
    BOOST_CHECK_EQUAL(root["node_id"].get_str(), "local");
    BOOST_CHECK(root["seeder"].get_bool());
    BOOST_CHECK(root["evaluator"].get_bool());
    BOOST_CHECK(root["modelnet_on"].get_bool());
    BOOST_CHECK(!root["training"].get_bool());
    BOOST_CHECK(!root["private_prompts"].get_bool());
    BOOST_CHECK_EQUAL(root["automatic_spend"].get_str(), "0");
    BOOST_CHECK_EQUAL(root["vram_mib"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(root["cpu_thread_cap"].getInt<int>(), 64);
    BOOST_CHECK(root["admitted"].isArray());
    BOOST_CHECK_EQUAL(root["admitted"].size(), 1U);
    BOOST_CHECK_EQUAL(root["admitted"][0].get_str(), "local");
}

BOOST_AUTO_TEST_CASE(second_form_keeps_the_first_membership)
{
    FormTree tree(m_path_root / "swarm-form-membership-reopen");
    const fs::path model = tree.path / "model";
    fs::create_directories(model);

    std::string err = "stale";
    BOOST_REQUIRE(modelnet::SwarmFormPlane(model, err));
    BOOST_CHECK(err.empty());

    const fs::path file = model / "swarm" / modelnet::kMembershipFile;
    std::string raw = ReadFile(file);
    raw.push_back(' ');
    WriteFile(file, raw);

    modelnet::FormationPlane again;
    err = "stale";
    BOOST_REQUIRE(again.Open(model, err));
    BOOST_REQUIRE(again.Form(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(ReadFile(file), raw);
    BOOST_CHECK_EQUAL(again.membership().node_id, "local");
    BOOST_CHECK(again.membership().seeder);
    BOOST_CHECK(again.membership().evaluator);
    BOOST_CHECK(again.membership().modelnet_on);
    BOOST_CHECK(!again.membership().training);
    BOOST_CHECK(!again.membership().private_prompts);
    BOOST_CHECK_EQUAL(again.membership().automatic_spend, "0");
    BOOST_CHECK_EQUAL(again.membership().vram_mib, 0);
    BOOST_CHECK_EQUAL(again.membership().cpu_thread_cap, 64);
    BOOST_CHECK(again.admitted("local"));

    err = "stale";
    BOOST_REQUIRE(modelnet::SwarmFormPlane(model, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(ReadFile(file), raw);
}

BOOST_AUTO_TEST_CASE(torn_membership_is_set_aside_and_formed_again)
{
    FormTree tree(m_path_root / "swarm-form-membership-torn");
    const fs::path model = tree.path / "model";
    fs::create_directories(model);

    std::string err = "stale";
    BOOST_REQUIRE(modelnet::SwarmFormPlane(model, err));
    const fs::path file = model / "swarm" / modelnet::kMembershipFile;
    const fs::path aside = fs::u8path(file.utf8string() + ".bad");
    const std::string good = ReadFile(file);
    BOOST_REQUIRE(!good.empty());

    for (const std::string& torn : {std::string{}, good.substr(0, good.size() / 2), std::string("\0\xff", 2)}) {
        WriteFile(file, torn);
        err = "stale";
        BOOST_REQUIRE(modelnet::SwarmFormPlane(model, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK_EQUAL(ReadFile(file), good);
        BOOST_CHECK_EQUAL(ReadFile(aside), torn);

        err = "stale";
        BOOST_REQUIRE(modelnet::SwarmFormPlane(model, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK_EQUAL(ReadFile(file), good);
    }
}

BOOST_AUTO_TEST_CASE(membership_with_spend_is_not_replaced)
{
    FormTree tree(m_path_root / "swarm-form-membership-spend");
    const fs::path model = tree.path / "model";
    fs::create_directories(model);

    std::string err = "stale";
    BOOST_REQUIRE(modelnet::SwarmFormPlane(model, err));
    const fs::path file = model / "swarm" / modelnet::kMembershipFile;
    std::string raw = ReadFile(file);
    const std::string zero = "\"automatic_spend\":\"0\"";
    const size_t at = raw.find(zero);
    BOOST_REQUIRE(at != std::string::npos);
    raw.replace(at, zero.size(), "\"automatic_spend\":\"1\"");
    WriteFile(file, raw);

    err = "stale";
    BOOST_CHECK(!modelnet::SwarmFormPlane(model, err));
    BOOST_CHECK_EQUAL(err, "SPEND");
    BOOST_CHECK_EQUAL(ReadFile(file), raw);
    BOOST_CHECK(!fs::exists(fs::u8path(file.utf8string() + ".bad")));
}

BOOST_AUTO_TEST_CASE(membership_symlink_is_not_written_through)
{
    FormTree tree(m_path_root / "swarm-form-membership-symlink");
    const fs::path model = tree.path / "model";
    const fs::path outside = tree.path / "outside-membership";
    fs::create_directories(model / "swarm");
    WriteFile(outside, "secret\n");
    fs::create_symlink(outside, model / "swarm" / modelnet::kMembershipFile);

    std::string err = "stale";
    BOOST_CHECK(!modelnet::SwarmFormPlane(model, err));
    BOOST_CHECK_EQUAL(err, "SYMLINK");
    BOOST_CHECK_EQUAL(ReadFile(outside), "secret\n");
}

BOOST_AUTO_TEST_SUITE_END()
