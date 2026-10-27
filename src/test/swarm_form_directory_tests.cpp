// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_form/directory.h>
#include <modelnet/swarm_form/plane.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>

BOOST_FIXTURE_TEST_SUITE(swarm_form_directory_tests, BasicTestingSetup)

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

} // namespace

BOOST_AUTO_TEST_CASE(empty_modeldir_is_modeldir_and_creates_nothing)
{
    const fs::path relative_swarm{"swarm"};
    const bool existed = fs::exists(relative_swarm);
    std::string err = "stale";
    modelnet::SwarmFormDirectory directory;
    BOOST_CHECK(!directory.Open(std::filesystem::path{}, err));
    BOOST_CHECK_EQUAL(err, "MODELDIR");
    BOOST_CHECK(!directory.opened());
    BOOST_CHECK(directory.path().empty());

    err = "stale";
    BOOST_CHECK(!modelnet::SwarmFormPlane(std::filesystem::path{}, err));
    BOOST_CHECK_EQUAL(err, "MODELDIR");
    if (!existed) {
        BOOST_CHECK(!fs::exists(relative_swarm));
    }
}

BOOST_AUTO_TEST_CASE(symlink_swarm_is_symlink_and_is_not_written)
{
    FormTree tree(m_path_root / "swarm-form-directory-symlink");
    const fs::path model = tree.path / "model";
    const fs::path target = tree.path / "target";
    fs::create_directories(model);
    fs::create_directories(target);
    {
        std::ofstream sentinel(target / "sentinel");
        sentinel << "keep\n";
    }
    fs::create_symlink(target, model / "swarm");

    std::string err = "stale";
    BOOST_CHECK(!modelnet::SwarmFormPlane(model, err));
    BOOST_CHECK_EQUAL(err, "SYMLINK");
    BOOST_CHECK(fs::is_symlink(fs::symlink_status(model / "swarm")));
    BOOST_CHECK(fs::exists(target / "sentinel"));
    BOOST_CHECK_EQUAL(ReadFile(target / "sentinel"), "keep\n");
    BOOST_CHECK(!fs::exists(target / "formation-membership.json"));
    BOOST_CHECK(!fs::exists(target / "formation-election.json"));
}

BOOST_AUTO_TEST_CASE(missing_swarm_directory_is_created)
{
    FormTree tree(m_path_root / "swarm-form-directory-create");
    const fs::path model = tree.path / "model";
    fs::create_directories(model);
    BOOST_CHECK(!fs::exists(model / "swarm"));

    std::string err = "stale";
    BOOST_REQUIRE(modelnet::SwarmFormPlane(model, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(fs::exists(model / "swarm"));
    BOOST_CHECK(fs::is_directory(model / "swarm"));
    BOOST_CHECK(fs::exists(model / "swarm" / "formation-membership.json"));
}

BOOST_AUTO_TEST_CASE(existing_swarm_directory_is_left_in_place)
{
    FormTree tree(m_path_root / "swarm-form-directory-exists");
    const fs::path model = tree.path / "model";
    fs::create_directories(model / "swarm");
    {
        std::ofstream keep(model / "swarm" / "keep.txt");
        keep << "keep\n";
    }

    std::string err = "stale";
    modelnet::SwarmFormDirectory directory;
    BOOST_REQUIRE(directory.Open(model, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(directory.opened());
    BOOST_CHECK_EQUAL(ReadFile(model / "swarm" / "keep.txt"), "keep\n");

    err = "stale";
    BOOST_REQUIRE(modelnet::SwarmFormPlane(model, err));
    BOOST_CHECK_EQUAL(ReadFile(model / "swarm" / "keep.txt"), "keep\n");
    BOOST_CHECK(fs::is_directory(fs::symlink_status(model / "swarm")));
}

BOOST_AUTO_TEST_SUITE_END()
