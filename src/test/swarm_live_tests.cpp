// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_live.h>
#include <modelnet/swarm_records.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iterator>
#include <string>
#include <unistd.h>

BOOST_FIXTURE_TEST_SUITE(swarm_live_tests, BasicTestingSetup)

namespace {

std::string Id(char c)
{
    return std::string(96, c);
}

fs::path Scratch()
{
    const fs::path path = fs::temp_directory_path() / ("btx-swarm-live-" + std::to_string(::getpid()));
    fs::remove_all(path);
    fs::create_directories(path);
    return path;
}

void Write(const fs::path& path, const std::string& body)
{
    fs::create_directories(path.parent_path());
    std::ofstream file(path, std::ios::trunc);
    file << body;
}

std::string ReadRaw(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

bool Contains(const std::vector<std::string>& ids, const std::string& id)
{
    return std::find(ids.begin(), ids.end(), id) != ids.end();
}

} // namespace

BOOST_AUTO_TEST_CASE(publish_keeps_four_bit_in_the_family_only)
{
    const fs::path empty = Scratch();
    std::string err = "stale";
    BOOST_CHECK(modelnet::SwarmPublishLive(empty, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!fs::exists(empty / "swarm" / "networks.json"));
    BOOST_CHECK(!fs::exists(empty / "swarm" / "timescales.json"));
    fs::remove_all(empty);

    const std::string full = Id('a');
    const std::string quant = Id('b');
    const std::string skipped = Id('c');
    const std::string lineage = Id('d');
    const fs::path dir = Scratch();
    Write(dir / "swarm" / "contribution.json",
          std::string("{\"automatic_spend_atoms\":\"0\",\"models\":[") +
              "{\"acquire\":\"joined\",\"artifact_id\":\"" + full +
              "\",\"cohort\":true,\"checkpoint_id\":\"ckpt-full\",\"lineage_id\":\"" + lineage +
              "\",\"quantization\":\"full\",\"visibility\":\"public\",\"prompt\":\"do not store\"}," +
              "{\"acquire\":\"joined\",\"artifact_id\":\"" + quant +
              "\",\"cohort\":false,\"checkpoint_id\":\"" + quant + "\",\"lineage_id\":\"" + lineage +
              "\",\"quantization\":\"4bit\",\"visibility\":\"public\"}," +
              "{\"acquire\":\"observer\",\"artifact_id\":\"" + skipped +
              "\",\"cohort\":true,\"checkpoint_id\":\"ckpt-skip\",\"quantization\":\"full\"}" +
              "]}");
    BOOST_REQUIRE(modelnet::SwarmPublishLive(dir, err));

    modelnet::SwarmNetworks networks;
    BOOST_REQUIRE(modelnet::SwarmLoadNetworks(dir, networks, err));
    BOOST_CHECK_EQUAL(networks.automatic_spend_atoms, "0");
    BOOST_REQUIRE_EQUAL(networks.family.member_artifact_ids.size(), 2U);
    BOOST_CHECK(Contains(networks.family.member_artifact_ids, full));
    BOOST_CHECK(Contains(networks.family.member_artifact_ids, quant));
    BOOST_CHECK(!Contains(networks.family.member_artifact_ids, skipped));
    BOOST_CHECK_EQUAL(networks.cohort.checkpoint_id, "ckpt-full");
    BOOST_CHECK_NE(networks.cohort.checkpoint_id, quant);
    BOOST_CHECK(Contains(networks.cohort.member_ids, full));
    BOOST_CHECK(!Contains(networks.cohort.member_ids, quant));

    UniValue times;
    BOOST_REQUIRE(times.read(ReadRaw(dir / "swarm" / "timescales.json")));
    BOOST_CHECK(times["immediate"].isArray());
    BOOST_CHECK(times["short"].isArray());
    BOOST_CHECK(times["medium"].isArray());
    BOOST_CHECK(times["long"].isArray());
    BOOST_CHECK(!times.exists("timescale"));
    BOOST_CHECK_EQUAL(times["immediate"].size(), 0U);
    BOOST_CHECK_EQUAL(times["short"].size(), 0U);
    BOOST_CHECK_EQUAL(times["medium"].size(), 0U);
    BOOST_CHECK_EQUAL(times["general_stable"].get_str(), "unchanged");
    BOOST_CHECK_EQUAL(times["automatic_spend_atoms"].get_str(), "0");
    BOOST_REQUIRE_EQUAL(times["long"].size(), 1U);
    BOOST_CHECK(times["long"][0].isObject());
    BOOST_CHECK_EQUAL(times["long"][0]["lineage_id"].get_str(), lineage);
    BOOST_CHECK(!times["long"][0].exists("prompt"));

    const auto old = fs::file_time_type::clock::now() - std::chrono::hours(3);
    fs::last_write_time(dir / "swarm" / "networks.json", old);
    fs::last_write_time(dir / "swarm" / "timescales.json", old);
    const auto networks_stamp = fs::last_write_time(dir / "swarm" / "networks.json");
    const auto times_stamp = fs::last_write_time(dir / "swarm" / "timescales.json");
    BOOST_REQUIRE(modelnet::SwarmPublishLive(dir, err));
    BOOST_CHECK(fs::last_write_time(dir / "swarm" / "networks.json") == networks_stamp);
    BOOST_CHECK(fs::last_write_time(dir / "swarm" / "timescales.json") == times_stamp);
    fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(distinct_lineages_and_checkpoints_stay_apart)
{
    const std::string full = Id('a');
    const std::string other = Id('b');
    const std::string remote = Id('c');
    const std::string lineage = Id('d');
    const std::string other_lineage = Id('e');
    const fs::path dir = Scratch();
    Write(dir / "swarm" / "contribution.json",
          std::string("{\"automatic_spend_atoms\":\"0\",\"models\":[") +
              "{\"acquire\":\"joined\",\"artifact_id\":\"" + full +
              "\",\"cohort\":true,\"checkpoint_id\":\"ckpt-a\",\"recipe\":\"recipe\",\"kv_share\":false,\"lineage_id\":\"" +
              lineage + "\",\"quantization\":\"full\"}," +
              "{\"acquire\":\"joined\",\"artifact_id\":\"" + other +
              "\",\"cohort\":true,\"checkpoint_id\":\"ckpt-b\",\"recipe\":\"recipe\",\"kv_share\":false,\"lineage_id\":\"" +
              lineage + "\",\"quantization\":\"full\"}," +
              "{\"acquire\":\"joined\",\"artifact_id\":\"" + remote +
              "\",\"cohort\":true,\"checkpoint_id\":\"ckpt-a\",\"recipe\":\"recipe\",\"kv_share\":true,\"lineage_id\":\"" +
              other_lineage + "\",\"quantization\":\"full\"}" +
              "]}");
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmPublishLive(dir, err));
    const std::string raw = ReadRaw(dir / "swarm" / "networks.json");
    UniValue networks;
    BOOST_REQUIRE(networks.read(raw));
    BOOST_CHECK(networks["family"]["member_artifact_ids"].empty());
    BOOST_CHECK(networks["family"]["lineage_id"].get_str().empty());
    BOOST_CHECK(networks["cohort"]["member_ids"].empty());
    BOOST_REQUIRE_EQUAL(networks["families"].size(), 2U);
    BOOST_REQUIRE_EQUAL(networks["cohorts"].size(), 3U);
    BOOST_CHECK_EQUAL(networks["automatic_spend_atoms"].get_str(), "0");

    const auto family_has = [&](const std::string& id, const std::string& artifact) {
        for (const UniValue& family : networks["families"].getValues()) {
            if (family["lineage_id"].get_str() != id) continue;
            for (const UniValue& member : family["member_artifact_ids"].getValues()) {
                if (member.get_str() == artifact) return true;
            }
        }
        return false;
    };
    BOOST_CHECK(family_has(lineage, full));
    BOOST_CHECK(family_has(lineage, other));
    BOOST_CHECK(!family_has(lineage, remote));
    BOOST_CHECK(family_has(other_lineage, remote));

    bool saw_recipe = false;
    for (const UniValue& cohort : networks["cohorts"].getValues()) {
        BOOST_CHECK_EQUAL(cohort["recipe_id"].get_str(), "recipe");
        const bool has_full = [&] {
            for (const UniValue& id : cohort["member_ids"].getValues()) {
                if (id.get_str() == full) return true;
            }
            return false;
        }();
        const bool has_other = [&] {
            for (const UniValue& id : cohort["member_ids"].getValues()) {
                if (id.get_str() == other) return true;
            }
            return false;
        }();
        BOOST_CHECK(!(has_full && has_other));
        if (has_full) {
            saw_recipe = true;
            BOOST_CHECK_EQUAL(cohort["checkpoint_id"].get_str(), "ckpt-a");
            BOOST_CHECK_EQUAL(cohort["lineage_id"].get_str(), lineage);
        }
    }
    BOOST_CHECK(saw_recipe);
    const UniValue& members = networks["families"][0]["members"];
    BOOST_CHECK(members[0].exists("checkpoint_id"));
    BOOST_CHECK(members[0].exists("recipe"));

    UniValue times;
    BOOST_REQUIRE(times.read(ReadRaw(dir / "swarm" / "timescales.json")));
    BOOST_REQUIRE_EQUAL(times["long"].size(), 2U);
    BOOST_CHECK_EQUAL(times["automatic_spend_atoms"].get_str(), "0");

    const auto old = fs::file_time_type::clock::now() - std::chrono::hours(3);
    fs::last_write_time(dir / "swarm" / "networks.json", old);
    const auto stamp = fs::last_write_time(dir / "swarm" / "networks.json");
    BOOST_REQUIRE(modelnet::SwarmPublishLive(dir, err));
    BOOST_CHECK(fs::last_write_time(dir / "swarm" / "networks.json") == stamp);

    Write(dir / "swarm" / "contribution.json",
          std::string("{\"automatic_spend_atoms\":\"0\",\"models\":[") +
              "{\"acquire\":\"joined\",\"artifact_id\":\"" + full +
              "\",\"cohort\":true,\"checkpoint_id\":\"ckpt-a\",\"recipe\":\"recipe\",\"lineage_id\":\"" + lineage +
              "\",\"quantization\":\"full\"}," +
              "{\"acquire\":\"joined\",\"artifact_id\":\"" + other +
              "\",\"cohort\":true,\"checkpoint_id\":\"ckpt-b\",\"recipe\":\"recipe\",\"lineage_id\":\"" + lineage +
              "\",\"quantization\":\"full\"}" +
              "]}");
    BOOST_REQUIRE(modelnet::SwarmPublishLive(dir, err));
    UniValue removed;
    BOOST_REQUIRE(removed.read(ReadRaw(dir / "swarm" / "networks.json")));
    BOOST_REQUIRE_EQUAL(removed["families"].size(), 1U);
    BOOST_CHECK_EQUAL(removed["family"]["lineage_id"].get_str(), lineage);
    BOOST_CHECK_EQUAL(removed["family"]["member_artifact_ids"].size(), 2U);
    bool still_remote = false;
    for (const UniValue& family : removed["families"].getValues()) {
        if (family["lineage_id"].get_str() == other_lineage) still_remote = true;
    }
    BOOST_CHECK(!still_remote);
    BOOST_REQUIRE_EQUAL(removed["cohorts"].size(), 2U);
    fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(prompt_is_private_and_writes_nothing)
{
    const fs::path dir = Scratch();
    std::string err;
    BOOST_CHECK(!modelnet::SwarmStorePublicKnowledge(dir, "prompt", "secret prompt", err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!fs::exists(dir / "swarm" / "knowledge.json"));
    BOOST_CHECK(!modelnet::SwarmStorePublicKnowledge(dir, "repository", "git@example", err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!modelnet::SwarmStorePublicKnowledge(dir, "credential", "token", err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!modelnet::SwarmStorePublicKnowledge(dir, "note", "other", err));
    BOOST_CHECK_EQUAL(err, "KNOWLEDGE_KIND");
    BOOST_CHECK(!fs::exists(dir / "swarm" / "knowledge.json"));
    fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(finding_is_stored_and_readable)
{
    const fs::path dir = Scratch();
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmStorePublicKnowledge(dir, "finding", "a public finding", err));
    BOOST_REQUIRE(modelnet::SwarmStorePublicKnowledge(dir, "finding", "another finding", err));
    UniValue root;
    BOOST_REQUIRE(root.read(ReadRaw(dir / "swarm" / "knowledge.json")));
    BOOST_CHECK(!root["private_prompt_log"].get_bool());
    BOOST_CHECK(!root.exists("prompt"));
    BOOST_REQUIRE_EQUAL(root["finding"].size(), 2U);
    BOOST_CHECK_EQUAL(root["finding"][0].get_str(), "a public finding");
    BOOST_CHECK_EQUAL(root["finding"][1].get_str(), "another finding");
    BOOST_CHECK(root["strategy"].isArray());
    BOOST_CHECK(root["evaluation"].isArray());
    BOOST_CHECK(root["adapter"].isArray());
    BOOST_CHECK(root["generation"].isArray());
    BOOST_CHECK_EQUAL(root["automatic_spend_atoms"].get_str(), "0");
    fs::remove_all(dir);
}

BOOST_AUTO_TEST_SUITE_END()
