// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// STORE2-01  store2_01_local_adapter_equals_modelstore
// STORE2-02  store2_02_tiered_miss_fills_local
// STORE2-03  store2_03_never_serve_unverified
// STORE2-04  store2_04_restart_residency

#include <modelnet/piece_store.h>
#include <modelnet/store.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_store2_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> TinyPiece(const std::string& payload)
{
    return std::vector<unsigned char>(payload.begin(), payload.end());
}

class FakeCloudObjectStore : public modelnet::CloudObjectStore
{
public:
    std::map<std::string, std::vector<unsigned char>> objects;

    bool GetObject(const std::string& key, uint64_t offset, uint64_t len,
                    std::vector<unsigned char>& out, std::string& err) override
    {
        const auto it = objects.find(key);
        if (it == objects.end()) {
            err = "missing object";
            return false;
        }
        if (offset > it->second.size()) {
            err = "range";
            return false;
        }
        const uint64_t avail = it->second.size() - offset;
        const uint64_t n = len == 0 ? avail : std::min(len, avail);
        out.assign(it->second.begin() + static_cast<std::ptrdiff_t>(offset),
                   it->second.begin() + static_cast<std::ptrdiff_t>(offset + n));
        return true;
    }

    bool PutObject(const std::string& key, std::istream& body, uint64_t content_length,
                    std::string& err) override
    {
        std::vector<unsigned char> buf;
        if (content_length > 0) {
            buf.resize(content_length);
            body.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(content_length));
            if (body.gcount() != static_cast<std::streamsize>(content_length)) {
                err = "short put";
                return false;
            }
        } else {
            buf.assign(std::istreambuf_iterator<char>(body), std::istreambuf_iterator<char>());
        }
        objects[key] = std::move(buf);
        return true;
    }

    bool HeadObject(const std::string& key, uint64_t& size, std::string& err) const override
    {
        const auto it = objects.find(key);
        if (it == objects.end()) {
            err = "missing object";
            return false;
        }
        size = it->second.size();
        return true;
    }

    bool DeleteObject(const std::string& key, std::string& err) override
    {
        (void)err;
        objects.erase(key);
        return true;
    }

    modelnet::PieceStoreHealth Health() const override
    {
        modelnet::PieceStoreHealth h;
        h.ok = true;
        h.backend = "fake";
        h.cloud_objects = objects.size();
        return h;
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(store2_01_local_adapter_equals_modelstore)
{
    const fs::path tmp = m_path_root / "store2-01";
    modelnet::LocalPieceStore local{tmp, /*quota*/ 4096};
    modelnet::Digest48 art{};
    art.data[0] = 0xB1;
    const auto bytes = TinyPiece("store2-tiny-piece");
    BOOST_REQUIRE_LT(bytes.size(), modelnet::PIECE_SIZE);
    const auto leaf = modelnet::ChunkLeaf(0, bytes);
    std::string err;
    BOOST_REQUIRE_MESSAGE(local.PutVerifiedPiece(art, 0, 0, bytes, leaf, err), err);

    BOOST_CHECK(local.HasPiece(art, 0, 0));
    BOOST_CHECK(local.Store().HasPiece(art, 0, 0));
    BOOST_CHECK(local.Residency(art, 0, 0) == modelnet::PieceResidency::LOCAL);

    std::vector<unsigned char> via_adapter;
    std::vector<unsigned char> via_store;
    BOOST_REQUIRE(local.GetPiece(art, 0, 0, via_adapter, err));
    BOOST_REQUIRE(local.Store().GetPiece(art, 0, 0, via_store, err));
    BOOST_CHECK(via_adapter == bytes);
    BOOST_CHECK(via_store == bytes);

    std::vector<uint32_t> listed;
    BOOST_REQUIRE(local.EnumerateCommittedPieces(art, 0, listed));
    BOOST_REQUIRE_EQUAL(listed.size(), 1U);
    BOOST_CHECK_EQUAL(listed[0], 0U);

    const modelnet::PieceStoreHealth h = local.Health();
    BOOST_CHECK(h.ok);
    BOOST_CHECK_EQUAL(h.backend, "local");
    BOOST_CHECK_GE(h.local_bytes, bytes.size());
}

BOOST_AUTO_TEST_CASE(store2_02_tiered_miss_fills_local)
{
    const fs::path tmp = m_path_root / "store2-02";
    auto local = std::make_unique<modelnet::LocalPieceStore>(tmp, /*quota*/ 4096);
    auto cloud = std::make_unique<FakeCloudObjectStore>();
    FakeCloudObjectStore* fake = cloud.get();
    modelnet::TieredPieceStorePolicy policy;
    policy.write_local = false;
    policy.write_cloud = true;
    policy.cache_cloud_hits_locally = true;
    modelnet::TieredPieceStore tiered(std::move(local), std::move(cloud), policy);

    modelnet::Digest48 art{};
    art.data[0] = 0xB2;
    const auto bytes = TinyPiece("store2-cloud-fill");
    const auto leaf = modelnet::ChunkLeaf(0, bytes);
    std::string err;
    BOOST_REQUIRE_MESSAGE(tiered.PutVerifiedPiece(art, 0, 0, bytes, leaf, err), err);
    BOOST_CHECK(tiered.Residency(art, 0, 0) == modelnet::PieceResidency::CLOUD);
    BOOST_CHECK(!tiered.Local().HasPiece(art, 0, 0));
    BOOST_CHECK(fake->objects.count(modelnet::PieceObjectKey(art, 0, 0)) == 1);

    std::vector<unsigned char> got;
    BOOST_REQUIRE_MESSAGE(tiered.GetPiece(art, 0, 0, got, err), err);
    BOOST_CHECK(got == bytes);
    BOOST_CHECK(tiered.Local().HasPiece(art, 0, 0));
    BOOST_CHECK(tiered.Residency(art, 0, 0) == modelnet::PieceResidency::BOTH);

    const modelnet::PieceStoreHealth h = tiered.Health();
    BOOST_CHECK(h.ok);
    BOOST_CHECK(h.backend.find("tiered") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(store2_03_never_serve_unverified)
{
    const fs::path tmp = m_path_root / "store2-03";
    modelnet::LocalPieceStore local{tmp / "local", /*quota*/ 4096};
    modelnet::Digest48 art{};
    art.data[0] = 0xB3;
    const auto bytes = TinyPiece("store2-verified");
    const auto leaf = modelnet::ChunkLeaf(0, bytes);
    modelnet::Digest48 wrong{};
    wrong.data[0] = 0xff;
    std::string err;
    BOOST_CHECK(!local.PutVerifiedPiece(art, 0, 0, bytes, wrong, err));
    BOOST_CHECK(err.find("corrupt") != std::string::npos);
    BOOST_CHECK(!local.HasPiece(art, 0, 0));
    BOOST_CHECK(local.Residency(art, 0, 0) == modelnet::PieceResidency::ABSENT);

    BOOST_REQUIRE(local.PutVerifiedPiece(art, 0, 0, bytes, leaf, err));
    const fs::path piece_path = tmp / "local" / "artifacts" / art.Hex().c_str() / "0" / "0.piece";
    {
        std::ofstream tamper(piece_path, std::ios::binary | std::ios::trunc);
        const char junk[] = "tampered-bytes";
        tamper.write(junk, sizeof(junk) - 1);
    }
    std::vector<unsigned char> got;
    err.clear();
    BOOST_CHECK(!local.GetPiece(art, 0, 0, got, err));
    BOOST_CHECK(err.find("corrupt") != std::string::npos);
    BOOST_CHECK(got.empty());

    auto loc2 = std::make_unique<modelnet::LocalPieceStore>(tmp / "tiered", /*quota*/ 4096);
    auto cloud = std::make_unique<FakeCloudObjectStore>();
    FakeCloudObjectStore* fake = cloud.get();
    modelnet::TieredPieceStorePolicy policy;
    policy.write_local = false;
    policy.write_cloud = true;
    modelnet::TieredPieceStore tiered(std::move(loc2), std::move(cloud), policy);
    BOOST_REQUIRE(tiered.PutVerifiedPiece(art, 0, 1, bytes, modelnet::ChunkLeaf(1, bytes), err));
    const std::string key = modelnet::PieceObjectKey(art, 0, 1);
    BOOST_REQUIRE(fake->objects.count(key) == 1);
    fake->objects[key] = TinyPiece("garbage-not-the-piece");
    std::vector<unsigned char> cloud_got;
    err.clear();
    BOOST_CHECK(!tiered.GetPiece(art, 0, 1, cloud_got, err));
    BOOST_CHECK(err.find("corrupt") != std::string::npos);
    BOOST_CHECK(!tiered.Local().HasPiece(art, 0, 1));
}

BOOST_AUTO_TEST_CASE(store2_04_restart_residency)
{
    const fs::path tmp = m_path_root / "store2-04";
    modelnet::Digest48 art{};
    art.data[0] = 0xB4;
    const auto bytes = TinyPiece("store2-restart");
    const auto leaf = modelnet::ChunkLeaf(0, bytes);
    std::string err;
    {
        modelnet::LocalPieceStore local{tmp / "local", /*quota*/ 4096};
        BOOST_REQUIRE(local.PutVerifiedPiece(art, 0, 0, bytes, leaf, err));
        BOOST_CHECK(local.Residency(art, 0, 0) == modelnet::PieceResidency::LOCAL);
    }
    BOOST_CHECK(fs::exists(tmp / "local" / "residency.json"));
    {
        std::ifstream in(tmp / "local" / "residency.json");
        const std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        BOOST_CHECK(raw.find("secret") == std::string::npos);
        BOOST_CHECK(raw.find("etag") == std::string::npos);
        BOOST_CHECK(raw.find("credential") == std::string::npos);
        BOOST_CHECK(raw.find("LOCAL") != std::string::npos);
    }
    {
        modelnet::LocalPieceStore local{tmp / "local", /*quota*/ 4096};
        BOOST_CHECK(local.Residency(art, 0, 0) == modelnet::PieceResidency::LOCAL);
        std::vector<unsigned char> got;
        BOOST_REQUIRE(local.GetPiece(art, 0, 0, got, err));
        BOOST_CHECK(got == bytes);
    }

    {
        auto local = std::make_unique<modelnet::LocalPieceStore>(tmp / "tiered", /*quota*/ 4096);
        auto cloud = std::make_unique<FakeCloudObjectStore>();
        modelnet::TieredPieceStorePolicy policy;
        policy.write_local = false;
        policy.write_cloud = true;
        modelnet::TieredPieceStore tiered(std::move(local), std::move(cloud), policy);
        BOOST_REQUIRE(tiered.PutVerifiedPiece(art, 0, 0, bytes, leaf, err));
        BOOST_CHECK(tiered.Residency(art, 0, 0) == modelnet::PieceResidency::CLOUD);
        BOOST_CHECK(!tiered.Local().HasPiece(art, 0, 0));
    }
    BOOST_CHECK(fs::exists(tmp / "tiered" / "residency.json"));
    {
        auto local = std::make_unique<modelnet::LocalPieceStore>(tmp / "tiered", /*quota*/ 4096);
        auto cloud = std::make_unique<FakeCloudObjectStore>();
        modelnet::TieredPieceStorePolicy policy;
        policy.write_local = false;
        policy.write_cloud = true;
        modelnet::TieredPieceStore tiered(std::move(local), std::move(cloud), policy);
        BOOST_CHECK(tiered.Residency(art, 0, 0) == modelnet::PieceResidency::CLOUD);
        BOOST_CHECK(!tiered.Local().HasPiece(art, 0, 0));
        BOOST_CHECK(tiered.HasPiece(art, 0, 0));
    }
}

BOOST_AUTO_TEST_SUITE_END()
