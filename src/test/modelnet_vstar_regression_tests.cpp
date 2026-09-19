// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Independent V-*/AUD-* regressions. Would fail on the vulnerable versions.

#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/hcp.h>
#include <modelnet/helper.h>
#include <modelnet/piece_picker.h>
#include <modelnet/provider_route.h>
#include <modelnet/s3_client.h>
#include <modelnet/selective_files.h>
#include <modelnet/transfer_session.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <fstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_vstar_regression_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> TinySafeTensors(unsigned char tag)
{
    const std::string json = "{\"__metadata__\":{\"t\":\"" + std::to_string(static_cast<int>(tag)) + "\"}}";
    std::vector<unsigned char> st(8 + json.size(), 0);
    WriteLE64(st.data(), json.size());
    std::memcpy(st.data() + 8, json.data(), json.size());
    return st;
}

} // namespace

BOOST_AUTO_TEST_CASE(vstar_put_fetched_unknown_artifact_rejected)
{
    const fs::path tmp = m_path_root / "vstar-unknown";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    fs::create_directories(tmp / "src");
    const auto st = TinySafeTensors(0x71);
    {
        std::ofstream out(tmp / "src" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::CatalogEntry imported;
    std::string err;
    BOOST_REQUIRE(cat.ImportPath(fs::PathToString(tmp / "src"), false, imported, err));
    std::vector<unsigned char> bytes;
    std::vector<modelnet::Digest48> proof;
    uint64_t file_size = 0;
    BOOST_REQUIRE(cat.GetVerifiedPiece(imported.artifact_id, 0, 0, bytes, proof, file_size, err));
    BOOST_CHECK(!cat.PutFetchedPiece(imported.artifact_id, 9, 0, bytes, proof, file_size,
                                      imported.core.files[0].pieces_root, err));
    modelnet::Digest48 unknown{};
    unknown.data[5] = 0xaa;
    BOOST_CHECK(!cat.PutFetchedPiece(unknown, 0, 0, bytes, proof, file_size,
                                     imported.core.files[0].pieces_root, err));
}

BOOST_AUTO_TEST_CASE(vstar_diversity_key_not_netgroup)
{
    using namespace modelnet;
    PeerId a;
    a.endpoint = "10.0.0.1:1";
    a.service_id = "svc-a";
    a.netgroup = "same-ng";
    PeerId b;
    b.endpoint = "10.0.0.2:1";
    b.service_id = "svc-b";
    b.netgroup = "same-ng";
    BOOST_CHECK(DiversityKey(a) != DiversityKey(b));
    BOOST_CHECK_EQUAL(NetgroupKey(a), NetgroupKey(b));
    PeerId c;
    c.endpoint = "10.0.0.3:1";
    c.netgroup = "same-ng";
    BOOST_CHECK_EQUAL(DiversityKey(c).substr(0, 3), "ep:");
    BOOST_CHECK(DiversityKey(a) != DiversityKey(c));
}

BOOST_AUTO_TEST_CASE(vstar_credit_ceiling_cannot_bypass)
{
    using namespace modelnet;
    CreditBroker broker{modelnet::PIECE_SIZE};
    TransferSession sess(broker);
    uint64_t id1 = 0, id2 = 0;
    std::string err;
    BOOST_REQUIRE(sess.ReserveAndQueue("fast", 0, 0, PIECE_SIZE, id1, err));
    BOOST_CHECK(!sess.ReserveAndQueue("also", 0, 1, PIECE_SIZE, id2, err));
}

BOOST_AUTO_TEST_CASE(vstar_xor_bucket_bit_not_byte)
{
    using namespace modelnet;
    Digest48 self{};
    Digest48 msb = self;
    msb.data[0] = 0x80;
    Digest48 lsb = self;
    lsb.data[0] = 0x01;
    BOOST_CHECK_EQUAL(RoutingBucketIndex(self, msb), 0);
    BOOST_CHECK_EQUAL(RoutingBucketIndex(self, lsb), 7);
}

BOOST_AUTO_TEST_CASE(vstar_incomplete_selection_not_complete)
{
    modelnet::SelectiveFileSet sel;
    sel.SelectOnly({0});
    BOOST_CHECK(!sel.AllFiles());
    BOOST_CHECK(!sel.AdvertiseHave(1));
}

BOOST_AUTO_TEST_CASE(vstar_hcp_import_refuses_secrets)
{
    const fs::path tmp = m_path_root / "vstar-hcp";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue params(UniValue::VARR);
    UniValue o(UniValue::VOBJ);
    o.pushKV("secret", "BTX_TEST_SECRET_SENTINEL");
    o.pushKV("wallet_seed", "BTX_TEST_SECRET_SENTINEL");
    params.push_back(o);
    UniValue result;
    std::string code, err;
    BOOST_CHECK(!modelnet::DispatchHcpRpc(cat, "importhcpstate", params, result, code, err));
    const std::string blob = result.write() + err + code;
    BOOST_CHECK(blob.find("BTX_TEST_SECRET_SENTINEL") == std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
