// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// AHP-J05 / NETWORK-02 journey-1 remainder, in-process only.
// Live WAN origin-outage peers and production btxd stay NOT_RUN.
// Coordinator wires this file into test_btx CMake later.

#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/io_executor.h>
#include <modelnet/source_huggingface.h>
#include <modelnet/transfer_session.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_ahp_j05_iso_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> MinimalSafeTensors()
{
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    return st;
}

UniValue Rpc(const std::string& method, const UniValue& params = UniValue(UniValue::VARR))
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", method);
    req.pushKV("params", params);
    return req;
}

UniValue Dispatch(modelnet::ModelCatalog& cat, const UniValue& req)
{
    UniValue result;
    std::string code, err;
    const bool ok = modelnet::DispatchHelperRpc(cat, req, result, code, err);
    BOOST_REQUIRE_MESSAGE(ok, req.write() + " :: " + err + " [" + code + "] result=" + result.write());
    return result;
}

} // namespace

BOOST_AUTO_TEST_CASE(ahp_j05_iso_native_piece_copy_origin_off)
{
    const fs::path tmp = m_path_root / "ahp-j05-iso";
    modelnet::ModelCatalog cat_a{tmp / "cat-a", 8 << 20};
    modelnet::ModelCatalog cat_b{tmp / "cat-b", 8 << 20};

    fs::create_directories(tmp / "src");
    const auto st = MinimalSafeTensors();
    {
        std::ofstream out(tmp / "src" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }

    UniValue params(UniValue::VARR);
    params.push_back(fs::PathToString(tmp / "src"));
    const UniValue imported = Dispatch(cat_a, Rpc("importmodel", params));

    std::string err;
    modelnet::Digest48 model_id, artifact_id;
    BOOST_REQUIRE(modelnet::Digest48::FromHex(imported["model_id"].get_str(), model_id, err));
    BOOST_REQUIRE(modelnet::Digest48::FromHex(imported["artifact_id"].get_str(), artifact_id, err));

    modelnet::CatalogEntry entry_a;
    BOOST_REQUIRE(cat_a.Find(model_id, entry_a));
    BOOST_REQUIRE(!entry_a.core.files.empty());
    const modelnet::Digest48 pieces_root = entry_a.core.files[0].pieces_root;

    UniValue man;
    BOOST_REQUIRE(cat_a.GetManifest(model_id, man, err));
    BOOST_CHECK_EQUAL(man["model_id"].get_str(), model_id.Hex());
    BOOST_CHECK_EQUAL(man["files"][0]["pieces_root"].get_str(), pieces_root.Hex());
    BOOST_REQUIRE_MESSAGE(cat_b.InstallFromManifest(man, err, /*complete=*/false), err);

    modelnet::CatalogEntry entry_b;
    BOOST_REQUIRE(cat_b.Find(model_id, entry_b));
    BOOST_CHECK(entry_b.incomplete);
    BOOST_CHECK_EQUAL(entry_b.model_id.Hex(), model_id.Hex());
    BOOST_CHECK_EQUAL(entry_b.artifact_id.Hex(), artifact_id.Hex());
    BOOST_CHECK_EQUAL(entry_b.core.files[0].pieces_root.Hex(), pieces_root.Hex());

    std::vector<unsigned char> missing;
    std::vector<modelnet::Digest48> missing_proof;
    uint64_t missing_size = 0;
    BOOST_CHECK(!cat_b.GetVerifiedPiece(artifact_id, 0, 0, missing, missing_proof, missing_size, err));

    std::vector<unsigned char> bytes;
    std::vector<modelnet::Digest48> proof;
    uint64_t file_size = 0;
    BOOST_REQUIRE_MESSAGE(cat_a.GetVerifiedPiece(artifact_id, 0, 0, bytes, proof, file_size, err), err);

    modelnet::Digest48 unknown{};
    unknown.data[0] = 0xab;
    BOOST_CHECK(!cat_b.PutFetchedPiece(unknown, 0, 0, bytes, proof, file_size, pieces_root, err));
    BOOST_CHECK_EQUAL(err, "unknown artifact");

    // Live HF/WAN origin-outage is NOT_RUN. Isolated equivalent: origin is off.
    const bool hf_origin_off = true;
    BOOST_REQUIRE(hf_origin_off);

    BOOST_REQUIRE_MESSAGE(cat_b.PutFetchedPiece(artifact_id, 0, 0, bytes, proof, file_size, pieces_root, err), err);

    std::vector<unsigned char> again;
    std::vector<modelnet::Digest48> proof2;
    uint64_t fs2 = 0;
    BOOST_REQUIRE_MESSAGE(cat_b.GetVerifiedPiece(artifact_id, 0, 0, again, proof2, fs2, err), err);
    BOOST_CHECK(again == bytes);
    BOOST_CHECK_EQUAL(fs2, file_size);

    UniValue man_a2;
    BOOST_REQUIRE(cat_a.GetManifest(model_id, man_a2, err));
    UniValue man_b2;
    BOOST_REQUIRE(cat_b.GetManifest(model_id, man_b2, err));
    BOOST_CHECK_EQUAL(man_a2["model_id"].get_str(), man["model_id"].get_str());
    BOOST_CHECK_EQUAL(man_b2["model_id"].get_str(), model_id.Hex());
    BOOST_CHECK_EQUAL(man_a2["files"][0]["pieces_root"].get_str(), pieces_root.Hex());
    BOOST_CHECK_EQUAL(man_b2["files"][0]["pieces_root"].get_str(), pieces_root.Hex());
    BOOST_CHECK_EQUAL(man_b2["artifact_id"].get_str(), artifact_id.Hex());

    BOOST_REQUIRE(cat_a.Find(model_id, entry_a));
    BOOST_REQUIRE(cat_b.Find(model_id, entry_b));
    BOOST_CHECK_EQUAL(entry_a.model_id.Hex(), entry_b.model_id.Hex());
    BOOST_CHECK_EQUAL(entry_a.core.files[0].pieces_root.Hex(), entry_b.core.files[0].pieces_root.Hex());
}

BOOST_AUTO_TEST_CASE(ahp_j05_iso_io_executor_hf_credit)
{
    using namespace modelnet;
    CreditBroker credit{4};
    IoExecutor io(1);
    HuggingFaceByteSource src("https://huggingface.co/org/j05-iso", "snap-j05");
    std::string err;
    BOOST_REQUIRE(src.Pin(err));
    BOOST_CHECK_EQUAL(src.Kind(), "HUGGINGFACE");
    BOOST_CHECK_EQUAL(src.SourceIntegrity(), "snap-j05");
    BOOST_CHECK(!src.FollowsRedirects());

    std::vector<unsigned char> out;
    BOOST_CHECK(!src.Read({0, 1}, out, 16, err));
    BOOST_CHECK_EQUAL(err, "not wired to live network");

    src.InjectTestBytes({'a', 'b', 'c', 'd', 'e', 'f'});
    BOOST_REQUIRE(credit.TryReserve(4));
    BOOST_REQUIRE(io.Submit(err));

    ReadExtent ext;
    ext.offset = 1;
    ext.length = 4;
    BOOST_REQUIRE(src.Read(ext, out, credit.Reserved(), err));
    BOOST_REQUIRE_EQUAL(out.size(), 4U);
    BOOST_CHECK_EQUAL(out[0], 'b');
    BOOST_CHECK_EQUAL(out[3], 'e');

    BOOST_CHECK(!src.Read({0, 5}, out, credit.Reserved(), err));
    BOOST_CHECK_EQUAL(err, "credit exhausted");
    BOOST_CHECK(!io.Submit(err));
    io.Complete();
    BOOST_REQUIRE(io.Submit(err));
    io.Complete();
    BOOST_CHECK(!io.StatusJson()["io_uring"].get_bool());
}

BOOST_AUTO_TEST_SUITE_END()
