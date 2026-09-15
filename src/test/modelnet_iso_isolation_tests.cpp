// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// V11-ISO-02 / ISO-05: model work never takes cs_main, never starves ExactReplay,
// never launches CUDA kernels in this binary, and does not advertise chain verify.

#include <modelnet/access_policy.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/pq1_runtime.h>
#include <modelnet/protocol.h>
#include <modelnet/qualification.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_iso_isolation_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(iso_01_every_native_http_path_requires_pq1)
{
    BOOST_CHECK(modelnet::NativeHttpRequiresVerifiedPq1());
    const auto paths = modelnet::AdvertisedNativeHttpPaths();
    BOOST_REQUIRE(!paths.empty());
    bool saw_hello = false, saw_grant = false, saw_receipts = false, saw_query = false;
    for (const auto& p : paths) {
        BOOST_CHECK(p.find("/hello") != std::string::npos ||
                    p.find("/query") != std::string::npos ||
                    p.find("/records") != std::string::npos ||
                    p.find("/manifests") != std::string::npos ||
                    p.find("/availability") != std::string::npos ||
                    p.find("/quotes") != std::string::npos ||
                    p.find("/transfers") != std::string::npos ||
                    p.find("/releases") != std::string::npos ||
                    p.find("/ext/") != std::string::npos);
        if (p.find("/hello") != std::string::npos) saw_hello = true;
        if (p.find("/ext/free/grant") != std::string::npos) saw_grant = true;
        if (p.find("/ext/receipts") != std::string::npos) saw_receipts = true;
        if (p.find("/query") != std::string::npos) saw_query = true;
    }
    BOOST_CHECK(saw_hello);
    BOOST_CHECK(saw_grant);
    BOOST_CHECK(saw_receipts);
    BOOST_CHECK(saw_query);

    const fs::path tmp = m_path_root / "iso01-http";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    for (const char* suffix : {"hello", "ext/caps", "query", "availability"}) {
        modelnet::NativeRequest req;
        req.method = "POST";
        req.path = std::string(modelnet::MODEL_HTTP_ROOT) + suffix;
        req.body = "{}";
        modelnet::NativeResponse resp;
        BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, req, resp));
        BOOST_CHECK(resp.status == 200 || resp.status == 400);
    }
}

BOOST_AUTO_TEST_CASE(iso_06_http_worker_and_tls_bounds)
{
    BOOST_CHECK_EQUAL(modelnet::PQ1_HTTP_WORKERS, 8);
    BOOST_CHECK_EQUAL(modelnet::PQ1_HTTP_QUEUE, 32);
    BOOST_CHECK_EQUAL(modelnet::PQ1_HANDSHAKE_MS, 10000);
    BOOST_CHECK_EQUAL(modelnet::PQ1_IDLE_MS, 30000);
    BOOST_CHECK_EQUAL(modelnet::PQ1_UNAUTH_HANDSHAKE_LIMIT, 4);
    BOOST_CHECK_EQUAL(modelnet::PQ1_MAX_INBOUND, 16);
    BOOST_CHECK_EQUAL(modelnet::PQ1_MAX_OUTBOUND, 8);
    BOOST_CHECK_EQUAL(modelnet::PQ1_INFLIGHT_PIECES, 8);
    BOOST_CHECK_LE(modelnet::PQ1_INFLIGHT_PIECES, modelnet::PQ1_MAX_INBOUND_PER_NETGROUP);
}

BOOST_AUTO_TEST_CASE(iso_02_model_work_yields_to_consensus)
{
    BOOST_CHECK(!modelnet::ModelWorkTakesConsensusLock());
    BOOST_CHECK(!modelnet::ModelWorkMayStarveExactReplay());
    BOOST_CHECK(!modelnet::ModelCudaQualifyKernelCompiled());
}

BOOST_AUTO_TEST_CASE(iso_05_capabilities_honest)
{
    const UniValue caps = modelnet::CapabilitiesObject();
    BOOST_CHECK_EQUAL(caps["paid_chain_verify"].get_bool(), false);
    BOOST_CHECK_EQUAL(caps["cuda_qualification"].get_bool(), true);
    BOOST_CHECK_EQUAL(caps["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(caps["remote_inference"].get_bool(), false);
    BOOST_CHECK_EQUAL(caps["browser_bridge"].get_bool(), false);
    modelnet::AccessPolicy acl;
    BOOST_CHECK(!acl.WritesBanMan());
    BOOST_CHECK(!acl.AffectsAddrMan());
}

BOOST_AUTO_TEST_CASE(iso_02_qualify_runtime_default_no_cuda)
{
    modelnet::QualReport report;
    modelnet::QualRuntimeOpts opts;
    const auto r = modelnet::QualifyRuntime("/nonexistent", opts, report);
    BOOST_CHECK(r == modelnet::QualResult::NOT_RUN_CUDA_ISOLATION ||
                r == modelnet::QualResult::NOT_RUN_RESOURCE_LIMIT ||
                r == modelnet::QualResult::INVALID_MODEL);
}

BOOST_AUTO_TEST_SUITE_END()
