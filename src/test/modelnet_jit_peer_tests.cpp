// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// BTX-SPEC-0348-CAPABILITY-01 Worker J — native PEER + DIRECT.
//   JIT-PEER-01  private membership
//   JIT-PEER-02  exact geometry
//   JIT-PEER-03  destination checks
//   JIT-PEER-04  memory registration scope
//   JIT-PEER-05  timeout buffer lifetime
//   JIT-PEER-06  assurance labeling
//   JIT-PEER-07  real backend startup (NIXL/GDS NOT_RUN if libs absent)
//   JIT-DIRECT-01  verified source fast path
//   JIT-DIRECT-02  unverified origin
//   JIT-DIRECT-03  alignment fallback
//   JIT-DIRECT-04  no false zero-copy
//   JIT-DIRECT-05  cancel GDS
//   JIT-DIRECT-06  ROCm/Metal distinction
//   JIT-DIRECT-07  fast-path parity
//
// Coordinator owns CMakeLists.txt. Do not ninja from this lane.
// Absent NIXL/GDS is NOT_RUN, never a stub-deleted probe or fake PASS.

#include <crypto/sha384.h>
#include <modelnet/capability.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <string>
#include <vector>

namespace modelnet {
void ResetPeerTransferStateForTests();
bool PeerDestinationBeforeCompute(Span<const unsigned char> received, const Digest48& expected, bool& compute_started,
                                  std::string& err_code, std::string& err);
bool CancelMidPeerTransfer(const Generation16& gen, bool still_inflight, PhysicalDisposition& disp);
bool RevokePeerSourceThenHostFallback(std::vector<unsigned char>& source_buffer, std::vector<unsigned char>& dest,
                                      Generation16 gen, PhysicalDisposition& disp, std::string& err);
} // namespace modelnet

BOOST_FIXTURE_TEST_SUITE(modelnet_jit_peer_tests, BasicTestingSetup)

namespace {

struct EnvRestore {
    const char* key;
    std::string old;
    bool had{false};
    explicit EnvRestore(const char* k) : key(k)
    {
        if (const char* v = std::getenv(k)) {
            had = true;
            old = v;
        }
    }
    ~EnvRestore()
    {
        if (had) ::setenv(key, old.c_str(), 1);
        else ::unsetenv(key);
    }
};

modelnet::Digest48 Sha384(Span<const unsigned char> bytes)
{
    modelnet::Digest48 d{};
    CSHA384 hasher;
    if (!bytes.empty()) hasher.Write(bytes.data(), bytes.size());
    hasher.Finalize(d.data.data());
    return d;
}

modelnet::TensorRange MakeTensor(const std::string& name, uint64_t offset, uint64_t length, const std::string& dtype,
                                 std::vector<int64_t> shape = {2, 8}, uint32_t file_index = 0)
{
    modelnet::TensorRange t;
    t.name = name;
    t.file_index = file_index;
    t.offset = offset;
    t.length = length;
    t.dtype = dtype;
    t.shape = std::move(shape);
    return t;
}

void AssertProbeHonesty(const modelnet::PeerTransferOffer& off)
{
    BOOST_REQUIRE(off.json.isObject());
    BOOST_REQUIRE(off.json.exists("stub"));
    BOOST_CHECK(!off.json["stub"].get_bool());
    BOOST_REQUIRE(off.json.exists("portable_host_buffer"));
    BOOST_CHECK(off.json["portable_host_buffer"].isTrue() || off.json["portable_host_buffer"].get_bool());
    BOOST_REQUIRE(off.json.exists("automatic_spend_atoms"));
    BOOST_CHECK_EQUAL(off.json["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_REQUIRE(off.json.exists("nixl_status"));
    BOOST_REQUIRE(off.json.exists("gds_status"));
    const std::string nixl_st = off.json["nixl_status"].get_str();
    const std::string gds_st = off.json["gds_status"].get_str();
    BOOST_CHECK(nixl_st == "PRESENT" || nixl_st == "NOT_RUN");
    BOOST_CHECK(gds_st == "PRESENT" || gds_st == "NOT_RUN");
    BOOST_CHECK(nixl_st != "PASS");
    BOOST_CHECK(gds_st != "PASS");
    if (!off.nixl_present) {
        BOOST_CHECK_EQUAL(nixl_st, "NOT_RUN");
        BOOST_CHECK_EQUAL(std::string(modelnet::TransportAssuranceName(off.assurance)), "HOST_BUFFER");
    } else {
        BOOST_CHECK_EQUAL(nixl_st, "PRESENT");
        BOOST_CHECK_EQUAL(std::string(modelnet::TransportAssuranceName(off.assurance)), "TRUSTED_FABRIC");
    }
    if (!off.gds_present) BOOST_CHECK_EQUAL(gds_st, "NOT_RUN");
}

} // namespace

BOOST_AUTO_TEST_CASE(JIT_PEER_01)
{
    BOOST_TEST_MESSAGE("JIT-PEER-01 private membership");
    modelnet::ResetPeerTransferStateForTests();
    std::string code, err;

    BOOST_CHECK(modelnet::PeerMembershipAllows("PRIVATE_FABRIC_APPROVED", "org-peer-a", code, err));
    BOOST_CHECK(code.empty());

    BOOST_CHECK(!modelnet::PeerMembershipAllows("PRIVATE_FABRIC_DISABLED", "org-peer-a", code, err));
    BOOST_CHECK_EQUAL(code, "FABRIC_POLICY_REQUIRED");

    BOOST_CHECK(!modelnet::PeerMembershipAllows("", "org-peer-a", code, err));
    BOOST_CHECK_EQUAL(code, "FABRIC_POLICY_REQUIRED");

    BOOST_CHECK(!modelnet::PeerMembershipAllows("PRIVATE_FABRIC_APPROVED", "", code, err));
    BOOST_CHECK_EQUAL(code, "FABRIC_POLICY_REQUIRED");

    BOOST_CHECK(!modelnet::PeerMembershipAllows("PRIVATE_FABRIC_APPROVED", "public-model-peer", code, err));
    BOOST_CHECK_EQUAL(code, "FABRIC_POLICY_REQUIRED");

    BOOST_CHECK(!modelnet::PeerMembershipAllows("PRIVATE_FABRIC_APPROVED", "wan-relay", code, err));
    BOOST_CHECK_EQUAL(code, "FABRIC_POLICY_REQUIRED");

    BOOST_CHECK(!modelnet::PeerMembershipAllows("PRIVATE_FABRIC_APPROVED", "https://example.invalid/peer", code, err));
    BOOST_CHECK_EQUAL(code, "FABRIC_POLICY_REQUIRED");
}

BOOST_AUTO_TEST_CASE(JIT_PEER_02)
{
    BOOST_TEST_MESSAGE("JIT-PEER-02 exact geometry");
    modelnet::ResetPeerTransferStateForTests();
    std::string code, err;
    modelnet::TensorRangeMap local;
    local.tensors.push_back(MakeTensor("attn.q", 0, 32, "F16", {4, 4}));
    local.tensors.push_back(MakeTensor("attn.k", 32, 32, "F16", {4, 4}));
    modelnet::TensorRangeMap peer = local;
    BOOST_CHECK(modelnet::PeerExactGeometry(local, peer, code, err));

    modelnet::TensorRangeMap name_only = local;
    name_only.tensors[1].offset = 64;
    name_only.tensors[1].length = 16;
    BOOST_CHECK(!modelnet::PeerExactGeometry(local, name_only, code, err));
    BOOST_CHECK_EQUAL(code, "REPRESENTATION_MISMATCH");

    modelnet::TensorRangeMap dtype = local;
    dtype.tensors[0].dtype = "F32";
    BOOST_CHECK(!modelnet::PeerExactGeometry(local, dtype, code, err));
    BOOST_CHECK_EQUAL(code, "REPRESENTATION_MISMATCH");

    modelnet::TensorRangeMap count = local;
    count.tensors.pop_back();
    BOOST_CHECK(!modelnet::PeerExactGeometry(local, count, code, err));
    BOOST_CHECK_EQUAL(code, "REPRESENTATION_MISMATCH");

    modelnet::TensorRangeMap layout = local;
    layout.tensors[0].shape = {2, 8};
    BOOST_CHECK(!modelnet::PeerExactGeometry(local, layout, code, err));
    BOOST_CHECK_EQUAL(code, "REPRESENTATION_MISMATCH");
}

BOOST_AUTO_TEST_CASE(JIT_PEER_03)
{
    BOOST_TEST_MESSAGE("JIT-PEER-03 destination checks");
    modelnet::ResetPeerTransferStateForTests();
    std::string code, err;
    const unsigned char good[] = {1, 2, 3, 4, 5, 6, 7, 8};
    const unsigned char bad[] = {9, 9, 9, 9, 9, 9, 9, 9};
    const modelnet::Digest48 expected = Sha384(good);

    BOOST_CHECK(!modelnet::VerifyPeerDestination(bad, expected, /*compute_started=*/false, code, err));
    BOOST_CHECK_EQUAL(code, "DESTINATION_UNVERIFIED");

    bool compute = true;
    BOOST_CHECK(!modelnet::VerifyPeerDestination(good, expected, /*compute_started=*/true, code, err));
    BOOST_CHECK_EQUAL(code, "DESTINATION_UNVERIFIED");
    BOOST_CHECK(compute);

    compute = false;
    BOOST_REQUIRE(modelnet::PeerDestinationBeforeCompute(good, expected, compute, code, err));
    BOOST_CHECK(compute);

    compute = false;
    BOOST_CHECK(!modelnet::PeerDestinationBeforeCompute(bad, expected, compute, code, err));
    BOOST_CHECK(!compute);
    BOOST_CHECK_EQUAL(code, "DESTINATION_UNVERIFIED");
}

BOOST_AUTO_TEST_CASE(JIT_PEER_04)
{
    BOOST_TEST_MESSAGE("JIT-PEER-04 memory registration scope");
    modelnet::ResetPeerTransferStateForTests();
    std::string code, err;
    const uint64_t weight = 4096;
    BOOST_CHECK(modelnet::RegisterPeerMemoryNarrow(weight, weight, code, err));
    BOOST_CHECK(!modelnet::RegisterPeerMemoryNarrow(weight, weight * 64, code, err));
    BOOST_CHECK_EQUAL(code, "REGISTRATION_TOO_WIDE");
    BOOST_CHECK(!modelnet::RegisterPeerMemoryNarrow(weight, 0, code, err));
    BOOST_CHECK_EQUAL(code, "REGISTRATION_TOO_WIDE");
    BOOST_CHECK(modelnet::RegisterPeerMemoryNarrow(0, 0, code, err));
}

BOOST_AUTO_TEST_CASE(JIT_PEER_05)
{
    BOOST_TEST_MESSAGE("JIT-PEER-05 timeout buffer lifetime");
    modelnet::ResetPeerTransferStateForTests();
    const modelnet::Generation16 live = modelnet::NewGeneration();
    const modelnet::Generation16 stale = modelnet::NewGeneration();
    BOOST_REQUIRE(live != stale);

    modelnet::PhysicalDisposition disp{};
    BOOST_REQUIRE(modelnet::CancelMidPeerTransfer(live, /*still_inflight=*/true, disp));
    BOOST_CHECK_EQUAL(std::string(modelnet::PhysicalDispositionName(disp)), "STILL_IN_FLIGHT");
    BOOST_CHECK(modelnet::RetainUntilQuiescent(disp));

    std::string err;
    BOOST_CHECK(!modelnet::LatePeerCompletionAfterTimeout(live, stale, disp, err));
    BOOST_CHECK_EQUAL(err, "stale generation");
    BOOST_CHECK_EQUAL(std::string(modelnet::PhysicalDispositionName(disp)), "STILL_IN_FLIGHT");
    BOOST_CHECK(modelnet::RetainUntilQuiescent(disp));

    err.clear();
    BOOST_REQUIRE(modelnet::LatePeerCompletionAfterTimeout(live, live, disp, err));
    BOOST_CHECK_EQUAL(std::string(modelnet::PhysicalDispositionName(disp)), "STOPPED_QUIESCENT");
    BOOST_CHECK(!modelnet::RetainUntilQuiescent(disp));
}

BOOST_AUTO_TEST_CASE(JIT_PEER_05_late_dma_dest_lifetime)
{
    BOOST_TEST_MESSAGE("JIT-PEER-05 late DMA: same-generation HostBufferTransfer cannot swap an inflight dest");
    modelnet::ResetPeerTransferStateForTests();
    const modelnet::Generation16 gen = modelnet::NewGeneration();
    const modelnet::Generation16 other = modelnet::NewGeneration();
    BOOST_REQUIRE(gen != other);

    const unsigned char src_a[] = {0x11, 0x22, 0x33, 0x44};
    const unsigned char src_b[] = {0x99, 0x98, 0x97, 0x96};
    std::vector<unsigned char> dest;
    modelnet::PhysicalDisposition disp{};
    std::string err;
    BOOST_REQUIRE(modelnet::HostBufferTransfer(src_a, dest, gen, disp, err));
    BOOST_REQUIRE(modelnet::CancelMidPeerTransfer(gen, /*still_inflight=*/true, disp));
    BOOST_CHECK_EQUAL(std::string(modelnet::PhysicalDispositionName(disp)), "STILL_IN_FLIGHT");

    // Same generation host copy would dest.swap() the inflight buffer.
    err.clear();
    BOOST_CHECK(!modelnet::HostBufferTransfer(src_b, dest, gen, disp, err));
    BOOST_CHECK_EQUAL(err, "stale generation");
    BOOST_CHECK_EQUAL(std::string(modelnet::PhysicalDispositionName(disp)), "STILL_IN_FLIGHT");
    BOOST_REQUIRE_EQUAL(dest.size(), 4);
    BOOST_CHECK_EQUAL(dest[0], 0x11);
    BOOST_CHECK_EQUAL(dest[3], 0x44);

    dest.clear();
    err.clear();
    BOOST_CHECK(!modelnet::HostBufferTransfer(src_b, dest, other, disp, err));
    BOOST_CHECK_EQUAL(err, "stale generation");
    BOOST_CHECK(dest.empty());

    err.clear();
    BOOST_CHECK(!modelnet::LatePeerCompletionAfterTimeout(gen, other, disp, err));
    BOOST_CHECK_EQUAL(err, "stale generation");
    BOOST_CHECK_EQUAL(std::string(modelnet::PhysicalDispositionName(disp)), "STILL_IN_FLIGHT");

    err.clear();
    BOOST_REQUIRE(modelnet::LatePeerCompletionAfterTimeout(gen, gen, disp, err));
    BOOST_CHECK_EQUAL(std::string(modelnet::PhysicalDispositionName(disp)), "STOPPED_QUIESCENT");

    err.clear();
    BOOST_REQUIRE(modelnet::HostBufferTransfer(src_b, dest, other, disp, err));
    BOOST_REQUIRE_EQUAL(dest.size(), 4);
    BOOST_CHECK_EQUAL(dest[0], 0x99);

    const unsigned char src_c[] = {0x01, 0x02, 0x03, 0x04};
    err.clear();
    BOOST_CHECK(!modelnet::HostBufferTransfer(src_c, dest, modelnet::NewGeneration(), disp, err));
    BOOST_CHECK_EQUAL(err, "stale generation");
    BOOST_CHECK_EQUAL(dest[0], 0x99);

    dest.clear();
    err.clear();
    BOOST_REQUIRE(modelnet::HostBufferTransfer(src_c, dest, modelnet::NewGeneration(), disp, err));
    BOOST_REQUIRE_EQUAL(dest.size(), 4);
    BOOST_CHECK_EQUAL(dest[0], 0x01);

    modelnet::ResetPeerTransferStateForTests();
    const modelnet::Generation16 gen_a = modelnet::NewGeneration();
    const modelnet::Generation16 gen_b = modelnet::NewGeneration();
    const modelnet::Generation16 gen_c = modelnet::NewGeneration();
    dest.clear();
    dest.shrink_to_fit();
    BOOST_REQUIRE(modelnet::HostBufferTransfer(src_a, dest, gen_a, disp, err));
    std::vector<unsigned char> holder;
    holder.swap(dest);
    holder.clear();
    holder.shrink_to_fit();
    err.clear();
    BOOST_REQUIRE(modelnet::HostBufferTransfer(src_b, dest, gen_b, disp, err));
    BOOST_CHECK_EQUAL(dest[0], 0x99);
    err.clear();
    BOOST_CHECK(!modelnet::HostBufferTransfer(src_c, dest, gen_c, disp, err));
    BOOST_CHECK_EQUAL(err, "stale generation");
    BOOST_CHECK_EQUAL(dest[0], 0x99);
}

BOOST_AUTO_TEST_CASE(JIT_PEER_06)
{
    BOOST_TEST_MESSAGE("JIT-PEER-06 assurance labeling");
    modelnet::ResetPeerTransferStateForTests();

    {
        EnvRestore nixl("BTX_NIXL_LIB");
        ::unsetenv("BTX_NIXL_LIB");
        modelnet::PeerTransferOffer off;
        BOOST_REQUIRE(modelnet::ProbePeerBackends(off));
        AssertProbeHonesty(off);
        BOOST_CHECK(!off.nixl_present);
        BOOST_CHECK_EQUAL(std::string(modelnet::TransportAssuranceName(off.assurance)), "HOST_BUFFER");
        BOOST_REQUIRE(off.json.exists("assurance"));
        BOOST_CHECK_EQUAL(off.json["assurance"].get_str(), "HOST_BUFFER");
        BOOST_CHECK(off.json["assurance"].get_str() != "NATIVE_PQ1");
    }

    {
        EnvRestore nixl("BTX_NIXL_LIB");
#ifdef __APPLE__
        ::setenv("BTX_NIXL_LIB", "/bin/sh", 1);
        modelnet::PeerTransferOffer off;
        BOOST_REQUIRE(modelnet::ProbePeerBackends(off));
        AssertProbeHonesty(off);
        BOOST_CHECK(!off.nixl_present);
        BOOST_CHECK_EQUAL(std::string(modelnet::TransportAssuranceName(off.assurance)), "HOST_BUFFER");
        BOOST_TEST_MESSAGE("JIT-PEER-06 Apple: Linux NIXL is not a macOS path (NOT_RUN)");
#else
        ::setenv("BTX_NIXL_LIB", "/proc/self/exe", 1);
        modelnet::PeerTransferOffer off;
        BOOST_REQUIRE(modelnet::ProbePeerBackends(off));
        AssertProbeHonesty(off);
        BOOST_CHECK(off.nixl_present);
        BOOST_CHECK_EQUAL(std::string(modelnet::TransportAssuranceName(off.assurance)), "TRUSTED_FABRIC");
        BOOST_REQUIRE(off.json.exists("assurance"));
        BOOST_CHECK_EQUAL(off.json["assurance"].get_str(), "TRUSTED_FABRIC");
        BOOST_CHECK(off.json["assurance"].get_str() != "NATIVE_PQ1");
        BOOST_CHECK(off.json.exists("nixl_status") && off.json["nixl_status"].get_str() != "PASS");
#endif
    }

    {
        EnvRestore nixl("BTX_NIXL_LIB");
        ::setenv("BTX_NIXL_LIB", "/no/such/nixl-lib-btx-0348.so", 1);
        modelnet::PeerTransferOffer off;
        BOOST_REQUIRE(modelnet::ProbePeerBackends(off));
        AssertProbeHonesty(off);
        BOOST_CHECK(!off.nixl_present);
        BOOST_CHECK_EQUAL(std::string(modelnet::TransportAssuranceName(off.assurance)), "HOST_BUFFER");
    }
}

BOOST_AUTO_TEST_CASE(JIT_PEER_07)
{
    BOOST_TEST_MESSAGE("JIT-PEER-07 real backend startup");
    modelnet::ResetPeerTransferStateForTests();
    modelnet::PeerTransferOffer off;
    BOOST_REQUIRE(modelnet::ProbePeerBackends(off));
    AssertProbeHonesty(off);
    BOOST_CHECK(!off.json["stub"].get_bool());
    BOOST_CHECK(off.json["portable_host_buffer"].get_bool());

    if (!off.nixl_present) {
        BOOST_TEST_MESSAGE("JIT-PEER-07 NIXL NOT_RUN");
        BOOST_REQUIRE(off.json.exists("nixl_status"));
        BOOST_CHECK_EQUAL(off.json["nixl_status"].get_str(), "NOT_RUN");
    } else {
        BOOST_TEST_MESSAGE("JIT-PEER-07 NIXL lib path present; live RDMA smoke remains NOT_RUN (no mock PASS)");
    }
    if (!off.gds_present) {
        BOOST_TEST_MESSAGE("JIT-PEER-07 GDS NOT_RUN");
        BOOST_REQUIRE(off.json.exists("gds_status"));
        BOOST_CHECK_EQUAL(off.json["gds_status"].get_str(), "NOT_RUN");
    }

    std::vector<unsigned char> dest;
    modelnet::PhysicalDisposition d{};
    std::string err;
    const unsigned char src[] = {0xca, 0xfe, 0xba, 0xbe};
    BOOST_REQUIRE(modelnet::HostBufferTransfer(src, dest, modelnet::NewGeneration(), d, err));
    BOOST_CHECK_EQUAL(dest.size(), 4);
    BOOST_CHECK(dest[0] == 0xca && dest[3] == 0xbe);
    BOOST_CHECK_EQUAL(std::string(modelnet::PhysicalDispositionName(d)), "STOPPED_QUIESCENT");
}

BOOST_AUTO_TEST_CASE(JIT_DIRECT_01)
{
    BOOST_TEST_MESSAGE("JIT-DIRECT-01 verified source fast path");
    modelnet::ResetPeerTransferStateForTests();
    std::string code, err;
    modelnet::TransportAssurance path = modelnet::TransportAssurance::HOST_BUFFER;
    BOOST_REQUIRE(modelnet::DirectVerifiedSourcePath(/*source_verified=*/true, /*gds_aligned=*/true, path, code, err));
    BOOST_CHECK(path == modelnet::TransportAssurance::HOST_BUFFER ||
                path == modelnet::TransportAssurance::VERIFIED_EXTERNAL);
    BOOST_CHECK(std::string(modelnet::TransportAssuranceName(path)) != "NATIVE_PQ1");

    modelnet::PeerTransferOffer off;
    BOOST_REQUIRE(modelnet::ProbePeerBackends(off));
    if (!off.gds_present) {
        BOOST_CHECK_EQUAL(std::string(modelnet::TransportAssuranceName(path)), "HOST_BUFFER");
        BOOST_TEST_MESSAGE("JIT-DIRECT-01 GDS NOT_RUN; portable host path used");
    }

    const unsigned char verified[] = {11, 22, 33, 44};
    std::vector<unsigned char> dest;
    modelnet::PhysicalDisposition disp{};
    BOOST_REQUIRE(modelnet::HostBufferTransfer(verified, dest, modelnet::NewGeneration(), disp, err));
    bool compute = false;
    BOOST_REQUIRE(modelnet::PeerDestinationBeforeCompute(dest, Sha384(verified), compute, code, err));
    BOOST_CHECK(compute);
    BOOST_CHECK_EQUAL(std::string(modelnet::PhysicalDispositionName(disp)), "STOPPED_QUIESCENT");
}

BOOST_AUTO_TEST_CASE(JIT_DIRECT_02)
{
    BOOST_TEST_MESSAGE("JIT-DIRECT-02 unverified origin");
    modelnet::ResetPeerTransferStateForTests();
    std::string code, err;
    modelnet::TransportAssurance path = modelnet::TransportAssurance::VERIFIED_EXTERNAL;
    BOOST_CHECK(!modelnet::DirectVerifiedSourcePath(/*source_verified=*/false, /*gds_aligned=*/true, path, code, err));
    BOOST_CHECK_EQUAL(code, "UNVERIFIED_ORIGIN");
    BOOST_CHECK_EQUAL(std::string(modelnet::TransportAssuranceName(path)), "HOST_BUFFER");

    BOOST_CHECK(!modelnet::RejectUnverifiedOriginDirect(false, code, err));
    BOOST_CHECK_EQUAL(code, "UNVERIFIED_ORIGIN");
    BOOST_CHECK(modelnet::RejectUnverifiedOriginDirect(true, code, err));
}

BOOST_AUTO_TEST_CASE(JIT_DIRECT_03)
{
    BOOST_TEST_MESSAGE("JIT-DIRECT-03 alignment fallback");
    modelnet::ResetPeerTransferStateForTests();
    std::string code, err;
    modelnet::TransportAssurance path = modelnet::TransportAssurance::VERIFIED_EXTERNAL;
    BOOST_REQUIRE(modelnet::DirectVerifiedSourcePath(/*source_verified=*/true, /*gds_aligned=*/false, path, code, err));
    BOOST_CHECK_EQUAL(std::string(modelnet::TransportAssuranceName(path)), "HOST_BUFFER");

    path = modelnet::TransportAssurance::VERIFIED_EXTERNAL;
    BOOST_REQUIRE(modelnet::AlignmentFallbackHost(/*aligned=*/false, path));
    BOOST_CHECK_EQUAL(std::string(modelnet::TransportAssuranceName(path)), "HOST_BUFFER");

    path = modelnet::TransportAssurance::VERIFIED_EXTERNAL;
    BOOST_REQUIRE(modelnet::AlignmentFallbackHost(/*aligned=*/true, path));
    BOOST_CHECK_EQUAL(std::string(modelnet::TransportAssuranceName(path)), "VERIFIED_EXTERNAL");

    std::vector<unsigned char> source = {1, 2, 3, 4, 5};
    std::vector<unsigned char> dest;
    modelnet::PhysicalDisposition disp{};
    BOOST_REQUIRE(modelnet::RevokePeerSourceThenHostFallback(source, dest, modelnet::NewGeneration(), disp, err));
    BOOST_CHECK(source.empty());
    BOOST_CHECK_EQUAL(dest.size(), 5);
    BOOST_CHECK(dest[0] == 1 && dest[4] == 5);
    BOOST_CHECK_EQUAL(std::string(modelnet::PhysicalDispositionName(disp)), "STOPPED_QUIESCENT");
}

BOOST_AUTO_TEST_CASE(JIT_DIRECT_03_revoke_keeps_source_on_dest_fence)
{
    BOOST_TEST_MESSAGE("JIT-DIRECT-03 revoke/host-fallback must not drop source when dest occupancy refuses");
    modelnet::ResetPeerTransferStateForTests();
    const unsigned char occupied[] = {9, 8, 7, 6};
    std::vector<unsigned char> dest;
    modelnet::PhysicalDisposition disp{};
    std::string err;
    const modelnet::Generation16 live = modelnet::NewGeneration();
    BOOST_REQUIRE(modelnet::HostBufferTransfer(occupied, dest, live, disp, err));

    std::vector<unsigned char> source = {1, 2, 3, 4, 5};
    err.clear();
    BOOST_CHECK(!modelnet::RevokePeerSourceThenHostFallback(source, dest, modelnet::NewGeneration(), disp, err));
    BOOST_CHECK_EQUAL(err, "stale generation");
    BOOST_REQUIRE_EQUAL(source.size(), 5);
    BOOST_CHECK(source[0] == 1 && source[4] == 5);
    BOOST_REQUIRE_EQUAL(dest.size(), 4);
    BOOST_CHECK_EQUAL(dest[0], 9);

    BOOST_REQUIRE(modelnet::CancelMidPeerTransfer(live, /*still_inflight=*/true, disp));
    std::vector<unsigned char> source2 = {0xa, 0xb, 0xc};
    err.clear();
    BOOST_CHECK(!modelnet::RevokePeerSourceThenHostFallback(source2, dest, live, disp, err));
    BOOST_CHECK_EQUAL(err, "stale generation");
    BOOST_REQUIRE_EQUAL(source2.size(), 3);
    BOOST_CHECK_EQUAL(source2[0], 0xa);
    BOOST_REQUIRE_EQUAL(dest.size(), 4);
    BOOST_CHECK_EQUAL(dest[0], 9);
}

BOOST_AUTO_TEST_CASE(JIT_DIRECT_04)
{
    BOOST_TEST_MESSAGE("JIT-DIRECT-04 no false zero-copy");
    modelnet::ResetPeerTransferStateForTests();
    std::string code, err;
    BOOST_CHECK(!modelnet::RejectFalseZeroCopy(/*device_pointer_recycled=*/true, /*fence_complete=*/false, code, err));
    BOOST_CHECK_EQUAL(code, "FALSE_ZERO_COPY");
    BOOST_CHECK(modelnet::RejectFalseZeroCopy(/*device_pointer_recycled=*/true, /*fence_complete=*/true, code, err));
    BOOST_CHECK(modelnet::RejectFalseZeroCopy(/*device_pointer_recycled=*/false, /*fence_complete=*/false, code, err));

    std::vector<unsigned char> dest;
    modelnet::PhysicalDisposition d{};
    const unsigned char src[] = {9, 8, 7};
    BOOST_REQUIRE(modelnet::HostBufferTransfer(src, dest, modelnet::NewGeneration(), d, err));
    BOOST_CHECK_EQUAL(dest.size(), 3);
    BOOST_CHECK(d == modelnet::PhysicalDisposition::STOPPED_QUIESCENT);
    BOOST_CHECK(dest[0] == 9 && dest[2] == 7);
}

BOOST_AUTO_TEST_CASE(JIT_DIRECT_05)
{
    BOOST_TEST_MESSAGE("JIT-DIRECT-05 cancel GDS");
    modelnet::ResetPeerTransferStateForTests();
    modelnet::PeerTransferOffer off;
    BOOST_REQUIRE(modelnet::ProbePeerBackends(off));
    if (!off.gds_present) BOOST_TEST_MESSAGE("JIT-DIRECT-05 GDS NOT_RUN");

    modelnet::PhysicalDisposition disp{};
    BOOST_REQUIRE(modelnet::GdsCancelRetain(/*still_inflight=*/true, disp));
    BOOST_CHECK_EQUAL(std::string(modelnet::PhysicalDispositionName(disp)), "STILL_IN_FLIGHT");
    BOOST_CHECK(modelnet::RetainUntilQuiescent(disp));

    BOOST_REQUIRE(modelnet::GdsCancelRetain(/*still_inflight=*/false, disp));
    BOOST_CHECK_EQUAL(std::string(modelnet::PhysicalDispositionName(disp)), "STOPPED_QUIESCENT");
    BOOST_CHECK(!modelnet::RetainUntilQuiescent(disp));
    BOOST_CHECK(modelnet::RetainUntilQuiescent(modelnet::PhysicalDisposition::UNKNOWN));
    BOOST_CHECK(!modelnet::RetainUntilQuiescent(modelnet::PhysicalDisposition::NOT_DISPATCHED));

    const modelnet::Generation16 gen = modelnet::NewGeneration();
    BOOST_REQUIRE(modelnet::CancelMidPeerTransfer(gen, /*still_inflight=*/true, disp));
    BOOST_CHECK(modelnet::RetainUntilQuiescent(disp));
    std::string err;
    const modelnet::Generation16 other = modelnet::NewGeneration();
    BOOST_CHECK(!modelnet::LatePeerCompletionAfterTimeout(gen, other, disp, err));
    BOOST_CHECK_EQUAL(err, "stale generation");

    modelnet::ResetPeerTransferStateForTests();
    const unsigned char gds_src[] = {0x44, 0x45, 0x46, 0x47};
    std::vector<unsigned char> gds_dest;
    BOOST_REQUIRE(modelnet::HostBufferTransfer(gds_src, gds_dest, gen, disp, err));
    BOOST_REQUIRE(modelnet::GdsCancelRetain(/*still_inflight=*/true, disp));
    BOOST_REQUIRE(modelnet::CancelMidPeerTransfer(gen, /*still_inflight=*/true, disp));
    BOOST_CHECK(modelnet::RetainUntilQuiescent(disp));
    gds_dest.clear();
    const unsigned char gds_other[] = {0x50, 0x51, 0x52, 0x53};
    err.clear();
    BOOST_CHECK(!modelnet::HostBufferTransfer(gds_other, gds_dest, other, disp, err));
    BOOST_CHECK_EQUAL(err, "stale generation");
    BOOST_CHECK(gds_dest.empty());
}

BOOST_AUTO_TEST_CASE(JIT_DIRECT_06)
{
    BOOST_TEST_MESSAGE("JIT-DIRECT-06 ROCm/Metal distinction");
    modelnet::ResetPeerTransferStateForTests();
    std::string code, err;

    BOOST_CHECK(!modelnet::RocmMetalDirectDistinction("ROCm", code, err));
    BOOST_CHECK(code == "NOT_RUN" || err.find("NOT_RUN") != std::string::npos);
    BOOST_CHECK(err.find("ROCm") != std::string::npos || err.find("HIP") != std::string::npos);
    BOOST_CHECK(err.find("CUDA GDS is not") != std::string::npos);

    BOOST_CHECK(!modelnet::RocmMetalDirectDistinction("Metal", code, err));
    BOOST_CHECK(code == "NOT_RUN" || err.find("NOT_RUN") != std::string::npos);
    BOOST_CHECK(err.find("Metal") != std::string::npos);

    BOOST_CHECK(!modelnet::RocmMetalDirectDistinction("unknown-backend", code, err));
    BOOST_CHECK_EQUAL(code, "UNKNOWN_COMPATIBILITY");

    const bool cuda_ok = modelnet::RocmMetalDirectDistinction("CUDA", code, err);
    if (!cuda_ok) {
        BOOST_CHECK_EQUAL(code, "NOT_RUN");
        BOOST_CHECK(err.find("NOT_RUN") != std::string::npos);
        BOOST_TEST_MESSAGE("JIT-DIRECT-06 CUDA GDS NOT_RUN");
    }
}

BOOST_AUTO_TEST_CASE(JIT_DIRECT_07)
{
    BOOST_TEST_MESSAGE("JIT-DIRECT-07 fast-path parity");
    modelnet::ResetPeerTransferStateForTests();
    const unsigned char payload[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    std::vector<unsigned char> host;
    modelnet::PhysicalDisposition disp{};
    std::string err;
    BOOST_REQUIRE(modelnet::HostBufferTransfer(payload, host, modelnet::NewGeneration(), disp, err));
    BOOST_CHECK(modelnet::DirectFastPathParity(payload, host));
    const unsigned char other[] = {0x10, 0x20, 0x30, 0x40, 0x51};
    BOOST_CHECK(!modelnet::DirectFastPathParity(payload, other));
    std::vector<unsigned char> short_copy = {0x10, 0x20};
    BOOST_CHECK(!modelnet::DirectFastPathParity(payload, short_copy));
}

BOOST_AUTO_TEST_SUITE_END()
