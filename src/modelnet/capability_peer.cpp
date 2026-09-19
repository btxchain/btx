// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Worker J (peer/direct transfer): ProbePeerBackends, HostBufferTransfer,
// RetainUntilQuiescent, and remaining JIT-PEER / JIT-DIRECT symbols.
// Coordinator must CMake-list this TU and strip the three duplicates from
// capability_exec.cpp after link. automatic_spend_atoms stays 0.

#include <modelnet/capability.h>

#include <crypto/sha384.h>
#include <util/fs.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace modelnet {
namespace {

std::mutex g_peer_mu;

struct GenTransfer {
    bool inflight{false};
    PhysicalDisposition disp{PhysicalDisposition::NOT_DISPATCHED};
    uintptr_t dest_addr{0};
};

std::map<Generation16, GenTransfer> g_gens;

bool Fail(std::string& err_code, std::string& err, const char* code, const std::string& msg)
{
    err_code = code;
    err = msg.empty() ? code : msg;
    return false;
}

std::string LowerAscii(std::string s)
{
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

bool EnvLibPresent(const char* key)
{
    const char* v = std::getenv(key);
    if (!v || !*v) return false;
    return fs::exists(fs::PathFromString(std::string(v)));
}

bool IsPublicWanPeer(const std::string& peer_id)
{
    const std::string p = LowerAscii(peer_id);
    if (p.empty()) return true;
    if (p == "public" || p.find("public-") == 0) return true;
    if (p.find("wan") != std::string::npos) return true;
    if (p.find("://") != std::string::npos) return true;
    return false;
}

Digest48 Sha384Span(Span<const unsigned char> bytes)
{
    Digest48 out{};
    CSHA384 hasher;
    if (!bytes.empty()) hasher.Write(bytes.data(), bytes.size());
    hasher.Finalize(out.data.data());
    return out;
}

bool SameShape(const std::vector<int64_t>& a, const std::vector<int64_t>& b)
{
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

} // namespace

void ResetPeerTransferStateForTests()
{
    std::lock_guard<std::mutex> lock(g_peer_mu);
    g_gens.clear();
}

bool ProbePeerBackends(PeerTransferOffer& out)
{
    out = {};
    out.json = UniValue(UniValue::VOBJ);
    out.json.pushKV("stub", false);
    out.json.pushKV("portable_host_buffer", true);
    out.json.pushKV("automatic_spend_atoms", 0);

#ifdef __APPLE__
    // Linux NIXL/UCX and CUDA GDS are not macOS/Metal paths (spec §16.4 / §17.1).
    out.nixl_present = false;
    out.gds_present = false;
    out.assurance = TransportAssurance::HOST_BUFFER;
    out.json.pushKV("nixl", false);
    out.json.pushKV("gds", false);
    out.json.pushKV("nixl_status", "NOT_RUN");
    out.json.pushKV("gds_status", "NOT_RUN");
    out.json.pushKV("nixl_detail", "NOT_RUN: Linux NIXL is not a macOS path");
    out.json.pushKV("gds_detail", "NOT_RUN: CUDA GDS is not Metal/macOS");
    out.json.pushKV("assurance", TransportAssuranceName(out.assurance));
    return true;
#else
    out.nixl_present = EnvLibPresent("BTX_NIXL_LIB");
    out.gds_present = EnvLibPresent("BTX_CUFILE_LIB");
    out.assurance = out.nixl_present ? TransportAssurance::TRUSTED_FABRIC : TransportAssurance::HOST_BUFFER;
    out.json.pushKV("nixl", out.nixl_present);
    out.json.pushKV("gds", out.gds_present);
    // Never advertise NIXL as PASS without a real lib file.
    out.json.pushKV("nixl_status", out.nixl_present ? "PRESENT" : "NOT_RUN");
    out.json.pushKV("gds_status", out.gds_present ? "PRESENT" : "NOT_RUN");
    if (const char* nixl = std::getenv("BTX_NIXL_LIB")) {
        out.json.pushKV("nixl_lib", nixl);
        if (!out.nixl_present) out.json.pushKV("nixl_detail", "NOT_RUN: BTX_NIXL_LIB path does not exist");
    } else {
        out.json.pushKV("nixl_detail", "NOT_RUN: BTX_NIXL_LIB unset");
    }
    if (const char* gds = std::getenv("BTX_CUFILE_LIB")) {
        out.json.pushKV("gds_lib", gds);
        if (!out.gds_present) out.json.pushKV("gds_detail", "NOT_RUN: BTX_CUFILE_LIB path does not exist");
    } else {
        out.json.pushKV("gds_detail", "NOT_RUN: BTX_CUFILE_LIB unset");
    }
    out.json.pushKV("assurance", TransportAssuranceName(out.assurance));
    return true;
#endif
}

bool HostBufferTransfer(Span<const unsigned char> src, std::vector<unsigned char>& dest, Generation16 gen,
                        PhysicalDisposition& disp, std::string& err)
{
    std::lock_guard<std::mutex> lock(g_peer_mu);
    // Same-generation host copy must not dest.swap() an inflight DMA dest: that
    // frees the registered buffer while a late NIXL/GDS callback can still write.
    const auto self = g_gens.find(gen);
    if (self != g_gens.end() && self->second.inflight && self->second.dest_addr != 0) {
        disp = PhysicalDisposition::STILL_IN_FLIGHT;
        err = "stale generation";
        return false;
    }
    if (dest.capacity() > 0) {
        const uintptr_t addr = reinterpret_cast<uintptr_t>(dest.data());
        for (auto& kv : g_gens) {
            if (kv.first == gen || kv.second.dest_addr != addr) continue;
            if (kv.second.inflight || !dest.empty()) {
                disp = kv.second.inflight ? PhysicalDisposition::STILL_IN_FLIGHT :
                                           PhysicalDisposition::STOPPED_QUIESCENT;
                err = "stale generation";
                return false;
            }
            kv.second.dest_addr = 0;
        }
    }
    std::vector<unsigned char> staged(src.begin(), src.end());
    if (!staged.empty()) {
        const uintptr_t staged_addr = reinterpret_cast<uintptr_t>(staged.data());
        for (auto& kv : g_gens) {
            if (kv.first == gen || kv.second.dest_addr != staged_addr) continue;
            if (kv.second.inflight) {
                disp = PhysicalDisposition::STILL_IN_FLIGHT;
                err = "stale generation";
                return false;
            }
            // Completed dest_addr after dest teardown can collide with a new
            // staged heap block. Unbind so occupancy does not alias generations.
            kv.second.dest_addr = 0;
        }
    }
    dest.swap(staged);
    GenTransfer& st = g_gens[gen];
    st.inflight = false;
    st.disp = PhysicalDisposition::STOPPED_QUIESCENT;
    st.dest_addr = dest.empty() ? 0 : reinterpret_cast<uintptr_t>(dest.data());
    disp = PhysicalDisposition::STOPPED_QUIESCENT;
    err.clear();
    return true;
}

bool RetainUntilQuiescent(PhysicalDisposition d)
{
    return d == PhysicalDisposition::STILL_IN_FLIGHT || d == PhysicalDisposition::UNKNOWN;
}

bool PeerMembershipAllows(const std::string& fabric_policy, const std::string& peer_id, std::string& err_code,
                          std::string& err)
{
    if (fabric_policy != "PRIVATE_FABRIC_APPROVED") {
        return Fail(err_code, err, "FABRIC_POLICY_REQUIRED",
                    "peer-device access requires PRIVATE_FABRIC_APPROVED organization authorization");
    }
    if (peer_id.empty() || IsPublicWanPeer(peer_id)) {
        return Fail(err_code, err, "FABRIC_POLICY_REQUIRED",
                    "public WAN / empty peer-id is not a private fabric membership");
    }
    err_code.clear();
    err.clear();
    return true;
}

bool PeerExactGeometry(const TensorRangeMap& local, const TensorRangeMap& peer, std::string& err_code, std::string& err)
{
    if (local.tensors.size() != peer.tensors.size()) {
        return Fail(err_code, err, "REPRESENTATION_MISMATCH",
                    "tensor count differs; name-only matching is not geometry");
    }
    for (size_t i = 0; i < local.tensors.size(); ++i) {
        const TensorRange& a = local.tensors[i];
        const TensorRange& b = peer.tensors[i];
        if (a.offset != b.offset || a.length != b.length || a.dtype != b.dtype || a.file_index != b.file_index ||
            !SameShape(a.shape, b.shape)) {
            return Fail(err_code, err, "REPRESENTATION_MISMATCH",
                        "tensor offset/length/dtype/layout differ; refusing name-only match");
        }
    }
    err_code.clear();
    err.clear();
    return true;
}

bool VerifyPeerDestination(Span<const unsigned char> received, const Digest48& expected, bool compute_started,
                           std::string& err_code, std::string& err)
{
    const Digest48 got = Sha384Span(received);
    if (got != expected) {
        return Fail(err_code, err, "DESTINATION_UNVERIFIED",
                    "SHA-384 of received bytes does not match expected destination digest; compute must not start");
    }
    if (compute_started) {
        return Fail(err_code, err, "DESTINATION_UNVERIFIED",
                    "compute started before destination digest match; destination remains quarantined");
    }
    err_code.clear();
    err.clear();
    return true;
}

bool RegisterPeerMemoryNarrow(uint64_t buffer_bytes, uint64_t registered_bytes, std::string& err_code, std::string& err)
{
    if (registered_bytes != buffer_bytes) {
        return Fail(err_code, err, "REGISTRATION_TOO_WIDE",
                    "peer registration must equal the exact weight buffer, not the GPU heap or KV/prompt ranges");
    }
    err_code.clear();
    err.clear();
    return true;
}

bool LatePeerCompletionAfterTimeout(const Generation16& live_gen, const Generation16& completion_gen,
                                    PhysicalDisposition& disp, std::string& err)
{
    std::lock_guard<std::mutex> lock(g_peer_mu);
    if (live_gen != completion_gen) {
        const auto it = g_gens.find(live_gen);
        if (it != g_gens.end() && it->second.inflight) {
            disp = PhysicalDisposition::STILL_IN_FLIGHT;
        } else if (it != g_gens.end()) {
            disp = it->second.disp == PhysicalDisposition::NOT_DISPATCHED ? PhysicalDisposition::STOPPED_QUIESCENT :
                                                                            it->second.disp;
        } else {
            disp = PhysicalDisposition::STILL_IN_FLIGHT;
        }
        err = "stale generation";
        return false;
    }
    GenTransfer& st = g_gens[live_gen];
    st.inflight = false;
    st.disp = PhysicalDisposition::STOPPED_QUIESCENT;
    disp = PhysicalDisposition::STOPPED_QUIESCENT;
    err.clear();
    return true;
}

bool GdsCancelRetain(bool still_inflight, PhysicalDisposition& disp)
{
    if (still_inflight) {
        disp = PhysicalDisposition::STILL_IN_FLIGHT;
        return true;
    }
    disp = PhysicalDisposition::STOPPED_QUIESCENT;
    return true;
}

bool DirectVerifiedSourcePath(bool source_verified, bool gds_aligned, TransportAssurance& path, std::string& err_code,
                              std::string& err)
{
    if (!source_verified) {
        path = TransportAssurance::HOST_BUFFER;
        return Fail(err_code, err, "UNVERIFIED_ORIGIN", "unverified origin cannot GDS or bypass destination quarantine");
    }
    if (!gds_aligned) {
        path = TransportAssurance::HOST_BUFFER;
        err_code.clear();
        err.clear();
        return true;
    }
    PeerTransferOffer off;
    ProbePeerBackends(off);
    if (off.gds_present) {
        path = TransportAssurance::VERIFIED_EXTERNAL;
    } else {
        path = TransportAssurance::HOST_BUFFER;
    }
    err_code.clear();
    err.clear();
    return true;
}

bool RejectUnverifiedOriginDirect(bool origin_verified, std::string& err_code, std::string& err)
{
    if (!origin_verified) {
        return Fail(err_code, err, "UNVERIFIED_ORIGIN",
                    "public unverified range cannot be offered as a direct device load");
    }
    err_code.clear();
    err.clear();
    return true;
}

bool AlignmentFallbackHost(bool aligned, TransportAssurance& path)
{
    if (!aligned) path = TransportAssurance::HOST_BUFFER;
    return true;
}

bool RejectFalseZeroCopy(bool device_pointer_recycled, bool fence_complete, std::string& err_code, std::string& err)
{
    if (device_pointer_recycled && !fence_complete) {
        return Fail(err_code, err, "FALSE_ZERO_COPY",
                    "device pointer recycled before transfer fence; not zero-copy and not safe reuse");
    }
    err_code.clear();
    err.clear();
    return true;
}

bool RocmMetalDirectDistinction(const std::string& backend, std::string& err_code, std::string& err)
{
    const std::string b = LowerAscii(backend);
    if (b == "cuda" || b == "gds" || b == "cufile") {
        PeerTransferOffer off;
        ProbePeerBackends(off);
        if (!off.gds_present) {
            return Fail(err_code, err, "NOT_RUN", "CUDA GDS library absent; NOT_RUN (not a ROCm/Metal relabel)");
        }
        err_code.clear();
        err.clear();
        return true;
    }
    if (b == "rocm" || b == "hip") {
        return Fail(err_code, err, "NOT_RUN", "CUDA GDS is not ROCm/HIP; eligible alternative is HOST_BUFFER; NOT_RUN");
    }
    if (b == "metal" || b == "mlx") {
        return Fail(err_code, err, "NOT_RUN", "CUDA GDS is not Metal; eligible alternative is HOST_BUFFER; NOT_RUN");
    }
    return Fail(err_code, err, "UNKNOWN_COMPATIBILITY", "unknown direct-storage backend");
}

bool DirectFastPathParity(Span<const unsigned char> direct, Span<const unsigned char> host_copy)
{
    return direct.size() == host_copy.size() && std::equal(direct.begin(), direct.end(), host_copy.begin());
}

bool PeerDestinationBeforeCompute(Span<const unsigned char> received, const Digest48& expected, bool& compute_started,
                                  std::string& err_code, std::string& err)
{
    compute_started = false;
    if (!VerifyPeerDestination(received, expected, /*compute_started=*/false, err_code, err)) {
        return false;
    }
    compute_started = true;
    return true;
}

bool CancelMidPeerTransfer(const Generation16& gen, bool still_inflight, PhysicalDisposition& disp)
{
    const bool ok = GdsCancelRetain(still_inflight, disp);
    std::lock_guard<std::mutex> lock(g_peer_mu);
    GenTransfer& st = g_gens[gen];
    st.inflight = still_inflight;
    st.disp = disp;
    return ok;
}

bool RevokePeerSourceThenHostFallback(std::vector<unsigned char>& source_buffer, std::vector<unsigned char>& dest,
                                      Generation16 gen, PhysicalDisposition& disp, std::string& err)
{
    // Snapshot, then host-copy. Revoke the peer source only after dest admits
    // this generation. Occupancy/inflight refusal must not drop the only copy.
    std::vector<unsigned char> snapshot(source_buffer.begin(), source_buffer.end());
    if (!HostBufferTransfer(snapshot, dest, gen, disp, err)) return false;
    if (&source_buffer != &dest) {
        source_buffer.clear();
        source_buffer.shrink_to_fit();
    }
    return true;
}

} // namespace modelnet
