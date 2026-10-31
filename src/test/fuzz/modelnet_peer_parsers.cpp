// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/helper.h>
#include <modelnet/piece_picker.h>
#include <modelnet/provider_exchange.h>
#include <modelnet/types.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <univalue.h>
#include <util/check.h>

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

// The parsers below read bytes from any peer after the PQ1 handshake
// (inbound TOFU), so they get fuzz targets of their own.

// Native HTTP request framing inside a PQ1 session (HandlePq1Fd).
FUZZ_TARGET(modelnet_native_http_request)
{
    const std::string raw(buffer.begin(), buffer.end());
    modelnet::NativeRequest req;
    std::string err;
    if (!modelnet::ParseHttpRequest(raw, req, err)) return;
    Assert(!req.method.empty() && !req.path.empty());
    Assert(req.body.size() <= raw.size());
}

// Provider exchange records from POST /btx-model/2/ext/pex.
FUZZ_TARGET(modelnet_pex_ingest)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const std::string from = fdp.ConsumeRandomLengthString(64);
    const int64_t now = fdp.ConsumeIntegralInRange<int64_t>(0, int64_t{1} << 50);
    UniValue body;
    if (!body.read(fdp.ConsumeRemainingBytesAsString())) return;

    const modelnet::PexLimits limits;
    modelnet::ProviderExchange pex{limits};
    std::vector<modelnet::ProviderHint> accepted;
    std::string err;
    if (pex.Ingest(from, body, now, accepted, err)) {
        Assert(accepted.size() <= limits.max_records);
        for (const auto& hint : accepted) {
            Assert(hint.expiry_ms > now && hint.expiry_ms <= now + limits.ttl_ms);
        }
    }
    Assert(pex.Recent(now).size() <= limits.cache_cap);
    const UniValue advertised = pex.Advertise(now, limits.max_records);
    (void)advertised.write();
    pex.Expire(now + limits.ttl_ms + 1);
    // Recent() leaves out expired entries itself, so ask for every entry.
    Assert(pex.Recent(std::numeric_limits<int64_t>::min()).empty());
}

// Availability JSON a retrieving client reads from each source peer.
FUZZ_TARGET(modelnet_availability_sources)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const int64_t observed = fdp.ConsumeIntegralInRange<int64_t>(0, int64_t{1} << 50);
    modelnet::Digest48 artifact;
    for (auto& b : artifact.data) b = fdp.ConsumeIntegral<unsigned char>();
    UniValue availability;
    if (!availability.read(fdp.ConsumeRemainingBytesAsString())) return;

    const std::string endpoint{"192.0.2.1:29447"};
    const modelnet::PeerId peer{endpoint, "fuzz-service", "192.0.2.0/24"};
    std::vector<modelnet::SourceAvailability> out;
    std::string err;
    try {
        if (!modelnet::ParseAvailabilitySources(availability, endpoint, peer, artifact, out, err, observed)) return;
    } catch (const std::runtime_error&) {
        // getInt() throws for a non-integer file_index or piece_count. The
        // retrieve worker calls this inside a try (helper.cpp LaunchRetrieveWorker).
        return;
    }
    for (const auto& source : out) {
        Assert(source.peer.endpoint == endpoint);
    }
}
