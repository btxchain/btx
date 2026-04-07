// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_matrict_runtime_report.h>

#include <shielded/matrict_plus_backend.h>
#include <shielded/ringct/matrict.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <functional>
#include <numeric>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace btx::test::matrictplus {
namespace {

using shielded::ringct::MatRiCTProof;
namespace backend = shielded::matrictplus;

struct ExpectedVector
{
    uint256 backend_id;
    uint256 proof_hash;
    uint64_t proof_size{0};
};

std::string ReadReferenceVectorFile()
{
    std::ifstream input{BTX_REFERENCE_TEST_VECTORS_PATH};
    if (!input.is_open()) {
        throw std::runtime_error("unable to open shielded reference vectors");
    }

    std::string out;
    input.seekg(0, std::ios::end);
    out.resize(static_cast<size_t>(input.tellg()));
    input.seekg(0, std::ios::beg);
    input.read(out.data(), static_cast<std::streamsize>(out.size()));
    if (!input.good() && !input.eof()) {
        throw std::runtime_error("failed to read shielded reference vectors");
    }
    return out;
}

UniValue ParseJson(std::string_view json)
{
    UniValue out;
    if (!out.read(json)) {
        throw std::runtime_error("failed to parse shielded reference vectors");
    }
    return out;
}

const UniValue& GetMatRiCTPlusReferenceVector()
{
    static const UniValue vectors = ParseJson(ReadReferenceVectorFile());
    const UniValue& kat = vectors.find_value("matrict_plus");
    if (!kat.isObject()) {
        throw std::runtime_error("missing matrict_plus reference vector");
    }
    return kat;
}

uint256 ParseUint256Hex(const UniValue& value)
{
    const auto parsed = uint256::FromHex(value.get_str());
    if (!parsed.has_value()) {
        throw std::runtime_error("invalid uint256 hex");
    }
    return *parsed;
}

ExpectedVector LoadExpectedVector()
{
    const UniValue& kat = GetMatRiCTPlusReferenceVector();
    const UniValue& proof = kat.find_value("proof");
    if (!proof.isObject()) {
        throw std::runtime_error("missing matrict_plus proof reference vector");
    }

    ExpectedVector expected;
    expected.backend_id = ParseUint256Hex(kat.find_value("backend_id_hex"));
    expected.proof_hash = ParseUint256Hex(proof.find_value("serialized_proof_hash_hex"));
    expected.proof_size = proof.find_value("serialized_size").getInt<uint64_t>();
    return expected;
}

uint64_t MeasureNanoseconds(const std::function<bool()>& fn)
{
    const auto start = std::chrono::steady_clock::now();
    const bool ok = fn();
    const auto end = std::chrono::steady_clock::now();
    if (!ok) {
        throw std::runtime_error("MatRiCT+ runtime capture step failed");
    }
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
}

uint64_t Average(const std::vector<uint64_t>& values)
{
    if (values.empty()) return 0;
    const uint64_t total = std::accumulate(values.begin(), values.end(), uint64_t{0});
    return total / values.size();
}

uint64_t Median(std::vector<uint64_t> values)
{
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const size_t mid = values.size() / 2;
    if ((values.size() % 2) == 1) {
        return values[mid];
    }
    return (values[mid - 1] + values[mid]) / 2;
}

UniValue BuildSummary(const std::vector<uint64_t>& values)
{
    UniValue summary(UniValue::VOBJ);
    summary.pushKV("count", static_cast<uint64_t>(values.size()));
    summary.pushKV("min_ns", values.empty() ? 0 : *std::min_element(values.begin(), values.end()));
    summary.pushKV("median_ns", Median(values));
    summary.pushKV("average_ns", Average(values));
    summary.pushKV("max_ns", values.empty() ? 0 : *std::max_element(values.begin(), values.end()));
    return summary;
}

UniValue BuildFixtureJson(const backend::PortableFixture& fixture)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("input_note_count", static_cast<uint64_t>(fixture.input_notes.size()));
    out.pushKV("output_note_count", static_cast<uint64_t>(fixture.output_notes.size()));
    out.pushKV("ring_size", fixture.ring_members.empty() ? 0 : static_cast<uint64_t>(fixture.ring_members.front().size()));
    out.pushKV("fee_sat", static_cast<int64_t>(fixture.fee));
    out.pushKV("tx_binding_hash_hex", fixture.tx_binding_hash.GetHex());
    return out;
}

} // namespace

UniValue BuildRuntimeReport(const RuntimeReportConfig& config)
{
    if (config.measured_iterations == 0) {
        throw std::runtime_error("measured_iterations must be non-zero");
    }

    const ExpectedVector expected = LoadExpectedVector();
    const backend::PortableFixture fixture = backend::BuildDeterministicFixture();
    if (!fixture.IsValid()) {
        throw std::runtime_error("deterministic MatRiCT+ fixture is invalid");
    }
    if (backend::GetBackendId() != expected.backend_id) {
        throw std::runtime_error("MatRiCT+ backend id drifted from reference vector");
    }

    for (size_t i = 0; i < config.warmup_iterations; ++i) {
        MatRiCTProof warmup;
        if (!backend::CreateProof(warmup, fixture) || !backend::VerifyProof(warmup, fixture)) {
            throw std::runtime_error("MatRiCT+ warmup failed");
        }
    }

    std::vector<uint64_t> create_times_ns;
    std::vector<uint64_t> verify_times_ns;
    create_times_ns.reserve(config.measured_iterations);
    verify_times_ns.reserve(config.measured_iterations);

    UniValue measurements(UniValue::VARR);
    for (size_t i = 0; i < config.measured_iterations; ++i) {
        MatRiCTProof proof;
        const uint64_t create_ns = MeasureNanoseconds([&] {
            return backend::CreateProof(proof, fixture);
        });
        const uint64_t proof_size = proof.GetSerializedSize();
        const uint256 proof_hash = backend::SerializeProofHash(proof);
        if (proof_size != expected.proof_size) {
            throw std::runtime_error("MatRiCT+ proof size drifted from reference vector");
        }
        if (proof_hash != expected.proof_hash) {
            throw std::runtime_error("MatRiCT+ proof hash drifted from reference vector");
        }
        const uint64_t verify_ns = MeasureNanoseconds([&] {
            return backend::VerifyProof(proof, fixture);
        });

        create_times_ns.push_back(create_ns);
        verify_times_ns.push_back(verify_ns);

        UniValue measurement(UniValue::VOBJ);
        measurement.pushKV("sample_index", static_cast<uint64_t>(i));
        measurement.pushKV("create_ns", create_ns);
        measurement.pushKV("verify_ns", verify_ns);
        measurement.pushKV("serialized_size", proof_size);
        measurement.pushKV("serialized_proof_hash_hex", proof_hash.GetHex());
        measurements.push_back(std::move(measurement));
    }

    UniValue runtime_config(UniValue::VOBJ);
    runtime_config.pushKV("warmup_iterations", static_cast<uint64_t>(config.warmup_iterations));
    runtime_config.pushKV("measured_iterations", static_cast<uint64_t>(config.measured_iterations));
    runtime_config.pushKV("duration_unit", "nanoseconds");
    runtime_config.pushKV("clock", "steady_clock");

    UniValue proof(UniValue::VOBJ);
    proof.pushKV("serialized_size", expected.proof_size);
    proof.pushKV("serialized_proof_hash_hex", expected.proof_hash.GetHex());
    proof.pushKV("reference_vector_match", true);

    UniValue out(UniValue::VOBJ);
    out.pushKV("format_version", 1);
    out.pushKV("report_kind", "matrict_plus_runtime");
    out.pushKV("backend_id_hex", expected.backend_id.GetHex());
    out.pushKV("fixture", BuildFixtureJson(fixture));
    out.pushKV("proof", std::move(proof));
    out.pushKV("runtime_config", std::move(runtime_config));
    out.pushKV("create_summary", BuildSummary(create_times_ns));
    out.pushKV("verify_summary", BuildSummary(verify_times_ns));
    out.pushKV("measurements", std::move(measurements));
    return out;
}

} // namespace btx::test::matrictplus
