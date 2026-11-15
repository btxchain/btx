// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_lifecycle/journal.h>
#include <modelnet/swarm_form/codec.h>
#include <modelnet/swarm_form/plane.h>
#include <modelnet/swarm_form/types.h>
#include <modelnet/swarm_lifecycle.h>
#include <modelnet/swarm_live.h>
#include <modelnet/swarm_node.h>
#include <modelnet/swarm_observer.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/check.h>
#include <util/fs.h>

#include <cstdint>
#include <exception>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <system_error>

// The swarm observer thread runs inside btxd on a default start and polls
// these files under the model directory every two seconds. Each target
// writes fuzzed bytes into a private model directory and calls the same pass
// the observer calls. The observer loop catches std::exception and keeps the
// node running, so these targets do the same; anything else is a crash.

namespace {

constexpr size_t MAX_FILE_BYTES{1 << 16};

fs::path FuzzModeldir()
{
    static const fs::path dir = fs::path{fs::temp_directory_path()} /
                                fs::u8path(strprintf("btx-fuzz-swarm-%08x", std::random_device{}()));
    return dir;
}

fs::path FreshModeldir()
{
    const fs::path dir = FuzzModeldir();
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir / "swarm");
    return dir;
}

void PutFile(const fs::path& path, const std::string& bytes)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

std::string GetFile(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

/** An empty string leaves the file absent; otherwise the first byte is a marker and the rest is the file. */
void MaybePut(FuzzedDataProvider& fdp, const fs::path& path)
{
    const std::string raw = fdp.ConsumeRandomLengthString(MAX_FILE_BYTES);
    if (raw.empty()) return;
    PutFile(path, raw.substr(1));
}

void PutCatalogInputs(FuzzedDataProvider& fdp, const fs::path& dir)
{
    MaybePut(fdp, dir / "catalog.json");
    MaybePut(fdp, dir / "swarm" / "lineage-mappings.json");
}

/** Run one observer pass with the observer loop's exception boundary. */
template <typename Pass>
bool ObserverPass(Pass pass)
{
    std::string err;
    try {
        const bool ok = pass(err);
        if (ok) Assert(err.empty());
        return ok;
    } catch (const std::exception&) {
        return false;
    }
}

void AssertJsonFile(const fs::path& path)
{
    // An empty observers.json reads as no subscriptions and is left in place.
    if (!fs::exists(path) || fs::file_size(path) == 0) return;
    UniValue parsed;
    Assert(parsed.read(GetFile(path)));
}

} // namespace

// catalog.json, swarm/lineage-mappings.json and swarm/observers.json.
FUZZ_TARGET(swarm_observer_catalog)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const fs::path dir = FreshModeldir();
    PutCatalogInputs(fdp, dir);
    MaybePut(fdp, dir / "swarm" / "observers.json");

    // The reader promises false on invalid input, so it is called without a catch.
    modelnet::SwarmCatalog entries;
    std::string err;
    if (modelnet::SwarmReadCatalog(dir, entries, err)) {
        Assert(err.empty());
        for (const auto& [artifact, entry] : entries) {
            Assert(artifact == entry.artifact_id);
            Assert(entry.lineage_id.size() == 96);
            Assert(entry.visibility == "private" || entry.visibility == "public");
        }
    } else {
        Assert(entries.empty());
        Assert(!err.empty());
    }

    const bool observed = ObserverPass([&](std::string& e) { return modelnet::SwarmObserveCatalog(dir, e); });
    if (!observed) return;
    AssertJsonFile(dir / "swarm" / "observers.json");
    // A snapshot this pass wrote is one the next pass reads back unchanged.
    const std::string first = GetFile(dir / "swarm" / "observers.json");
    Assert(ObserverPass([&](std::string& e) { return modelnet::SwarmObserveCatalog(dir, e); }));
    Assert(GetFile(dir / "swarm" / "observers.json") == first);
}

// swarm/peers.json, swarm/device.json and a previous swarm/mesh-state.json.
FUZZ_TARGET(swarm_mesh_refresh)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const fs::path dir = FreshModeldir();
    MaybePut(fdp, dir / "swarm" / "peers.json");
    MaybePut(fdp, dir / "swarm" / "device.json");
    MaybePut(fdp, dir / "swarm" / "mesh-state.json");

    modelnet::SwarmGovernSnapshot snap;
    if (ObserverPass([&](std::string& e) { return modelnet::SwarmLoadGoverned(dir, snap, e); })) {
        Assert(snap.roles.automatic_spend_atoms == "0");
        Assert(snap.budget.active_workers >= 0 && snap.budget.cpu_threads >= 0);
        Assert(snap.budget.vram_bytes >= 0 && snap.budget.max_steps >= 0);
        Assert(snap.hardware_threads >= 1 && snap.hardware_threads <= 64);
    }
    if (!ObserverPass([&](std::string& e) { return modelnet::SwarmRefreshLocalMesh(dir, e); })) return;
    const fs::path mesh = dir / "swarm" / "mesh-state.json";
    Assert(fs::exists(mesh));
    AssertJsonFile(mesh);
    const std::string first = GetFile(mesh);
    Assert(ObserverPass([&](std::string& e) { return modelnet::SwarmRefreshLocalMesh(dir, e); }));
    Assert(GetFile(mesh) == first);
}

// The contribution view: catalog, mappings, device and a previous contribution.json.
FUZZ_TARGET(swarm_integrate_catalog)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const fs::path dir = FreshModeldir();
    PutCatalogInputs(fdp, dir);
    MaybePut(fdp, dir / "swarm" / "device.json");
    MaybePut(fdp, dir / "swarm" / "contribution.json");

    if (!ObserverPass([&](std::string& e) { return modelnet::SwarmIntegrateCatalog(dir, e); })) return;
    const fs::path contribution = dir / "swarm" / "contribution.json";
    Assert(fs::exists(contribution));
    UniValue parsed;
    Assert(parsed.read(GetFile(contribution)));
    Assert(parsed.isObject() && parsed["automatic_spend_atoms"].get_str() == "0");
    const std::string first = GetFile(contribution);
    Assert(ObserverPass([&](std::string& e) { return modelnet::SwarmIntegrateCatalog(dir, e); }));
    Assert(GetFile(contribution) == first);
    // The live view reads what the contribution view wrote.
    Assert(ObserverPass([&](std::string& e) { return modelnet::SwarmPublishLive(dir, e); }));
}

// swarm/contribution.json plus previous networks.json and timescales.json.
FUZZ_TARGET(swarm_publish_live)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const fs::path dir = FreshModeldir();
    MaybePut(fdp, dir / "swarm" / "contribution.json");
    MaybePut(fdp, dir / "swarm" / "networks.json");
    MaybePut(fdp, dir / "swarm" / "timescales.json");

    if (!ObserverPass([&](std::string& e) { return modelnet::SwarmPublishLive(dir, e); })) return;
    if (!fs::exists(dir / "swarm" / "contribution.json")) return;
    AssertJsonFile(dir / "swarm" / "networks.json");
    AssertJsonFile(dir / "swarm" / "timescales.json");
    const std::string networks = GetFile(dir / "swarm" / "networks.json");
    const std::string times = GetFile(dir / "swarm" / "timescales.json");
    Assert(ObserverPass([&](std::string& e) { return modelnet::SwarmPublishLive(dir, e); }));
    Assert(GetFile(dir / "swarm" / "networks.json") == networks);
    Assert(GetFile(dir / "swarm" / "timescales.json") == times);
}

// swarm/formation-membership.json and swarm/formation-election.json.
FUZZ_TARGET(swarm_form_plane)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const fs::path dir = FreshModeldir();
    MaybePut(fdp, dir / "swarm" / modelnet::kMembershipFile);
    MaybePut(fdp, dir / "swarm" / modelnet::kElectionFile);

    // The decoders promise false on invalid input.
    const fs::path member_path = dir / "swarm" / modelnet::kMembershipFile;
    if (fs::exists(member_path)) {
        modelnet::SwarmFormMember member;
        std::string err;
        if (modelnet::DecodeMember(GetFile(member_path), member, err)) {
            const std::string encoded = modelnet::EncodeMember(member);
            modelnet::SwarmFormMember again;
            Assert(modelnet::DecodeMember(encoded, again, err));
            Assert(modelnet::EncodeMember(again) == encoded);
        }
    }
    const fs::path election_path = dir / "swarm" / modelnet::kElectionFile;
    if (fs::exists(election_path)) {
        std::string leader;
        uint64_t epoch{0};
        std::string err;
        if (modelnet::DecodeElection(GetFile(election_path), leader, epoch, err)) {
            const std::string encoded = modelnet::EncodeElection(leader, epoch);
            std::string leader2;
            uint64_t epoch2{0};
            Assert(modelnet::DecodeElection(encoded, leader2, epoch2, err));
            Assert(leader2 == leader && epoch2 == epoch);
        }
    }

    if (!ObserverPass([&](std::string& e) { return modelnet::SwarmFormPlane(dir, e); })) return;
    // A plane formed once forms again from the file it left behind.
    Assert(fs::exists(member_path));
    Assert(ObserverPass([&](std::string& e) { return modelnet::SwarmFormPlane(dir, e); }));
}

// One observer tick over every input file, in the order the btxd loop runs it.
FUZZ_TARGET(swarm_observer_tick)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const fs::path dir = FreshModeldir();
    PutCatalogInputs(fdp, dir);
    MaybePut(fdp, dir / "swarm" / "device.json");
    MaybePut(fdp, dir / "swarm" / "peers.json");
    MaybePut(fdp, dir / "swarm" / "observers.json");
    MaybePut(fdp, dir / "swarm" / "contribution.json");
    MaybePut(fdp, dir / "swarm" / modelnet::kMembershipFile);
    MaybePut(fdp, dir / "swarm" / modelnet::kElectionFile);

    LIMITED_WHILE(true, 2)
    {
        if (!ObserverPass([&](std::string& e) { return modelnet::SwarmObserveCatalog(dir, e); })) break;
        ObserverPass([&](std::string& e) { return modelnet::SwarmRefreshLocalMesh(dir, e); });
        if (ObserverPass([&](std::string& e) { return modelnet::SwarmIntegrateCatalog(dir, e); })) {
            ObserverPass([&](std::string& e) { return modelnet::SwarmFormPlane(dir, e); });
            ObserverPass([&](std::string& e) { return modelnet::SwarmPublishLive(dir, e); });
        }
    }
}

// The NIF lifecycle journal file reader and writer.
FUZZ_TARGET(swarm_nif_journal)
{
    const fs::path dir = FreshModeldir();
    const fs::path path = dir / "swarm" / "attempt.nif";
    PutFile(path, std::string(buffer.begin(), buffer.end()));

    modelnet::NifRequestRecord record;
    std::string err;
    if (!modelnet::NifLifecycleJournalRead(path, record, err)) {
        Assert(!err.empty());
        return;
    }
    Assert(err.empty());
    // What the reader accepts, the writer writes back and the reader reads again.
    const fs::path copy = dir / "swarm" / "copy.nif";
    Assert(modelnet::NifLifecycleJournalWrite(copy, record, err));
    modelnet::NifRequestRecord again;
    Assert(modelnet::NifLifecycleJournalRead(copy, again, err));
    Assert(again.principal == record.principal && again.receiver == record.receiver);
    Assert(again.realm == record.realm && again.generation == record.generation);
    Assert(again.runtime_image == record.runtime_image && again.commitment == record.commitment);
    Assert(again.attempt == record.attempt && again.epoch == record.epoch);
    Assert(again.ceiling_bytes == record.ceiling_bytes && again.lease_until_ms == record.lease_until_ms);
    Assert(again.cancelled == record.cancelled && again.output_ceiling == record.output_ceiling);
    Assert(again.accepted_output == record.accepted_output && again.economic_contract == record.economic_contract);
}
