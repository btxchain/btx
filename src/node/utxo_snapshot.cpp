// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/utxo_snapshot.h>

#include <logging.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <txdb.h>
#include <uint256.h>
#include <util/fs.h>
#include <validation.h>

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <optional>
#include <string>

namespace node {

bool WriteSnapshotBaseBlockhash(Chainstate& snapshot_chainstate)
{
    AssertLockHeld(::cs_main);
    assert(snapshot_chainstate.m_from_snapshot_blockhash);

    const std::optional<fs::path> chaindir = snapshot_chainstate.CoinsDB().StoragePath();
    assert(chaindir); // Sanity check that chainstate isn't in-memory.
    const fs::path write_to = *chaindir / node::SNAPSHOT_BLOCKHASH_FILENAME;

    FILE* file{fsbridge::fopen(write_to, "wb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        LogPrintf("[snapshot] failed to open base blockhash file for writing: %s\n",
                  fs::PathToString(write_to));
        return false;
    }
    afile << *snapshot_chainstate.m_from_snapshot_blockhash;

    if (afile.fclose() != 0) {
        LogPrintf("[snapshot] failed to close base blockhash file %s after writing\n",
                  fs::PathToString(write_to));
        return false;
    }
    return true;
}

std::optional<uint256> ReadSnapshotBaseBlockhash(fs::path chaindir)
{
    if (!fs::exists(chaindir)) {
        LogPrintf("[snapshot] cannot read base blockhash: no chainstate dir "
            "exists at path %s\n", fs::PathToString(chaindir));
        return std::nullopt;
    }
    const fs::path read_from = chaindir / node::SNAPSHOT_BLOCKHASH_FILENAME;
    const std::string read_from_str = fs::PathToString(read_from);

    if (!fs::exists(read_from)) {
        LogPrintf("[snapshot] snapshot chainstate dir is malformed! no base blockhash file "
            "exists at path %s. Try deleting %s and calling loadtxoutset again?\n",
            fs::PathToString(chaindir), read_from_str);
        return std::nullopt;
    }

    uint256 base_blockhash;
    FILE* file{fsbridge::fopen(read_from, "rb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        LogPrintf("[snapshot] failed to open base blockhash file for reading: %s\n",
            read_from_str);
        return std::nullopt;
    }
    afile >> base_blockhash;

    int64_t position = afile.tell();
    afile.seek(0, SEEK_END);
    if (position != afile.tell()) {
        LogPrintf("[snapshot] warning: unexpected trailing data in %s\n", read_from_str);
    }
    return base_blockhash;
}

bool WriteAttestedAssumeutxoData(Chainstate& snapshot_chainstate,
                                 const AssumeutxoData& data)
{
    AssertLockHeld(::cs_main);
    assert(snapshot_chainstate.m_from_snapshot_blockhash);

    const std::optional<fs::path> chaindir = snapshot_chainstate.CoinsDB().StoragePath();
    assert(chaindir);
    const fs::path write_to = *chaindir / node::SNAPSHOT_ATTESTED_ASSUMEUTXO_FILENAME;

    FILE* file{fsbridge::fopen(write_to, "wb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        LogPrintf("[snapshot] failed to open attested assumeutxo file for writing: %s\n",
                  fs::PathToString(write_to));
        return false;
    }
    // Versioned sidecar so future fields can be added without silently
    // mis-parsing older files. v1 matches AssumeutxoData's current layout.
    constexpr uint32_t ATTESTED_ASSUMEUTXO_VERSION{1};
    uint256 hash_serialized;
    std::copy(data.hash_serialized.begin(), data.hash_serialized.end(),
              hash_serialized.begin());
    afile << ATTESTED_ASSUMEUTXO_VERSION;
    afile << data.height;
    afile << hash_serialized;
    afile << data.m_chain_tx_count;
    afile << data.blockhash;
    afile << data.shielded_state_commitment;

    if (afile.fclose() != 0) {
        LogPrintf("[snapshot] failed to close attested assumeutxo file %s after writing\n",
                  fs::PathToString(write_to));
        return false;
    }
    return true;
}

std::optional<AssumeutxoData> ReadAttestedAssumeutxoData(fs::path chaindir)
{
    if (!fs::exists(chaindir)) {
        return std::nullopt;
    }
    const fs::path read_from = chaindir / node::SNAPSHOT_ATTESTED_ASSUMEUTXO_FILENAME;
    if (!fs::exists(read_from)) {
        return std::nullopt;
    }

    FILE* file{fsbridge::fopen(read_from, "rb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        LogPrintf("[snapshot] failed to open attested assumeutxo file for reading: %s\n",
                  fs::PathToString(read_from));
        return std::nullopt;
    }

    uint32_t version{0};
    try {
        uint256 hash_serialized;
        int height{0};
        uint64_t chain_tx_count{0};
        uint256 blockhash;
        uint256 shielded_state_commitment;
        afile >> version;
        if (version != 1) {
            LogPrintf("[snapshot] unsupported attested assumeutxo version %u in %s\n",
                      version, fs::PathToString(read_from));
            return std::nullopt;
        }
        afile >> height;
        afile >> hash_serialized;
        afile >> chain_tx_count;
        afile >> blockhash;
        afile >> shielded_state_commitment;
        return AssumeutxoData{
            .height = height,
            .hash_serialized = AssumeutxoHash{hash_serialized},
            .m_chain_tx_count = chain_tx_count,
            .blockhash = blockhash,
            .shielded_state_commitment = shielded_state_commitment,
        };
    } catch (const std::ios_base::failure& e) {
        LogPrintf("[snapshot] failed to parse attested assumeutxo file %s: %s\n",
                  fs::PathToString(read_from), e.what());
        return std::nullopt;
    }
}

std::optional<fs::path> FindSnapshotChainstateDir(const fs::path& data_dir)
{
    fs::path possible_dir =
        data_dir / fs::u8path(strprintf("chainstate%s", SNAPSHOT_CHAINSTATE_SUFFIX));

    if (fs::exists(possible_dir)) {
        return possible_dir;
    }
    return std::nullopt;
}

} // namespace node
