// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/obs01/obs01.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/prf01/prf01.h>
#include <modelnet/prf02/prf02.h>
#include <modelnet/prf03/prf03.h>
#include <modelnet/prf04/prf04.h>
#include <modelnet/prf05/prf05.h>
#include <modelnet/prf06/prf06.h>
#include <modelnet/prf07/prf07.h>
#include <modelnet/prf08/prf08.h>
#include <modelnet/prf09/prf09.h>
#include <modelnet/qat01/qat01.h>
#include <modelnet/qat02/qat02.h>
#include <modelnet/qat03/qat03.h>
#include <modelnet/qat04/qat04.h>
#include <modelnet/qat05/qat05.h>
#include <modelnet/qat06/qat06.h>
#include <modelnet/rel01/rel01.h>
#include <util/fs.h>

#include <cstdlib>
#include <fstream>
#include <string>
#include <system_error>
#include <unistd.h>

namespace modelnet {
namespace {

template <typename T>
bool ReportsQualification(const T& gate)
{
    if (gate.passed() || gate.gpu_passed() || gate.release_qualified() || gate.hardware_qualified()) {
        return true;
    }
    if constexpr (requires(const T& g) { g.windows_passed(); }) {
        return gate.windows_passed();
    }
    return false;
}

template <typename T>
bool Accept(std::string& err)
{
    T gate;
    if (!gate.Pass(err)) return false;
    if (ReportsQualification(gate)) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    return true;
}

struct LabDir {
    std::string previous;
    bool had{false};
    explicit LabDir(const fs::path& dir)
    {
        const char* cur = std::getenv("BTX035_LAB_DIR");
        had = cur != nullptr;
        if (had) previous = cur;
        ::setenv("BTX035_LAB_DIR", PathToString(dir).c_str(), 1);
    }
    ~LabDir()
    {
        if (had) ::setenv("BTX035_LAB_DIR", previous.c_str(), 1);
        else ::unsetenv("BTX035_LAB_DIR");
    }
};

struct TempTree {
    fs::path root;
    explicit TempTree(const fs::path& path) : root(path) {}
    ~TempTree()
    {
        std::error_code ec;
        fs::remove_all(root, ec);
    }
};

bool PrepareLab(const fs::path& dir, bool truncated, std::string& err)
{
    try {
        fs::create_directories(dir);
        if (!fs::is_directory(dir)) {
            err = "BTX035_RECOVERY_REQUIRED";
            return false;
        }
        if (truncated) {
            std::ofstream out(PathToString(dir / "lab.json"), std::ios::binary);
            out << "{\"automatic_spend_atoms\":\"0\"";
            if (!out.good()) {
                err = "BTX035_RECOVERY_REQUIRED";
                return false;
            }
        }
    } catch (const std::filesystem::filesystem_error&) {
        err = "BTX035_RECOVERY_REQUIRED";
        return false;
    }
    return true;
}

} // namespace

bool Obs01::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }

    if (!Accept<Prf01>(err)) return false;
    if (!Accept<Prf02>(err)) return false;
    {
        const TempTree tree{fs::temp_directory_path() / ("btx-obs01-" + std::to_string(::getpid()))};
        const fs::path admission = tree.root / "prf03";
        if (!PrepareLab(admission, false, err)) return false;
        const LabDir hold(admission);
        if (!Accept<Prf03>(err)) return false;
        const fs::path recovery = tree.root / "prf05";
        if (!PrepareLab(recovery, true, err)) return false;
        const LabDir recover(recovery);
        if (!Accept<Prf05>(err)) return false;
    }
    if (!Accept<Prf04>(err)) return false;
    if (!Accept<Prf06>(err)) return false;
    if (!Accept<Prf07>(err)) return false;
    if (!Accept<Prf08>(err)) return false;
    if (!Accept<Prf09>(err)) return false;
    if (!Accept<Qat01>(err)) return false;
    if (!Accept<Qat02>(err)) return false;
    if (!Accept<Qat03>(err)) return false;
    if (!Accept<Qat04>(err)) return false;
    if (!Accept<Qat05>(err)) return false;
    if (!Accept<Qat06>(err)) return false;
    if (!Accept<Rel01>(err)) return false;

    if (passed() || gpu_passed() || windows_passed() || release_qualified() || hardware_qualified()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }

    m_done = true;
    err.clear();
    return true;
}

bool Obs01::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Obs01::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
