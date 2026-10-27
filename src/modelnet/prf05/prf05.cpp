// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/prf05/prf05.h>

#include <modelnet/lab_disk.h>
#include <modelnet/nifdt_contract/contract.h>

#include <string>

namespace modelnet {

bool Prf05::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    LabDiskImage image;
    std::string read_err;
    const bool loaded = LoadLabDisk(image, read_err);
    if (loaded || read_err != "BTX035_RECOVERY_REQUIRED") {
        err = read_err.empty() ? std::string("BTX035_RECOVERY_REQUIRED") : read_err;
        return false;
    }
    m_done = true;
    err.clear();
    return true;
}

bool Prf05::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Prf05::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
