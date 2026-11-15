// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/tick_bind/tick_bind.h>
#include <modelnet/bnd01/bnd01.h>
#include <modelnet/bnd02/bnd02.h>
#include <modelnet/bnd03/bnd03.h>
#include <modelnet/bnd04/bnd04.h>
#include <modelnet/bnd05/bnd05.h>
#include <modelnet/bnd06/bnd06.h>
#include <modelnet/bnd07/bnd07.h>
#include <modelnet/bnd08/bnd08.h>
#include <modelnet/bnd09/bnd09.h>
#include <modelnet/bnd10/bnd10.h>
#include <modelnet/bnd11/bnd11.h>
#include <modelnet/cyc01/cyc01.h>
#include <modelnet/ext01/ext01.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool TickBind::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    Bnd01 b1;
    Bnd02 b2;
    Bnd03 b3;
    Bnd04 b4;
    Bnd05 b5;
    Bnd06 b6;
    Bnd07 b7;
    Bnd08 b8;
    Bnd09 b9;
    Bnd10 b10;
    Bnd11 b11;
    Cyc01 cycle;
    Ext01 ext;
    if (!b1.Pass(err) || !b2.Pass(err) || !b3.Pass(err) || !b4.Pass(err) ||
        !b5.Pass(err) || !b6.Pass(err) || !b7.Pass(err) || !b8.Pass(err) ||
        !b9.Pass(err) || !b10.Pass(err) || !b11.Pass(err) || !cycle.Pass(err) ||
        !ext.Pass(err)) {
        return false;
    }
    if (b1.passed() || b10.release_qualified() || b11.release_qualified() ||
        cycle.passed() || ext.passed() || ext.gpu_passed() || ext.windows_passed()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    m_done = true;
    err.clear();
    return true;
}

bool TickBind::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool TickBind::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
