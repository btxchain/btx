// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_kernel/dt_kernel.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cmath>

namespace modelnet {
namespace {

bool Finite(double value)
{
    return std::isfinite(value);
}

} // namespace

bool DtKernel::Load(double w00, double w01, double w10, double w11, std::string& err)
{
    if (!Finite(w00) || !Finite(w01) || !Finite(w10) || !Finite(w11)) {
        err = DT_KERNEL_NONFINITE;
        return false;
    }
    m_w00 = w00;
    m_w01 = w01;
    m_w10 = w10;
    m_w11 = w11;
    m_loaded = true;
    err.clear();
    return true;
}

bool DtKernel::Forward(double x0, double x1, std::string& err)
{
    if (!Finite(x0) || !Finite(x1)) {
        err = DT_KERNEL_NONFINITE;
        return false;
    }
    if (!m_loaded) {
        err = DT_KERNEL_ORDER;
        return false;
    }
    const double y0 = m_w00 * x0 + m_w01 * x1;
    const double y1 = m_w10 * x0 + m_w11 * x1;
    if (!Finite(y0) || !Finite(y1)) {
        err = DT_KERNEL_NONFINITE;
        return false;
    }
    m_y0 = y0;
    m_y1 = y1;
    m_have_forward = true;
    m_forward_count += 1;
    err.clear();
    return true;
}

bool DtKernel::Dgrad(double dy0, double dy1, std::string& err)
{
    if (!m_have_forward) {
        err = DT_KERNEL_ORDER;
        return false;
    }
    if (!Finite(dy0) || !Finite(dy1)) {
        err = DT_KERNEL_NONFINITE;
        return false;
    }
    const double dx0 = m_w00 * dy0 + m_w10 * dy1;
    const double dx1 = m_w01 * dy0 + m_w11 * dy1;
    if (!Finite(dx0) || !Finite(dx1)) {
        err = DT_KERNEL_NONFINITE;
        return false;
    }
    m_dx0 = dx0;
    m_dx1 = dx1;
    m_step_dgrad = true;
    m_dgrad_count += 1;
    err.clear();
    return true;
}

bool DtKernel::Wgrad(double x0, double x1, double dy0, double dy1, std::string& err)
{
    if (!m_step_dgrad) {
        err = DT_KERNEL_ORDER;
        return false;
    }
    if (!Finite(x0) || !Finite(x1) || !Finite(dy0) || !Finite(dy1)) {
        err = DT_KERNEL_NONFINITE;
        return false;
    }
    const double gw00 = dy0 * x0;
    const double gw01 = dy0 * x1;
    const double gw10 = dy1 * x0;
    const double gw11 = dy1 * x1;
    if (!Finite(gw00) || !Finite(gw01) || !Finite(gw10) || !Finite(gw11)) {
        err = DT_KERNEL_NONFINITE;
        return false;
    }
    m_gw00 = gw00;
    m_gw01 = gw01;
    m_gw10 = gw10;
    m_gw11 = gw11;
    m_step_wgrad = true;
    err.clear();
    return true;
}

bool DtKernel::Apply(double lr, std::string& err)
{
    if (!m_step_dgrad || !m_step_wgrad) {
        err = DT_KERNEL_ORDER;
        return false;
    }
    if (!Finite(lr)) {
        err = DT_KERNEL_NONFINITE;
        return false;
    }
    const double w00 = m_w00 - lr * m_gw00;
    const double w01 = m_w01 - lr * m_gw01;
    const double w10 = m_w10 - lr * m_gw10;
    const double w11 = m_w11 - lr * m_gw11;
    if (!Finite(w00) || !Finite(w01) || !Finite(w10) || !Finite(w11)) {
        err = DT_KERNEL_NONFINITE;
        return false;
    }
    m_w00 = w00;
    m_w01 = w01;
    m_w10 = w10;
    m_w11 = w11;
    m_step_dgrad = false;
    m_step_wgrad = false;
    err.clear();
    return true;
}

bool DtKernel::DualPipe(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
