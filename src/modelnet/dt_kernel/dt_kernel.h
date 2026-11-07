// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_KERNEL_DT_KERNEL_H
#define BITCOIN_MODELNET_DT_KERNEL_DT_KERNEL_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** A weight, activation, gradient, or learning rate was not finite. Nothing is stored. */
inline constexpr char DT_KERNEL_NONFINITE[] = "NONFINITE";

/** The call is ahead of the step. Stored weights, outputs, and gradients stay. */
inline constexpr char DT_KERNEL_ORDER[] = "ORDER";

/**
 * Laboratory 2x2 map.
 *
 *   y0 = w00*x0 + w01*x1
 *   y1 = w10*x0 + w11*x1
 *   dx0 = w00*dy0 + w10*dy1
 *   dx1 = w01*dy0 + w11*dy1
 *   gw00 = dy0*x0  gw01 = dy0*x1
 *   gw10 = dy1*x0  gw11 = dy1*x1
 *   w := w - lr * gw
 *
 * Values are the FP32 formula held in double. This is not DualPipe and not
 * a hardware measurement. hardware_qualified() stays false. gpu(),
 * launched(), and broadcast() stay false. automatic_spend() is "0".
 * bytes_moved() and atoms_moved() stay 0. No process is spawned.
 *
 * Load stores the weight. A non-finite value is NONFINITE and stores nothing.
 * Forward stores y. A non-finite input is NONFINITE and does not change y.
 * forward_count() increases by 1 only on success. Forward before Load is ORDER.
 * Dgrad stores dx and does not change the weight. Dgrad before a successful
 * Forward is ORDER. A non-finite dy after that Forward is NONFINITE and does
 * not change dx. dgrad_count() increases by 1 only on success.
 * Wgrad stores gw and does not apply it. Wgrad before Dgrad for this step is
 * ORDER. Apply subtracts lr times gw only after both Dgrad and Wgrad have
 * succeeded since the last successful Apply. Otherwise ORDER. A non-finite
 * lr on a ready step is NONFINITE and does not change the weight. A successful
 * Apply clears those two step marks, so a second Apply without a new Wgrad
 * is ORDER. Cumulative forward_count() and dgrad_count() stay.
 * DualPipe returns false with NIFDT_ENGINE_ABSENT and does not change the
 * weight or either count.
 */
class DtKernel {
public:
    bool Load(double w00, double w01, double w10, double w11, std::string& err);
    bool Forward(double x0, double x1, std::string& err);
    bool Dgrad(double dy0, double dy1, std::string& err);
    bool Wgrad(double x0, double x1, double dy0, double dy1, std::string& err);
    bool Apply(double lr, std::string& err);
    bool DualPipe(std::string& err);

    double w00() const { return m_w00; }
    double w01() const { return m_w01; }
    double w10() const { return m_w10; }
    double w11() const { return m_w11; }
    double y0() const { return m_y0; }
    double y1() const { return m_y1; }
    double dx0() const { return m_dx0; }
    double dx1() const { return m_dx1; }
    double gw00() const { return m_gw00; }
    double gw01() const { return m_gw01; }
    double gw10() const { return m_gw10; }
    double gw11() const { return m_gw11; }

    bool loaded() const { return m_loaded; }
    std::int64_t forward_count() const { return m_forward_count; }
    std::int64_t dgrad_count() const { return m_dgrad_count; }

    bool hardware_qualified() const { return false; }
    bool gpu() const { return false; }
    bool launched() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    std::int64_t bytes_moved() const { return static_cast<std::int64_t>(0); }
    std::int64_t atoms_moved() const { return static_cast<std::int64_t>(0); }

private:
    double m_w00{0};
    double m_w01{0};
    double m_w10{0};
    double m_w11{0};
    double m_y0{0};
    double m_y1{0};
    double m_dx0{0};
    double m_dx1{0};
    double m_gw00{0};
    double m_gw01{0};
    double m_gw10{0};
    double m_gw11{0};
    std::int64_t m_forward_count{0};
    std::int64_t m_dgrad_count{0};
    bool m_loaded{false};
    bool m_have_forward{false};
    bool m_step_dgrad{false};
    bool m_step_wgrad{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_KERNEL_DT_KERNEL_H
