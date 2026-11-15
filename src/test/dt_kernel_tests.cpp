// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_kernel/dt_kernel.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cmath>
#include <cstdint>
#include <limits>
#include <string>

namespace {

bool Close(double got, double want)
{
    return std::fabs(got - want) <= 1e-12;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(dt_kernel_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(identity_step_apply_and_dualpipe_leaves_weight)
{
    modelnet::DtKernel kernel;
    BOOST_CHECK(!kernel.hardware_qualified());
    BOOST_CHECK(!kernel.gpu());
    BOOST_CHECK(!kernel.launched());
    BOOST_CHECK(!kernel.broadcast());
    BOOST_CHECK_EQUAL(kernel.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(kernel.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(kernel.forward_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(kernel.dgrad_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(kernel.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(kernel.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!kernel.loaded());

    std::string err = "prior";
    BOOST_CHECK(kernel.Load(1.0, 0.0, 0.0, 1.0, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(kernel.loaded());
    BOOST_CHECK(Close(kernel.w00(), 1.0));
    BOOST_CHECK(Close(kernel.w01(), 0.0));
    BOOST_CHECK(Close(kernel.w10(), 0.0));
    BOOST_CHECK(Close(kernel.w11(), 1.0));

    BOOST_CHECK(kernel.Forward(2.0, 3.0, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(Close(kernel.y0(), 2.0));
    BOOST_CHECK(Close(kernel.y1(), 3.0));
    BOOST_CHECK_EQUAL(kernel.forward_count(), static_cast<int64_t>(1));

    BOOST_CHECK(kernel.Dgrad(1.0, 0.0, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(Close(kernel.dx0(), 1.0));
    BOOST_CHECK(Close(kernel.dx1(), 0.0));
    BOOST_CHECK(Close(kernel.w00(), 1.0));
    BOOST_CHECK(Close(kernel.w01(), 0.0));
    BOOST_CHECK(Close(kernel.w10(), 0.0));
    BOOST_CHECK(Close(kernel.w11(), 1.0));
    BOOST_CHECK_EQUAL(kernel.dgrad_count(), static_cast<int64_t>(1));

    BOOST_CHECK(kernel.Wgrad(2.0, 3.0, 1.0, 0.0, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(Close(kernel.gw00(), 2.0));
    BOOST_CHECK(Close(kernel.gw01(), 3.0));
    BOOST_CHECK(Close(kernel.gw10(), 0.0));
    BOOST_CHECK(Close(kernel.gw11(), 0.0));
    BOOST_CHECK(Close(kernel.w00(), 1.0));
    BOOST_CHECK(Close(kernel.w11(), 1.0));

    BOOST_CHECK(kernel.Apply(0.5, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(Close(kernel.w00(), 0.0));
    BOOST_CHECK(Close(kernel.w01(), -1.5));
    BOOST_CHECK(Close(kernel.w10(), 0.0));
    BOOST_CHECK(Close(kernel.w11(), 1.0));
    BOOST_CHECK_EQUAL(kernel.forward_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(kernel.dgrad_count(), static_cast<int64_t>(1));

    BOOST_CHECK(!kernel.Apply(0.5, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(err, modelnet::DT_KERNEL_ORDER);
    BOOST_CHECK(Close(kernel.w00(), 0.0));
    BOOST_CHECK(Close(kernel.w01(), -1.5));
    BOOST_CHECK_EQUAL(kernel.forward_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(kernel.dgrad_count(), static_cast<int64_t>(1));

    const double w00 = kernel.w00();
    const double w01 = kernel.w01();
    const double w10 = kernel.w10();
    const double w11 = kernel.w11();
    BOOST_CHECK(!kernel.DualPipe(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(Close(kernel.w00(), w00));
    BOOST_CHECK(Close(kernel.w01(), w01));
    BOOST_CHECK(Close(kernel.w10(), w10));
    BOOST_CHECK(Close(kernel.w11(), w11));
    BOOST_CHECK(Close(kernel.w00(), 0.0));
    BOOST_CHECK_EQUAL(kernel.forward_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(kernel.dgrad_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!kernel.hardware_qualified());
    BOOST_CHECK(!kernel.gpu());
    BOOST_CHECK(!kernel.launched());
    BOOST_CHECK(!kernel.broadcast());
    BOOST_CHECK_EQUAL(kernel.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(kernel.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(kernel.atoms_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(nonfinite_load_and_forward_store_nothing)
{
    modelnet::DtKernel kernel;
    std::string err = "prior";
    const double nan = std::numeric_limits<double>::quiet_NaN();
    const double inf = std::numeric_limits<double>::infinity();

    BOOST_CHECK(!kernel.Load(nan, 0.0, 0.0, 1.0, err));
    BOOST_CHECK_EQUAL(err, "NONFINITE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_KERNEL_NONFINITE);
    BOOST_CHECK(!kernel.loaded());
    BOOST_CHECK(Close(kernel.w00(), 0.0));
    BOOST_CHECK(Close(kernel.w11(), 0.0));
    BOOST_CHECK_EQUAL(kernel.forward_count(), static_cast<int64_t>(0));

    BOOST_CHECK(!kernel.Load(1.0, inf, 0.0, 1.0, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_KERNEL_NONFINITE);
    BOOST_CHECK(!kernel.loaded());

    BOOST_CHECK(kernel.Load(1.0, 0.0, 0.0, 1.0, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!kernel.Load(1.0, 0.0, 0.0, nan, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_KERNEL_NONFINITE);
    BOOST_CHECK(Close(kernel.w00(), 1.0));
    BOOST_CHECK(Close(kernel.w01(), 0.0));
    BOOST_CHECK(Close(kernel.w10(), 0.0));
    BOOST_CHECK(Close(kernel.w11(), 1.0));

    BOOST_CHECK(kernel.Forward(2.0, 3.0, err));
    BOOST_CHECK(Close(kernel.y0(), 2.0));
    BOOST_CHECK(Close(kernel.y1(), 3.0));
    BOOST_CHECK_EQUAL(kernel.forward_count(), static_cast<int64_t>(1));

    BOOST_CHECK(!kernel.Forward(nan, 3.0, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_KERNEL_NONFINITE);
    BOOST_CHECK(Close(kernel.y0(), 2.0));
    BOOST_CHECK(Close(kernel.y1(), 3.0));
    BOOST_CHECK_EQUAL(kernel.forward_count(), static_cast<int64_t>(1));

    BOOST_CHECK(!kernel.Forward(2.0, -inf, err));
    BOOST_CHECK_EQUAL(err, "NONFINITE");
    BOOST_CHECK(Close(kernel.y0(), 2.0));
    BOOST_CHECK(Close(kernel.y1(), 3.0));
    BOOST_CHECK_EQUAL(kernel.forward_count(), static_cast<int64_t>(1));
    BOOST_CHECK(Close(kernel.w00(), 1.0));
}

BOOST_AUTO_TEST_CASE(order_and_nonfinite_gradient_leave_state)
{
    modelnet::DtKernel kernel;
    std::string err = "prior";
    const double nan = std::numeric_limits<double>::quiet_NaN();

    BOOST_CHECK(!kernel.Forward(2.0, 3.0, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_KERNEL_ORDER);
    BOOST_CHECK(Close(kernel.y0(), 0.0));
    BOOST_CHECK_EQUAL(kernel.forward_count(), static_cast<int64_t>(0));

    BOOST_CHECK(!kernel.Dgrad(1.0, 0.0, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(err, modelnet::DT_KERNEL_ORDER);
    BOOST_CHECK(Close(kernel.dx0(), 0.0));
    BOOST_CHECK(Close(kernel.dx1(), 0.0));
    BOOST_CHECK_EQUAL(kernel.dgrad_count(), static_cast<int64_t>(0));

    BOOST_CHECK(kernel.Load(1.0, 0.0, 0.0, 1.0, err));
    BOOST_CHECK(kernel.Forward(2.0, 3.0, err));
    BOOST_CHECK(!kernel.Wgrad(2.0, 3.0, 1.0, 0.0, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_KERNEL_ORDER);
    BOOST_CHECK(Close(kernel.gw00(), 0.0));
    BOOST_CHECK(Close(kernel.gw01(), 0.0));
    BOOST_CHECK(Close(kernel.gw10(), 0.0));
    BOOST_CHECK(Close(kernel.gw11(), 0.0));
    BOOST_CHECK(Close(kernel.w00(), 1.0));

    BOOST_CHECK(!kernel.Apply(0.5, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_KERNEL_ORDER);
    BOOST_CHECK(Close(kernel.w00(), 1.0));
    BOOST_CHECK(Close(kernel.w11(), 1.0));

    BOOST_CHECK(kernel.Dgrad(1.0, 0.0, err));
    BOOST_CHECK(Close(kernel.dx0(), 1.0));
    BOOST_CHECK(Close(kernel.dx1(), 0.0));
    BOOST_CHECK_EQUAL(kernel.dgrad_count(), static_cast<int64_t>(1));
    BOOST_CHECK(Close(kernel.w00(), 1.0));

    BOOST_CHECK(!kernel.Dgrad(nan, 0.0, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_KERNEL_NONFINITE);
    BOOST_CHECK(Close(kernel.dx0(), 1.0));
    BOOST_CHECK(Close(kernel.dx1(), 0.0));
    BOOST_CHECK_EQUAL(kernel.dgrad_count(), static_cast<int64_t>(1));
    BOOST_CHECK(Close(kernel.w00(), 1.0));
    BOOST_CHECK(Close(kernel.w11(), 1.0));

    BOOST_CHECK(!kernel.Wgrad(nan, 3.0, 1.0, 0.0, err));
    BOOST_CHECK_EQUAL(err, "NONFINITE");
    BOOST_CHECK(Close(kernel.gw00(), 0.0));
    BOOST_CHECK(Close(kernel.w00(), 1.0));
    BOOST_CHECK_EQUAL(kernel.dgrad_count(), static_cast<int64_t>(1));

    BOOST_CHECK(kernel.Wgrad(2.0, 3.0, 1.0, 0.0, err));
    BOOST_CHECK(Close(kernel.gw00(), 2.0));
    BOOST_CHECK(Close(kernel.gw01(), 3.0));
    BOOST_CHECK(!kernel.Apply(nan, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_KERNEL_NONFINITE);
    BOOST_CHECK(Close(kernel.w00(), 1.0));
    BOOST_CHECK(Close(kernel.w01(), 0.0));
    BOOST_CHECK(Close(kernel.w10(), 0.0));
    BOOST_CHECK(Close(kernel.w11(), 1.0));
    BOOST_CHECK_EQUAL(kernel.forward_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(kernel.dgrad_count(), static_cast<int64_t>(1));

    BOOST_CHECK(kernel.Apply(0.5, err));
    BOOST_CHECK(Close(kernel.w00(), 0.0));
    BOOST_CHECK(!kernel.Wgrad(2.0, 3.0, 1.0, 0.0, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_KERNEL_ORDER);
    BOOST_CHECK(Close(kernel.gw00(), 2.0));
    BOOST_CHECK(Close(kernel.w00(), 0.0));
    BOOST_CHECK(!kernel.hardware_qualified());
    BOOST_CHECK_EQUAL(kernel.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(kernel.atoms_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_SUITE_END()
