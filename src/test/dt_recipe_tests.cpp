// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_recipe/dt_recipe.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cmath>
#include <cstdint>
#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_recipe_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(adamw_step_freezes_the_name_and_draft_leaves_the_weight)
{
    modelnet::DtRecipe recipe;
    std::string err = "prior";
    BOOST_CHECK(!recipe.qualified_v41());
    BOOST_CHECK(!recipe.backbone_changed());
    BOOST_CHECK(!recipe.launched());
    BOOST_CHECK(!recipe.gpu());
    BOOST_CHECK(!recipe.broadcast());
    BOOST_CHECK(!recipe.frozen());
    BOOST_CHECK(recipe.name().empty());
    BOOST_CHECK_EQUAL(recipe.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(recipe.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(recipe.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(recipe.atoms_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(recipe.Pin(modelnet::DT_RECIPE_ADAMW, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(recipe.name(), "adamw");
    BOOST_CHECK(!recipe.frozen());

    BOOST_CHECK(recipe.Role(modelnet::DT_RECIPE_MATRIX, 1.0, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(recipe.has_role("matrix"));
    BOOST_CHECK(std::fabs(recipe.weight("matrix") - 1.0) <= 1e-12);

    BOOST_CHECK(recipe.Step("matrix", 0.5, 0.1, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(recipe.frozen());
    BOOST_CHECK(std::fabs(recipe.weight("matrix") - 0.95) <= 1e-12);
    BOOST_CHECK(!recipe.backbone_changed());

    BOOST_CHECK(!recipe.Pin(modelnet::DT_RECIPE_SGD, err));
    BOOST_CHECK_EQUAL(err, "FROZEN");
    BOOST_CHECK_EQUAL(err, modelnet::DT_RECIPE_FROZEN);
    BOOST_CHECK_EQUAL(recipe.name(), "adamw");
    BOOST_CHECK(std::fabs(recipe.weight("matrix") - 0.95) <= 1e-12);

    BOOST_CHECK(recipe.Pin("adamw", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(recipe.name(), "adamw");

    BOOST_CHECK(!recipe.Step("matrix", std::numeric_limits<double>::quiet_NaN(), 0.1, err));
    BOOST_CHECK_EQUAL(err, "NONFINITE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_RECIPE_NONFINITE);
    BOOST_CHECK(std::fabs(recipe.weight("matrix") - 0.95) <= 1e-12);

    BOOST_CHECK(!recipe.Step("matrix", 0.5, std::numeric_limits<double>::infinity(), err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_RECIPE_NONFINITE);
    BOOST_CHECK(std::fabs(recipe.weight("matrix") - 0.95) <= 1e-12);

    BOOST_CHECK(recipe.Draft(9.0, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(recipe.has_draft());
    BOOST_CHECK(std::fabs(recipe.draft_loss() - 9.0) <= 1e-12);
    BOOST_CHECK(std::fabs(recipe.weight("matrix") - 0.95) <= 1e-12);
    BOOST_CHECK(!recipe.backbone_changed());

    BOOST_CHECK(!recipe.Draft(std::numeric_limits<double>::quiet_NaN(), err));
    BOOST_CHECK_EQUAL(err, "NONFINITE");
    BOOST_CHECK(std::fabs(recipe.draft_loss() - 9.0) <= 1e-12);
    BOOST_CHECK(std::fabs(recipe.weight("matrix") - 0.95) <= 1e-12);
    BOOST_CHECK(!recipe.backbone_changed());

    BOOST_CHECK(!recipe.Pin(modelnet::DT_RECIPE_FP8, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(recipe.name(), "adamw");
    BOOST_CHECK(std::fabs(recipe.weight("matrix") - 0.95) <= 1e-12);

    BOOST_CHECK(!recipe.qualified_v41());
    BOOST_CHECK(!recipe.launched());
    BOOST_CHECK(!recipe.gpu());
    BOOST_CHECK(!recipe.broadcast());
    BOOST_CHECK(!recipe.backbone_changed());
    BOOST_CHECK_EQUAL(recipe.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(recipe.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(recipe.atoms_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(roles_stay_split_and_a_step_is_required_to_freeze)
{
    modelnet::DtRecipe recipe;
    std::string err = "prior";

    BOOST_CHECK(!recipe.Pin("", err));
    BOOST_CHECK_EQUAL(err, "PROFILE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_RECIPE_PROFILE);
    BOOST_CHECK(recipe.name().empty());

    BOOST_CHECK(!recipe.Pin(modelnet::DT_RECIPE_FP8, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(recipe.name().empty());
    BOOST_CHECK(!recipe.frozen());

    BOOST_CHECK(!recipe.Pin("rmsprop", err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_RECIPE_PROFILE);
    BOOST_CHECK(recipe.name().empty());

    BOOST_CHECK(recipe.Pin("adamw", err));
    BOOST_CHECK(recipe.Pin(modelnet::DT_RECIPE_SGD, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(recipe.name(), "sgd");
    BOOST_CHECK(!recipe.frozen());

    BOOST_CHECK(!recipe.Pin("", err));
    BOOST_CHECK_EQUAL(err, "PROFILE");
    BOOST_CHECK_EQUAL(recipe.name(), "sgd");

    BOOST_CHECK(!recipe.Role("attention", 4.0, err));
    BOOST_CHECK_EQUAL(err, "ROLE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_RECIPE_ROLE);
    BOOST_CHECK(!recipe.has_role("attention"));
    BOOST_CHECK(std::fabs(recipe.weight("attention") - 0.0) <= 1e-12);

    BOOST_CHECK(!recipe.Role(modelnet::DT_RECIPE_MATRIX, std::numeric_limits<double>::quiet_NaN(), err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_RECIPE_NONFINITE);
    BOOST_CHECK(!recipe.has_role("matrix"));

    BOOST_CHECK(recipe.Role("matrix", 1.0, err));
    BOOST_CHECK(recipe.Role(modelnet::DT_RECIPE_EMBEDDING, 2.0, err));
    BOOST_CHECK(recipe.Role(modelnet::DT_RECIPE_SCALAR, 3.0, err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!recipe.Role("matrix", 8.0, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(std::fabs(recipe.weight("matrix") - 1.0) <= 1e-12);
    BOOST_CHECK(std::fabs(recipe.weight("embedding") - 2.0) <= 1e-12);
    BOOST_CHECK(std::fabs(recipe.weight("scalar") - 3.0) <= 1e-12);

    modelnet::DtRecipe unpinned;
    BOOST_CHECK(unpinned.Role("matrix", 1.0, err));
    BOOST_CHECK(!unpinned.Step("matrix", 0.5, 0.1, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_RECIPE_PROFILE);
    BOOST_CHECK(std::fabs(unpinned.weight("matrix") - 1.0) <= 1e-12);
    BOOST_CHECK(!unpinned.frozen());
    BOOST_CHECK(unpinned.Pin("adamw", err));
    BOOST_CHECK_EQUAL(unpinned.name(), "adamw");

    BOOST_CHECK(!recipe.Step("missing", 0.5, 0.1, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_RECIPE_ROLE);
    BOOST_CHECK(!recipe.frozen());
    BOOST_CHECK(std::fabs(recipe.weight("matrix") - 1.0) <= 1e-12);

    BOOST_CHECK(recipe.Step("matrix", 0.5, 0.1, err));
    BOOST_CHECK(std::fabs(recipe.weight("matrix") - 0.95) <= 1e-12);
    BOOST_CHECK(std::fabs(recipe.weight("embedding") - 2.0) <= 1e-12);
    BOOST_CHECK(std::fabs(recipe.weight("scalar") - 3.0) <= 1e-12);
    BOOST_CHECK(recipe.frozen());
    BOOST_CHECK_EQUAL(recipe.name(), "sgd");

    BOOST_CHECK(recipe.Step(modelnet::DT_RECIPE_EMBEDDING, 1.0, 0.25, err));
    BOOST_CHECK(std::fabs(recipe.weight("embedding") - 1.75) <= 1e-12);
    BOOST_CHECK(std::fabs(recipe.weight("matrix") - 0.95) <= 1e-12);
    BOOST_CHECK(std::fabs(recipe.weight("scalar") - 3.0) <= 1e-12);

    BOOST_CHECK(!recipe.Pin("adamw", err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_RECIPE_FROZEN);
    BOOST_CHECK_EQUAL(recipe.name(), "sgd");

    BOOST_CHECK(recipe.Draft(9.0, err));
    BOOST_CHECK(!recipe.backbone_changed());
    BOOST_CHECK(std::fabs(recipe.weight("matrix") - 0.95) <= 1e-12);
    BOOST_CHECK(std::fabs(recipe.weight("embedding") - 1.75) <= 1e-12);
    BOOST_CHECK(std::fabs(recipe.weight("scalar") - 3.0) <= 1e-12);
    BOOST_CHECK_EQUAL(recipe.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(recipe.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!recipe.qualified_v41());
    BOOST_CHECK(!recipe.launched());
    BOOST_CHECK(!recipe.gpu());
    BOOST_CHECK(!recipe.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
