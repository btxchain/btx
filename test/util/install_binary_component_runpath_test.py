#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Compile an inert Linux probe with the live packaged-library CMake helper."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "cmake/module/InstallBinaryComponent.cmake"
SONAME = "libbtx_runpath_regression_421ad01e.so.1"
OUTPUT = "runpath-regression:42\n"
OPTIONS = argparse.Namespace(cmake=None, compiler=None, generator="Unix Makefiles", output_dir=None)

PROJECT = r'''cmake_minimum_required(VERSION 3.22)
project(BTXRunpathRegression LANGUAGES CXX)
set(CMAKE_SKIP_INSTALL_RPATH TRUE)
include("${BTX_MODULE_FILE}")
add_library(btx_runpath_regression_421ad01e SHARED marker.cpp)
set_target_properties(btx_runpath_regression_421ad01e PROPERTIES
  SOVERSION 1 LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
add_executable(probe probe.cpp)
set_target_properties(probe PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
target_link_libraries(probe PRIVATE btx_runpath_regression_421ad01e)
set_property(TARGET probe PROPERTY LINK_FLAGS " -Wl,--as-needed")
btx_set_packaged_lib_runpath(probe)
get_target_property(probe_flags probe LINK_FLAGS)
string(FIND "${probe_flags}" "-Wl,--as-needed" caller_flag)
if(caller_flag LESS 0)
  message(FATAL_ERROR "Packaged runpath helper replaced caller-owned flags")
endif()
'''
MARKER = 'extern "C" int btx_runpath_value() { return 42; }\n'
PROBE = r'''#include <cstdio>
extern "C" int btx_runpath_value();
int main() {
    const int value = btx_runpath_value();
    std::printf("runpath-regression:%d\n", value);
    return value == 42 ? 0 : 1;
}
'''


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux ELF producer test")
class PackagedRunpathTest(unittest.TestCase):
    observations = []
    commands = []

    @classmethod
    def setUpClass(cls):
        cls.observations = []
        cls.commands = []
        cls.started = time.monotonic()
        if OPTIONS.output_dir:
            parent = Path(OPTIONS.output_dir)
            parent.mkdir(parents=True, exist_ok=True)
            cls.output = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
        else:
            cls.output_temp = tempfile.TemporaryDirectory(prefix="btx-runpath-records-")
            cls.output = Path(cls.output_temp.name)
        cls.scratch = tempfile.TemporaryDirectory(prefix="work-", dir=cls.output)
        cls.work = Path(cls.scratch.name)
        cls.addClassCleanup(cls.clean_scratch)
        cls.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C",
                   "HOME": str(cls.work / "home")}
        (cls.work / "home").mkdir()
        cls.cmake = OPTIONS.cmake or shutil.which("cmake")
        # Keep clang++'s invocation name rather than resolving its symlink.
        cls.compiler = OPTIONS.compiler or shutil.which("c++")
        cls.readelf = shutil.which("readelf")
        if not all([cls.cmake, cls.compiler, cls.readelf]):
            raise RuntimeError("Linux runpath test requires CMake, a C++ compiler and readelf")
        generator_tool = "ninja" if OPTIONS.generator == "Ninja" else "make"
        if not shutil.which(generator_tool):
            raise RuntimeError("Missing selected generator tool: " + generator_tool)
        cls.module_before = hashlib.sha256(MODULE.read_bytes()).hexdigest()
        cls.inputs = {"module": str(MODULE), "module_sha256": cls.module_before,
                      "test_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      "cmake": cls.cmake, "compiler": cls.compiler,
                      "generator": OPTIONS.generator}
        print("Runpath regression records: " + str(cls.output), flush=True)

    @classmethod
    def clean_scratch(cls):
        cls.scratch.cleanup()
        cls.scratch_removed = not cls.work.exists()
        cls.module_after = hashlib.sha256(MODULE.read_bytes()).hexdigest() if MODULE.exists() else None
        cls.write_observations()
        if not cls.scratch_removed:
            raise AssertionError("Runpath test scratch was not removed")
        if hasattr(cls, "module_before") and cls.module_after != cls.module_before:
            raise AssertionError("The test changed its live production module")

    @classmethod
    def write_observations(cls):
        (cls.output / "OBSERVATIONS.json").write_text(json.dumps({
            "inputs": getattr(cls, "inputs", {}), "observations": cls.observations,
            "commands": cls.commands, "scratch_removed": getattr(cls, "scratch_removed", False),
            "module_after": getattr(cls, "module_after", None)}, indent=2) + "\n")

    def run_command(self, argv):
        remaining = 90 - (time.monotonic() - self.started)
        if remaining <= 0:
            raise RuntimeError("Runpath test's 90-second command budget exhausted")
        entry = {"argv": [str(a) for a in argv]}
        self.commands.append(entry)
        proc = subprocess.Popen(entry["argv"], cwd=self.work, env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, start_new_session=True)
        try:
            output, _ = proc.communicate(timeout=min(30, remaining))
        except subprocess.TimeoutExpired:
            entry["timeout"] = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            output, _ = proc.communicate()
            entry["returncode"] = proc.returncode
            log = "command-%03d.log" % len(self.commands)
            (self.output / log).write_text(output)
            entry["log"] = log
            raise
        log = "command-%03d.log" % len(self.commands)
        (self.output / log).write_text(output)
        entry.update(returncode=proc.returncode, log=log)
        return proc.returncode, output

    def successful(self, argv):
        code, output = self.run_command(argv)
        self.assertEqual(code, 0, output)
        return output

    def build_relocated_probe(self, *, opt_out):
        area = self.work / self._testMethodName
        source, build, installed = area / "source", area / "build", area / "relocated"
        source.mkdir(parents=True)
        for name, data in [("CMakeLists.txt", PROJECT), ("marker.cpp", MARKER), ("probe.cpp", PROBE)]:
            (source / name).write_text(data)
        observation = {"test": self._testMethodName, "opt_out": opt_out, "built": False}
        self.observations.append(observation)
        self.successful([self.cmake, "-S", source, "-B", build, "-G", OPTIONS.generator,
                         "-DBTX_MODULE_FILE=" + str(MODULE),
                         "-DCMAKE_CXX_COMPILER=" + str(self.compiler), "-DCMAKE_BUILD_TYPE=Release",
                         "-DCMAKE_SKIP_BUILD_RPATH=" + ("ON" if opt_out else "OFF")])
        self.successful([self.cmake, "--build", build, "--parallel", "1", "--verbose"])
        observation["built"] = True
        dynamic = self.successful([self.readelf, "-d", build / "bin/probe"])
        observation["needed"] = re.findall(r"\(NEEDED\).*?\[(.*?)\]", dynamic)
        observation["runpath"] = re.findall(r"\(RUNPATH\).*?\[(.*?)\]", dynamic)
        observation["rpath"] = re.findall(r"\(RPATH\).*?\[(.*?)\]", dynamic)
        shutil.copytree(build / "bin", installed / "bin", symlinks=True)
        shutil.copytree(build / "lib", installed / "lib", symlinks=True)
        build.rename(area / "build-unavailable-at-original-path")
        code, output = self.run_command([installed / "bin/probe"])
        observation.update(relocated_exit=code, relocated_output=output)
        self.write_observations()
        self.assertIn(SONAME, observation["needed"])
        return installed, observation

    def test_adjacent_library_after_relocation(self):
        installed, observed = self.build_relocated_probe(opt_out=False)
        self.assertEqual(observed["runpath"], ["$ORIGIN/../lib"], "literal packaged RUNPATH")
        self.assertEqual(observed["rpath"], [])
        self.assertEqual(observed["relocated_exit"], 0, observed["relocated_output"])
        self.assertEqual(observed["relocated_output"], OUTPUT)
        (installed / "lib").rename(installed / "lib-withheld")
        try:
            code, output = self.run_command([installed / "bin/probe"])
            observed.update(missing_library_exit=code, missing_library_output=output)
            self.assertNotEqual(code, 0)
            self.assertIn(SONAME, output)
        finally:
            (installed / "lib-withheld").rename(installed / "lib")
        code, output = self.run_command([installed / "bin/probe"])
        observed.update(restored_library_exit=code, restored_library_output=output)
        self.assertEqual(code, 0, output)
        self.assertEqual(output, OUTPUT)

    def test_runtime_path_opt_out(self):
        _, observed = self.build_relocated_probe(opt_out=True)
        self.assertEqual(observed["runpath"], [])
        self.assertEqual(observed["rpath"], [])
        self.assertNotEqual(observed["relocated_exit"], 0)
        self.assertIn(SONAME, observed["relocated_output"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cmake")
    parser.add_argument("--compiler")
    parser.add_argument("--generator", choices=("Unix Makefiles", "Ninja"), default="Unix Makefiles")
    parser.add_argument("--output-dir", type=Path)
    OPTIONS, unittest_args = parser.parse_known_args()
    program = unittest.main(argv=[sys.argv[0]] + unittest_args, exit=False)
    result = program.result
    if hasattr(PackagedRunpathTest, "output"):
        summary = {"success": result.wasSuccessful(), "tests_run": result.testsRun,
                   "failures": len(result.failures), "errors": len(result.errors),
                   "skipped": len(result.skipped), "module": getattr(PackagedRunpathTest, "inputs", {}),
                   "scratch_removed": getattr(PackagedRunpathTest, "scratch_removed", False)}
        (PackagedRunpathTest.output / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
    sys.exit(0 if result.wasSuccessful() else 1)
