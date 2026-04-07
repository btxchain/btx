from setuptools import setup, find_packages
import os

# Get the absolute path to the directory containing setup.py
here = os.path.abspath(os.path.dirname(__file__))

# Read the README.md file safely
with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

# Use the README.md in the python directory if it exists, otherwise use the root README
if not os.path.exists(os.path.join(here, "README.md")):
    with open(os.path.join(here, "..", "README.md"), encoding="utf-8") as f:
        long_description = f.read()

setup(
    name="bitcoinpqc",
    version="0.1.0",
    packages=find_packages(),
    description="Python bindings for libbitcoinpqc",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Bitcoin PQC Developers",
    url="https://github.com/bitcoinpqc/libbitcoinpqc",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.7",
    # Add explicit entry for test_suite if you have tests
    test_suite="tests",
)
