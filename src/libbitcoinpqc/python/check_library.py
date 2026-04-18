#!/usr/bin/env python3
"""
Check if the libbitcoinpqc C library can be found and loaded.
"""

import os
import sys
import ctypes
from pathlib import Path
import platform
from datetime import datetime


def find_library():
    """Find the bitcoinpqc shared library."""
    search_paths = [
        Path.cwd(),
        Path(__file__).parent.parent,
        Path("/usr/lib"),
        Path("/usr/local/lib"),
        # CMake build directory
        Path(__file__).parent.parent / "build" / "lib",
        # Rust build directories
        Path(__file__).parent.parent / "target" / "debug",
        Path(__file__).parent.parent / "target" / "debug" / "deps",
        Path(__file__).parent.parent / "target" / "release",
        Path(__file__).parent.parent / "target" / "release" / "deps",
    ]

    if platform.system() == "Windows":
        lib_names = ["bitcoinpqc.dll"]
    elif platform.system() == "Darwin":  # macOS
        lib_names = ["libbitcoinpqc.dylib", "libbitcoinpqc.so"]
    else:  # Linux/Unix
        lib_names = ["libbitcoinpqc.so", "libbitcoinpqc.dylib"]

    print("Searching for library...")
    for path in search_paths:
        print(f"Looking in {path}")
        for name in lib_names:
            lib_path = path / name
            if lib_path.exists():
                print(f"Found at: {lib_path}")
                return str(lib_path)

    print("Library not found in standard locations")
    return None


def main():
    """Check if the C library can be loaded."""
    print("Bitcoin PQC Library Check Utility")
    print("=================================")

    # Check if we're running from the source directory
    if Path(__file__).parent.name == "python":
        print("Running from python source directory")

    # Find the library
    lib_path = find_library()

    if lib_path is None:
        print("Could not find the libbitcoinpqc library")
        print("\nTry building the C library with:")
        print("  mkdir -p build && cd build && cmake .. && make")
        print("  cd ..")
        sys.exit(1)

    # Try to load the library
    try:
        print(f"Attempting to load {lib_path}")
        lib = ctypes.CDLL(lib_path)
        print("Successfully loaded the library!")

        # Check if basic functions are available
        if hasattr(lib, "bitcoin_pqc_public_key_size"):
            print("Found bitcoin_pqc_public_key_size function")
        else:
            print("WARNING: bitcoin_pqc_public_key_size function not found")

        # Print the library info
        print("\nLibrary Information:")
        print(f"  Path: {lib_path}")
        print(f"  Size: {os.path.getsize(lib_path) / 1024:.1f} KB")
        print(f"  Modified: {datetime.fromtimestamp(os.path.getmtime(lib_path)).strftime('%Y-%m-%d %H:%M:%S')}")

        print("\nAll checks passed. The Python bindings should work correctly.")
        return 0
    except Exception as e:
        print(f"Failed to load the library: {e}")
        print("\nPossible solutions:")
        print("1. Make sure you have built the C library correctly")
        print("2. Check that the library file exists and is readable")
        print("3. On Linux, add the library directory to LD_LIBRARY_PATH:")
        print("   export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/path/to/library/dir")
        print("4. On macOS, add the library directory to DYLD_LIBRARY_PATH:")
        print("   export DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH:/path/to/library/dir")
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())
