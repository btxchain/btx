# libbitcoinpqc - Post-Quantum Cryptography for Bitcoin
# Main Makefile for building, testing, and installing all components

# User-configurable variables
PREFIX ?= /usr/local
DEBUG ?= 0
VERBOSE ?= 0
INSTALL_DEPS ?= 0
BUILD_DOCS ?= 0
NO_COLOR ?= 0
BUILD_BINDINGS ?= 0

# Tool detection
CMAKE := $(shell command -v cmake 2> /dev/null)
CARGO := $(shell command -v cargo 2> /dev/null)
PYTHON := $(shell command -v python3 2> /dev/null)
NPM := $(shell command -v npm 2> /dev/null)

# Build directories
BUILD_DIR := build
RELEASE_DIR := target/release
DEBUG_DIR := target/debug

# Colors for terminal output
ifeq ($(NO_COLOR), 0)
  GREEN := \033[0;32m
  YELLOW := \033[0;33m
  RED := \033[0;31m
  BLUE := \033[0;34m
  NC := \033[0m # No Color
else
  GREEN :=
  YELLOW :=
  RED :=
  BLUE :=
  NC :=
endif

# Default target
.PHONY: all
all: info c-lib rust-lib bindings

.PHONY: everything
everything: all examples tests docs

# Bindings target
.PHONY: bindings
bindings: python nodejs

# Print build information
.PHONY: info
info:
	@echo -e "${BLUE}Building libbitcoinpqc - Post-Quantum Cryptography for Bitcoin${NC}"
	@echo -e "${BLUE}------------------------------------------------------------${NC}"
	@if [ -n "$(CMAKE)" ]; then echo -e "  [${GREEN}✓${NC}] CMake: $(CMAKE)"; else echo -e "  [${RED}✗${NC}] CMake (required for C library)"; fi
	@if [ -n "$(CARGO)" ]; then echo -e "  [${GREEN}✓${NC}] Cargo: $(CARGO)"; else echo -e "  [${RED}✗${NC}] Cargo (required for Rust library)"; fi
	@if [ -n "$(PYTHON)" ]; then echo -e "  [${GREEN}✓${NC}] Python: $(PYTHON)"; else echo -e "  [${YELLOW}!${NC}] Python (optional for Python bindings)"; fi
	@if [ -n "$(NPM)" ]; then echo -e "  [${GREEN}✓${NC}] NPM: $(NPM)"; else echo -e "  [${YELLOW}!${NC}] NPM (optional for NodeJS bindings)"; fi
	@echo -e "${BLUE}------------------------------------------------------------${NC}"
	@echo -e "${YELLOW}This will build the core libraries (C and Rust) and language bindings.${NC}"
	@echo -e "${YELLOW}Available make targets:${NC}"
	@echo -e "  ${GREEN}make c-lib${NC}        - Build only the C library"
	@echo -e "  ${GREEN}make rust-lib${NC}     - Build only the Rust library"
	@echo -e "  ${GREEN}make bindings${NC}     - Build only Python and NodeJS bindings"
	@echo -e "  ${GREEN}make examples${NC}     - Build example programs"
	@echo -e "  ${GREEN}make everything${NC}   - Build all components (libraries, bindings, examples, tests)"
	@echo -e "  ${GREEN}make help${NC}         - Show all available targets"
	@echo -e "${BLUE}------------------------------------------------------------${NC}"

# C library targets
.PHONY: c-lib
c-lib: cmake-configure cmake-build

.PHONY: cmake-configure
cmake-configure:
	@echo -e "${BLUE}Configuring C library with CMake...${NC}"
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake .. -DCMAKE_BUILD_TYPE=$(if $(filter 1,$(DEBUG)),Debug,Release) -DBUILD_EXAMPLES=ON -DCMAKE_INSTALL_PREFIX=$(PREFIX)

.PHONY: cmake-build
cmake-build:
	@echo -e "${BLUE}Building C library...${NC}"
	@cmake --build $(BUILD_DIR) $(if $(filter 1,$(VERBOSE)),--verbose,)

# Rust library targets
.PHONY: rust-lib
rust-lib:
	@echo -e "${BLUE}Building Rust library...${NC}"
	@$(CARGO) build $(if $(filter 0,$(DEBUG)),--release,)

# Example targets
.PHONY: examples
examples: c-examples rust-examples

.PHONY: c-examples
c-examples: c-lib
	@echo -e "${BLUE}Building C examples...${NC}"
	@cmake --build $(BUILD_DIR) --target examples

.PHONY: rust-examples
rust-examples:
	@echo -e "${BLUE}Building and running Rust examples...${NC}"
	@$(CARGO) run --example basic $(if $(filter 0,$(DEBUG)),--release,)

# Testing targets
.PHONY: tests
tests: test-c test-rust

.PHONY: test-c
test-c: c-lib
	@echo -e "${BLUE}Running C tests...${NC}"
	@cd $(BUILD_DIR) && ctest $(if $(filter 1,$(VERBOSE)),-V,)

.PHONY: test-rust
test-rust:
	@echo -e "${BLUE}Running Rust tests...${NC}"
	@$(CARGO) test $(if $(filter 0,$(DEBUG)),--release,)

# Benchmark targets
.PHONY: bench
bench:
	@echo -e "${BLUE}Running benchmarks...${NC}"
	@$(CARGO) bench

# Documentation targets
.PHONY: docs
docs:
ifeq ($(BUILD_DOCS), 1)
	@echo -e "${BLUE}Building documentation...${NC}"
	@$(CARGO) doc --no-deps
	@echo -e "${GREEN}Documentation built in target/doc/bitcoinpqc/index.html${NC}"
else
	@echo -e "${YELLOW}Skipping documentation build (use BUILD_DOCS=1 to enable)${NC}"
endif

# Language bindings
.PHONY: python
python: rust-lib
	@echo -e "${BLUE}Building Python bindings...${NC}"
	@if [ -n "$(PYTHON)" ]; then \
		echo -e "${YELLOW}Creating a Python virtual environment...${NC}"; \
		$(PYTHON) -m venv python/.venv || { echo -e "${RED}Failed to create virtual environment${NC}"; exit 1; }; \
		echo -e "${GREEN}Virtual environment created at python/.venv${NC}"; \
		echo -e "${YELLOW}Installing Python bindings in virtual environment...${NC}"; \
		. python/.venv/bin/activate && cd python && $(PYTHON) -m pip install -e . && \
		echo -e "${GREEN}Python bindings installed successfully in virtual environment${NC}"; \
		echo -e "${YELLOW}To use the bindings, activate the virtual environment:${NC}"; \
		echo -e "  source python/.venv/bin/activate"; \
	else \
		echo -e "${RED}Python not found, skipping Python bindings${NC}"; \
	fi

.PHONY: nodejs
nodejs: rust-lib
	@echo -e "${BLUE}Building NodeJS bindings...${NC}"
	@if [ -n "$(NPM)" ]; then \
		cd nodejs && $(NPM) install && $(NPM) run build; \
	else \
		echo -e "${RED}NPM not found, skipping NodeJS bindings${NC}"; \
	fi

# Installation targets
.PHONY: install
install: install-c install-rust

.PHONY: install-c
install-c: c-lib
	@echo -e "${BLUE}Installing C library to $(PREFIX)...${NC}"
	@cd $(BUILD_DIR) && cmake --install .

.PHONY: install-rust
install-rust: rust-lib
	@echo -e "${BLUE}Installing Rust library...${NC}"
	@$(CARGO) install --path .

# Clean targets
.PHONY: clean
clean: clean-c clean-rust clean-bindings

.PHONY: clean-c
clean-c:
	@echo -e "${BLUE}Cleaning C library build files...${NC}"
	@rm -rf $(BUILD_DIR)

.PHONY: clean-rust
clean-rust:
	@echo -e "${BLUE}Cleaning Rust library build files...${NC}"
	@$(CARGO) clean

.PHONY: clean-bindings
clean-bindings:
	@echo -e "${BLUE}Cleaning language bindings...${NC}"
	@if [ -d "python/build" ]; then rm -rf python/build; fi
	@if [ -d "nodejs/dist" ]; then rm -rf nodejs/dist; fi

# Help target
.PHONY: help
help:
	@echo -e "${BLUE}libbitcoinpqc Makefile Help${NC}"
	@echo -e "${BLUE}-------------------------${NC}"
	@echo -e "Main targets:"
	@echo -e "  ${GREEN}all${NC}             - Build C and Rust libraries and language bindings (default)"
	@echo -e "  ${GREEN}bindings${NC}        - Build Python and NodeJS bindings"
	@echo -e "  ${GREEN}everything${NC}      - Build all components including examples and tests"
	@echo -e "  ${GREEN}c-lib${NC}           - Build only the C library"
	@echo -e "  ${GREEN}rust-lib${NC}        - Build only the Rust library"
	@echo -e "  ${GREEN}python${NC}          - Build Python bindings"
	@echo -e "  ${GREEN}nodejs${NC}          - Build NodeJS bindings"
	@echo -e "  ${GREEN}examples${NC}        - Build example programs"
	@echo -e "  ${GREEN}tests${NC}           - Run all tests"
	@echo -e "  ${GREEN}bench${NC}           - Run benchmarks"
	@echo -e "  ${GREEN}docs${NC}            - Build documentation"
	@echo -e "  ${GREEN}install${NC}         - Install libraries"
	@echo -e "  ${GREEN}clean${NC}           - Clean all build files"
	@echo -e "  ${GREEN}help${NC}            - Display this help message"
	@echo -e "  ${GREEN}fix-warnings${NC}    - Fix common build warnings"
	@echo -e "  ${GREEN}troubleshoot${NC}    - Display troubleshooting information"
	@echo -e ""
	@echo -e "Developer targets:"
	@echo -e "  ${GREEN}dev${NC}             - Run format, lint, and analyze"
	@echo -e "  ${GREEN}format${NC}          - Format C and Rust code"
	@echo -e "  ${GREEN}lint${NC}            - Lint C and Rust code"
	@echo -e "  ${GREEN}analyze${NC}         - Run static analysis on C code"
	@echo -e "  ${GREEN}dev-deps${NC}        - Install development dependencies"
	@echo -e ""
	@echo -e "Configuration options:"
	@echo -e "  ${YELLOW}DEBUG=1${NC}          - Build in debug mode (default: 0)"
	@echo -e "  ${YELLOW}VERBOSE=1${NC}        - Show verbose build output (default: 0)"
	@echo -e "  ${YELLOW}PREFIX=/path${NC}     - Installation prefix (default: /usr/local)"
	@echo -e "  ${YELLOW}BUILD_DOCS=1${NC}     - Build documentation (default: 0)"
	@echo -e "  ${YELLOW}NO_COLOR=1${NC}       - Disable colored output (default: 0)"

# Fix warnings targets
.PHONY: fix-warnings
fix-warnings:
	@echo -e "${BLUE}Fixing CRYPTO_ALGNAME redefinition warnings...${NC}"
	@echo -e "${YELLOW}This functionality has been removed.${NC}"
	@echo -e "${GREEN}Please edit CMakeLists.txt manually if needed.${NC}"

# Troubleshooting information
.PHONY: troubleshoot
troubleshoot:
	@echo -e "${BLUE}libbitcoinpqc Troubleshooting${NC}"
	@echo -e "${BLUE}---------------------------${NC}"
	@echo -e "Common issues and solutions:"
	@echo -e ""
	@echo -e "  ${YELLOW}CRYPTO_ALGNAME redefinition warnings:${NC}"
	@echo -e "    These are harmless but can be fixed by editing CMakeLists.txt manually"
	@echo -e "    Change CRYPTO_ALGNAME to CRYPTO_ALGNAME_SPHINCS in the target_compile_definitions"
	@echo -e ""
	@echo -e "  ${YELLOW}Example compilation errors:${NC}"
	@echo -e "    If examples don't compile, ensure you're using the latest code."
	@echo -e "    Run: make clean && make"
	@echo -e ""
	@echo -e "  ${YELLOW}Missing tools:${NC}"
	@echo -e "    Make sure you have all required development tools installed."
	@echo -e ""
	@echo -e "  ${YELLOW}Python or NodeJS bindings issues:${NC}"
	@echo -e "    If you experience Python or NodeJS binding problems:"
	@echo -e "    - For Python: Check the virtual environment at python/.venv"
	@echo -e "    - For NodeJS: Check the build logs in nodejs/build"
	@echo -e "    You can build bindings separately with 'make python' or 'make nodejs'"
	@echo -e ""
	@echo -e "  ${YELLOW}Terminal color issues:${NC}"
	@echo -e "    If you see raw escape sequences (like \\033[0;32m), run with NO_COLOR=1"
	@echo -e ""
	@echo -e "  ${YELLOW}For more detailed help:${NC}"
	@echo -e "    Check the README.md or open an issue on GitHub."

# Developer tools
.PHONY: dev
dev: format lint analyze

.PHONY: format
format:
	@echo -e "${BLUE}Formatting code...${NC}"
	@if command -v clang-format > /dev/null; then \
		find src include examples -name "*.c" -o -name "*.h" | xargs clang-format -i -style=file; \
		echo -e "${GREEN}C/C++ code formatted${NC}"; \
	else \
		echo -e "${YELLOW}clang-format not found, skipping C/C++ formatting${NC}"; \
	fi
	@if [ -n "$(CARGO)" ]; then \
		$(CARGO) fmt; \
		echo -e "${GREEN}Rust code formatted${NC}"; \
	else \
		echo -e "${YELLOW}Cargo not found, skipping Rust formatting${NC}"; \
	fi

.PHONY: lint
lint:
	@echo -e "${BLUE}Linting code...${NC}"
	@if command -v cppcheck > /dev/null; then \
		cppcheck --enable=all --suppressions-list=.cppcheck-suppressions --error-exitcode=0 src include examples; \
		echo -e "${GREEN}C/C++ code linted${NC}"; \
	else \
		echo -e "${YELLOW}cppcheck not found, skipping C/C++ linting${NC}"; \
	fi
	@if [ -n "$(CARGO)" ]; then \
		$(CARGO) clippy; \
		echo -e "${GREEN}Rust code linted${NC}"; \
	else \
		echo -e "${YELLOW}Cargo not found, skipping Rust linting${NC}"; \
	fi

.PHONY: analyze
analyze:
	@echo -e "${BLUE}Analyzing code...${NC}"
	@if command -v scan-build > /dev/null; then \
		scan-build -o analysis-reports cmake --build $(BUILD_DIR); \
		echo -e "${GREEN}Static analysis completed. See analysis-reports directory for results.${NC}"; \
	else \
		echo -e "${YELLOW}scan-build not found, skipping static analysis${NC}"; \
	fi

.PHONY: dev-deps
dev-deps:
	@echo -e "${BLUE}Installing development dependencies...${NC}"
	@if command -v apt-get > /dev/null; then \
		sudo apt-get update && sudo apt-get install -y clang-format cppcheck clang-tools llvm; \
	elif command -v dnf > /dev/null; then \
		sudo dnf install -y clang-tools-extra cppcheck; \
	elif command -v pacman > /dev/null; then \
		sudo pacman -S --needed clang cppcheck; \
	elif command -v brew > /dev/null; then \
		brew install llvm cppcheck; \
	else \
		echo -e "${YELLOW}Could not detect package manager, please install manually:${NC}"; \
		echo "- clang-format (for code formatting)"; \
		echo "- cppcheck (for static analysis)"; \
		echo "- clang tools (for static analysis)"; \
	fi
	@if [ -n "$(CARGO)" ]; then \
		rustup component add clippy rustfmt; \
		echo -e "${GREEN}Rust development tools installed${NC}"; \
	fi
