# libbitcoinpqc fuzz harness — local pre-merge smoke check
#
# Mirrors the recipe in .github/workflows/libbitcoinpqc-fuzz.yml so the
# same checks can be run locally before merging. Targets pin the same
# Rust nightly and cargo-fuzz version the workflow pins, so
# `make fuzz-smoke` locally mirrors the versioned workflow recipe.
#
# Usage from this directory:
#
#   make help          - show available targets and pinned versions
#   make fuzz-smoke    - full smoke check (matches CI workflow recipe)
#   make fuzz-build    - cargo +nightly fuzz build only
#
# Requirements (one-time setup):
#
#   - rustup           - install via https://rustup.rs/
#   - The pinned nightly + cargo-fuzz, both installable via:
#         make fuzz-toolchain
#
# Linux developers: `make fuzz-deps-linux` installs the apt packages the
# CI workflow installs (cmake, clang, libclang-dev, libssl-dev,
# pkg-config, build-essential).
#
# macOS developers: cmake + clang via your normal build environment
# (already present if you build the BTX node) is sufficient.

RUST_NIGHTLY        ?= nightly-2026-05-01
CARGO_FUZZ_VERSION  ?= 0.13.1
SMOKE_TIME          ?= 1

# Same target list and order as the workflow's smoke loop in
# .github/workflows/libbitcoinpqc-fuzz.yml. Keep these in sync.
SMOKE_TARGETS := keypair_generation key_parsing signature_parsing \
                 sign_verify cross_algorithm determinism \
                 sig_substitution structured_parsing

CORPUS_SEED_DIR  := corpus/verify_robustness
CORPUS_SEED_FILE := $(CORPUS_SEED_DIR)/secp_smoke

.PHONY: help fuzz-smoke fuzz-build fuzz-corpus-seed \
        fuzz-toolchain fuzz-deps-linux fuzz-clean

help:
	@echo "libbitcoinpqc fuzz harness — make targets"
	@echo ""
	@echo "  make fuzz-smoke         Full pre-merge smoke check (matches CI workflow)"
	@echo "  make fuzz-build         cargo +nightly fuzz build only"
	@echo "  make fuzz-corpus-seed   Generate deterministic verify_robustness seed"
	@echo "  make fuzz-toolchain     Install pinned nightly + cargo-fuzz"
	@echo "  make fuzz-deps-linux    Install Linux system deps (apt)"
	@echo "  make fuzz-clean         Clean fuzz build artifacts and generated seed"
	@echo ""
	@echo "Pinned versions (override via 'make TARGET RUST_NIGHTLY=...' etc.):"
	@echo "  RUST_NIGHTLY        = $(RUST_NIGHTLY)"
	@echo "  CARGO_FUZZ_VERSION  = $(CARGO_FUZZ_VERSION)"
	@echo "  SMOKE_TIME          = $(SMOKE_TIME) (seconds per target)"
	@echo "  SMOKE_TARGETS       = $(SMOKE_TARGETS)"

fuzz-toolchain:
	rustup toolchain install $(RUST_NIGHTLY) --profile minimal
	cargo +$(RUST_NIGHTLY) install cargo-fuzz --locked --version $(CARGO_FUZZ_VERSION)

fuzz-deps-linux:
	sudo apt-get update
	sudo apt-get install -y \
	    build-essential \
	    clang \
	    cmake \
	    libclang-dev \
	    libssl-dev \
	    pkg-config

fuzz-build:
	cargo +$(RUST_NIGHTLY) fuzz build

# Algorithm 0 => SECP256K1_SCHNORR. The first 32 seed bytes are the
# secret key material, so they must be non-zero. The rest provides
# enough garbage to hit all three verify_robustness scenarios
# deterministically. Same construction as the workflow's
# "Prepare deterministic smoke inputs" step. Keep in sync.
$(CORPUS_SEED_FILE):
	mkdir -p $(CORPUS_SEED_DIR)
	@python3 -c "import pathlib; pathlib.Path('$@').write_bytes(bytes([0]) + (b'\\x01'*32) + (b'\\x00'*96) + (b'\\x00'*32) + (b'\\x02'*96))"
	@echo "wrote $(CORPUS_SEED_FILE) ($$(wc -c < $@ | tr -d ' ') bytes)"

fuzz-corpus-seed: $(CORPUS_SEED_FILE)

fuzz-smoke: fuzz-build fuzz-corpus-seed
	@echo ""
	@echo "===== smoke verify_robustness seeded invariant ====="
	cargo +$(RUST_NIGHTLY) fuzz run verify_robustness $(CORPUS_SEED_FILE)
	@echo ""
	@set -e; for tgt in $(SMOKE_TARGETS); do \
	    echo "===== smoke $$tgt ($(SMOKE_TIME)s) ====="; \
	    cargo +$(RUST_NIGHTLY) fuzz run $$tgt -- -max_total_time=$(SMOKE_TIME); \
	done
	@echo ""
	@echo "✓ fuzz-smoke complete — mirrors CI workflow recipe"

fuzz-clean:
	rm -rf target
	rm -f $(CORPUS_SEED_FILE)
	rmdir $(CORPUS_SEED_DIR) 2>/dev/null || true
