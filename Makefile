CARGO ?= cargo
# Dependencies are fetched once (`cargo fetch --locked`); every target below
# then runs without network access.
export CARGO_NET_OFFLINE ?= true

FINAL := results/final
DEV := results/dev
VERIFY := target/verify-final

.PHONY: all build fmt fmt-check lint unit-test integration-test test check \
        dev final verify quick clean

all: check

build:
	$(CARGO) build --locked --release

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt --check

lint:
	$(CARGO) clippy --locked --all-targets -- -D warnings

unit-test:
	$(CARGO) test --locked --lib

integration-test:
	$(CARGO) test --locked --test '*'

test: unit-test integration-test

# Everything CI runs.
check: fmt-check lint build test

# Quick look at one development seed. Not a protocol run.
quick:
	$(CARGO) run --locked --release --quiet -- run --seed 1

# Development run: threshold table on the development seeds only.
dev:
	$(CARGO) run --locked --release --quiet -- dev --out $(DEV)
	cd $(DEV) && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS

# The frozen held-out evaluation and the exploratory sweeps: every table and
# figure under results/final, plus checksums.
final:
	$(CARGO) run --locked --release --quiet -- final --out $(FINAL)
	cd $(FINAL) && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS

# Rerun the final evaluation into a clean directory and compare it, byte for
# byte, with the committed results.
verify:
	rm -rf $(VERIFY)
	$(CARGO) run --locked --release --quiet -- final --out $(VERIFY) > /dev/null
	cd $(VERIFY) && sha256sum --check --quiet ../../$(FINAL)/SHA256SUMS
	@echo "verified: a clean rerun reproduces $(FINAL) exactly"

clean:
	$(CARGO) clean
