.PHONY: all compile clean check test compliance cover doc binopt fuzz bench bench-compare

# Tools
REBAR3 := rebar3
ERLC := erlc

# Paths
INCLUDE := include

#==============================================================================
# Core targets
#==============================================================================

all: compile

compile:
	$(REBAR3) compile

clean:
	$(REBAR3) clean

check:
	$(REBAR3) check

test:
	$(REBAR3) test

compliance:
	$(REBAR3) ct --dir test/compliance

cover:
	$(REBAR3) ct --cover
	$(REBAR3) cover --verbose
	@echo ""
	@echo "Quality gate: Coverage must be >= 85%"

doc:
	$(REBAR3) ex_doc

#==============================================================================
# Fuzzing
#==============================================================================

# Long seeded campaign over the four wire-facing parsers. Override with
# make fuzz ITERATIONS=200000 SEED=42
ITERATIONS ?= 50000
SEED ?= $(shell date +%s)

fuzz:
	@echo "fuzz campaign: seed=$(SEED) iterations=$(ITERATIONS) per target"
	NHTTP_FUZZ_SEED=$(SEED) NHTTP_FUZZ_ITERATIONS=$(ITERATIONS) \
		$(REBAR3) ct --dir test/fuzz --suite nhttp_fuzz_SUITE --group campaign

#==============================================================================
# Benchmarks
#==============================================================================

# Cost per call for every wire-facing entry point: reductions, heap words,
# binary octets, microseconds. Compare two trees with
# make bench-compare BENCH_BASE=../nhttp_lib-base
BENCH_LABEL ?= head
BENCH_BASE ?=

bench:
	@bench/run.sh run $(CURDIR) $(BENCH_LABEL)

bench-compare:
	@test -n "$(BENCH_BASE)" || { echo "set BENCH_BASE to a second compiled tree"; exit 2; }
	@bench/run.sh compare $(BENCH_BASE) base $(CURDIR) $(BENCH_LABEL)

#==============================================================================
# Binary optimization analysis
#==============================================================================

binopt:
	@for f in src/*.erl; do \
		$(ERLC) +bin_opt_info -I $(INCLUDE) -o /tmp "$$f" 2>&1 | grep -E "^src/" | grep -v "OPTIMIZED: match context reused"; \
	done
	@rm -f /tmp/nhttp*.beam

#==============================================================================
# Help
#==============================================================================

help:
	@echo "nhttp_lib Makefile targets:"
	@echo ""
	@echo "  Core:"
	@echo "    make              - Build the project"
	@echo "    make compile      - Build the project"
	@echo "    make clean        - Clean build artifacts"
	@echo "    make check        - Run fmt check, xref, dialyzer, hank"
	@echo "    make test         - Run all tests (CT + PropEr)"
	@echo "    make compliance   - Run RFC compliance suites (test/compliance/)"
	@echo "    make cover        - Run tests with coverage (>= 85% required)"
	@echo "    make doc          - Generate ex_doc documentation"
	@echo ""
	@echo "  Quality gates (must pass after every phase):"
	@echo "    - All checks pass (make check)"
	@echo "    - Coverage >= 85% (make cover)"
	@echo ""
	@echo "  Analysis:"
	@echo "    make binopt       - Analyze binary optimization opportunities"
	@echo "    make bench        - Cost per call for every wire-facing entry point"
	@echo "    make bench-compare BENCH_BASE=<tree> - Delta against a second tree"
	@echo ""
	@echo "  Fuzzing:"
	@echo "    make fuzz         - Long seeded campaign (ITERATIONS=, SEED=)"
	@echo ""
