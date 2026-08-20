CC ?= cc
AR ?= ar
CFLAGS ?= -O2 -g -Wall -Wextra -Werror -std=c11
CPPFLAGS += -Icfg/include
CPPFLAGS += -Iformat -Ilat/include $(shell pkg-config --cflags glib-2.0)
LDLIBS += $(shell pkg-config --libs glib-2.0)

BUILD := build
CFG_SRC := \
	cfg/src/common.c \
	cfg/src/elf_image.c \
	cfg/src/function_symbols.c \
	cfg/src/ijmp_resolve.c \
	cfg/src/cfg_decoder.c \
	cfg/src/cfg_program.c
CFG_OBJ := $(CFG_SRC:%.c=$(BUILD)/%.o)
FORMAT_OBJ := $(BUILD)/format/bundle.o

.PHONY: all clean test test-native test-aot-native test-spec-analyze test-spec-gzip test-spec-gzip-aot check-import

all: $(BUILD)/latc $(BUILD)/liblatc_cfg.a

$(BUILD)/liblatc_cfg.a: $(CFG_OBJ)
	$(AR) rcs $@ $^

$(BUILD)/latc: $(BUILD)/compiler/latc.o $(BUILD)/compiler/profile.o $(FORMAT_OBJ) $(BUILD)/liblatc_cfg.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILD)/tests/cfg-fixture: tests/cfg-fixture.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/test-cfg: tests/test-cfg.c $(BUILD)/liblatc_cfg.a
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

test: all $(BUILD)/tests/cfg-fixture $(BUILD)/tests/test-cfg
	$(BUILD)/tests/test-cfg $(BUILD)/tests/cfg-fixture
	$(BUILD)/latc analyze $(BUILD)/tests/cfg-fixture
	$(BUILD)/latc compile $(BUILD)/tests/cfg-fixture -o $(BUILD)/tests/cfg-bundle --runner $(BUILD)/tests/cfg-fixture
	$(BUILD)/latc inspect --json $(BUILD)/tests/cfg-bundle
	sh tests/test-profile.sh $(BUILD)/latc $(BUILD)/tests/cfg-fixture \
	  tests/cfg-fixture.profile $(BUILD)/tests/cfg-profile-bundle
	sh tests/test-aot-bundle.sh $(BUILD)/latc $(BUILD)/tests/cfg-fixture \
	  tests/fake.aot2 $(BUILD)/tests/cfg-aot-bundle
	sh tests/test-bundle-corruption.sh $(BUILD)/latc $(BUILD)/tests/cfg-bundle $(BUILD)/tests/cfg-bundle.bad
	sh tests/test-spec-tools.sh $(BUILD)/tests/spec-tools
	$(MAKE) check-import

test-native: all
	@test -n "$(RUNNER)" -a -n "$(X86_GUEST)" || \
	  { echo "usage: make test-native RUNNER=/path/to/runner X86_GUEST=/path/to/static-x86"; exit 2; }
	sh tests/test-bundle-runner.sh $(BUILD)/latc $(RUNNER) $(X86_GUEST) $(BUILD)/native-test

test-aot-native: all
	@test -n "$(RUNNER)" -a -n "$(X86_GUEST)" || \
	  { echo "usage: make test-aot-native RUNNER=/path/to/runner X86_GUEST=/path/to/static-x86"; exit 2; }
	sh tests/test-aot-native.sh $(BUILD)/latc $(RUNNER) $(X86_GUEST) $(BUILD)/aot-native-test

test-spec-analyze: all
	@test -n "$(SPECINT_BINDIR)" || \
	  { echo "usage: make test-spec-analyze SPECINT_BINDIR=/path/to/specbin"; exit 2; }
	python3 spec2000/analyze-specint.py --latc $(BUILD)/latc \
	  --bindir $(SPECINT_BINDIR) --output $(BUILD)/specint2000-analysis.json

test-spec-gzip: all
	@test -n "$(RUNNER)" -a -n "$(SPEC_GZIP)" -a -n "$(SPEC_GZIP_INPUT)" \
	  -a -n "$(SPEC_GZIP_EXPECTED)" || { echo "usage: make test-spec-gzip RUNNER=... SPEC_GZIP=... SPEC_GZIP_INPUT=... SPEC_GZIP_EXPECTED=..."; exit 2; }
	sh spec2000/test-gzip.sh $(BUILD)/latc $(RUNNER) $(SPEC_GZIP) \
	  $(SPEC_GZIP_INPUT) $(SPEC_GZIP_EXPECTED) $(BUILD)/spec-gzip

test-spec-gzip-aot: all
	@test -n "$(RUNNER)" -a -n "$(SPEC_GZIP)" -a -n "$(SPEC_GZIP_INPUT)" \
	  -a -n "$(SPEC_GZIP_EXPECTED)" || { echo "usage: make test-spec-gzip-aot RUNNER=... SPEC_GZIP=... SPEC_GZIP_INPUT=... SPEC_GZIP_EXPECTED=..."; exit 2; }
	sh spec2000/test-gzip-aot.sh $(BUILD)/latc $(RUNNER) $(SPEC_GZIP) \
	  $(SPEC_GZIP_INPUT) $(SPEC_GZIP_EXPECTED) $(BUILD)/spec-gzip-aot

check-import:
	python3 scripts/check-import.py

clean:
	rm -rf $(BUILD)

-include $(CFG_OBJ:.o=.d) $(BUILD)/compiler/latc.d \
	$(BUILD)/compiler/profile.d $(BUILD)/format/bundle.d
