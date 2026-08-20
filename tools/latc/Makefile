CC ?= cc
AR ?= ar
CFLAGS ?= -O2 -g -Wall -Wextra -Werror -std=c11
CPPFLAGS += -Icfg/include
CPPFLAGS += -Iformat -Ilat/include -Inative/include -Inative/format \
	-Inative/runtime \
	$(shell pkg-config --cflags glib-2.0)
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

.PHONY: all clean test test-native test-native-shell test-aot-native test-spec-analyze test-spec-gzip test-spec-gzip-aot check-import

all: $(BUILD)/latc $(BUILD)/liblatc_cfg.a

$(BUILD)/liblatc_cfg.a: $(CFG_OBJ)
	$(AR) rcs $@ $^

$(BUILD)/latc: $(BUILD)/compiler/latc.o $(BUILD)/compiler/profile.o \
	$(FORMAT_OBJ) $(BUILD)/native/format/native-image.o $(BUILD)/liblatc_cfg.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILD)/tests/cfg-fixture: tests/cfg-fixture.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-exit42: tests/x86-exit42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/test-cfg: tests/test-cfg.c $(BUILD)/liblatc_cfg.a
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

test: all $(BUILD)/tests/cfg-fixture $(BUILD)/tests/test-cfg \
	$(BUILD)/tests/test-fallback-loader $(BUILD)/tests/test-native-format \
	$(BUILD)/tests/test-native-relocate $(BUILD)/tests/test-native-dispatch \
	$(BUILD)/tests/x86-exit42
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
	$(BUILD)/tests/test-fallback-loader \
	  $(abspath $(BUILD)/tests/liblat-good.so) \
	  $(abspath $(BUILD)/tests/liblat-bad.so)
	$(BUILD)/tests/test-native-format $(BUILD)/tests/native-image
	$(BUILD)/tests/test-native-relocate
	$(BUILD)/tests/test-native-dispatch
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-exit42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] == 2'
	$(BUILD)/latc inspect-native --json $(BUILD)/tests/native-image | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["execution_model"] == "lat-native-image"; assert d["tbs"] == 1; assert d["relocations"] == 1'
	$(MAKE) check-import

$(BUILD)/tests/liblat-good.so: tests/fake-liblat.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -shared \
	  -DLAT_FAKE_BUILD_ID='"test-build"' -o $@ $<

$(BUILD)/tests/liblat-bad.so: tests/fake-liblat.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -shared \
	  -DLAT_FAKE_BUILD_ID='"other-build"' -o $@ $<

$(BUILD)/tests/test-fallback-loader: tests/test-fallback-loader.c \
		$(BUILD)/native/runtime/fallback-loader.o \
		$(BUILD)/tests/liblat-good.so $(BUILD)/tests/liblat-bad.so
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ \
	  tests/test-fallback-loader.c \
	  $(BUILD)/native/runtime/fallback-loader.o -ldl

$(BUILD)/tests/test-native-format: tests/test-native-format.c \
		$(BUILD)/native/format/native-image.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

$(BUILD)/tests/test-native-relocate: tests/test-native-relocate.c \
		native/runtime/relocate.c native/runtime/runtime-symbols.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

$(BUILD)/tests/test-native-dispatch: tests/test-native-dispatch.c \
		native/runtime/dispatch.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

$(BUILD)/tests/make-native-smoke: tests/make-native-smoke.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

$(BUILD)/tests/make-native-state-smoke: tests/make-native-state-smoke.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

$(BUILD)/tests/make-native-dispatch-smoke: tests/make-native-dispatch-smoke.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

$(BUILD)/tests/mark-native-exit-smoke: tests/mark-native-exit-smoke.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

test-native: all
	@test -n "$(RUNNER)" -a -n "$(X86_GUEST)" || \
	  { echo "usage: make test-native RUNNER=/path/to/runner X86_GUEST=/path/to/static-x86"; exit 2; }
	sh tests/test-bundle-runner.sh $(BUILD)/latc $(RUNNER) $(X86_GUEST) $(BUILD)/native-test

test-native-shell: all $(BUILD)/tests/test-native-format \
		$(BUILD)/tests/make-native-smoke \
		$(BUILD)/tests/make-native-state-smoke \
		$(BUILD)/tests/make-native-dispatch-smoke \
		$(BUILD)/tests/mark-native-exit-smoke
	$(BUILD)/tests/test-native-format $(BUILD)/tests/native-image
	cp $(BUILD)/tests/native-image $(BUILD)/tests/not-exit-smoke-image
	! $(BUILD)/tests/mark-native-exit-smoke \
	  $(BUILD)/tests/not-exit-smoke-image
	scripts/link-native-shell.sh $(BUILD)/tests/native-image \
	  $(BUILD)/tests/native-shell.la64
	loongarch64-unknown-linux-gnu-readelf -h $(BUILD)/tests/native-shell.la64 | \
	  grep -q 'DYN (Position-Independent Executable file)'
	loongarch64-unknown-linux-gnu-readelf -S $(BUILD)/tests/native-shell.la64 | \
	  grep -q '.latc.image'
	! loongarch64-unknown-linux-gnu-readelf -d $(BUILD)/tests/native-shell.la64 | \
	  grep -q 'liblat.so.1'
	$(BUILD)/tests/make-native-smoke $(BUILD)/tests/native-smoke-image
	scripts/link-native-shell.sh $(BUILD)/tests/native-smoke-image \
	  $(BUILD)/tests/native-smoke.la64
	loongarch64-unknown-linux-gnu-readelf -h $(BUILD)/tests/native-smoke.la64 | \
	  grep -q 'DYN (Position-Independent Executable file)'
	$(BUILD)/tests/make-native-state-smoke \
	  $(BUILD)/tests/native-state-smoke-image
	scripts/link-native-shell.sh $(BUILD)/tests/native-state-smoke-image \
	  $(BUILD)/tests/native-state-smoke.la64
	$(BUILD)/tests/make-native-dispatch-smoke \
	  $(BUILD)/tests/native-dispatch-smoke-image
	scripts/link-native-shell.sh $(BUILD)/tests/native-dispatch-smoke-image \
	  $(BUILD)/tests/native-dispatch-smoke.la64

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
