CC ?= cc
X86_CC ?= $(CC)
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

.PHONY: all clean test test-native test-native-shell test-native-long-tb \
	test-aot-native test-spec-analyze test-spec-gzip test-spec-gzip-aot \
	test-spec-gzip-native check-import

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

$(BUILD)/tests/x86-exit-add42: tests/x86-exit-add42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-exit-loop42: tests/x86-exit-loop42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-exit-memory42: tests/x86-exit-memory42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-exit-call42: tests/x86-exit-call42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-write-exit42: tests/x86-write-exit42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-stack-exit42: tests/x86-stack-exit42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-brk-exit42: tests/x86-brk-exit42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-mmap-exit42: tests/x86-mmap-exit42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-file-exit42: tests/x86-file-exit42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-open-error42: tests/x86-open-error42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-c-exit42: tests/x86-c-start.S tests/x86-c-exit42.c
	@mkdir -p $(dir $@)
	$(CC) -O2 -fno-stack-protector -nostdlib -static -no-pie \
	  -Wl,--build-id=none -o $@ $^

$(BUILD)/tests/x86-indirect-call42: tests/x86-indirect-call42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-runtime-indirect-call42: tests/x86-runtime-indirect-call42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-helper-state42: tests/x86-helper-state42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-ifunc-like42: tests/x86-ifunc-like42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-auxv42: tests/x86-auxv42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-addr32-call42: tests/x86-addr32-call42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-tls42: tests/x86-tls-start.S tests/x86-tls42.c
	@mkdir -p $(dir $@)
	$(CC) -O2 -fno-stack-protector -fno-tree-vectorize \
	  -fno-tree-loop-distribute-patterns -nostdlib -static -no-pie \
	  -Wl,--build-id=none -o $@ $^

$(BUILD)/tests/x86-prlimit42: tests/x86-prlimit42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-getrandom42: tests/x86-getrandom42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-readlinkat42: tests/x86-readlinkat42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-readlink42: tests/x86-readlink42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-newfstatat42: tests/x86-newfstatat42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-mprotect42: tests/x86-mprotect42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-fstat42: tests/x86-fstat42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-entry-regs42: tests/x86-entry-regs42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-long-tb-exit42: tests/x86-long-tb-exit42.S
	@mkdir -p $(dir $@)
	$(X86_CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-exit-group42: tests/x86-exit-group42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-argv-env42: tests/x86-argv-env42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-static-hello: tests/x86-static-hello.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-glibc-hello: tests/x86-glibc-hello.c
	@mkdir -p $(dir $@)
	$(CC) -O2 -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/test-cfg: tests/test-cfg.c $(BUILD)/liblatc_cfg.a
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

test: all $(BUILD)/tests/cfg-fixture $(BUILD)/tests/test-cfg \
	$(BUILD)/tests/test-fallback-loader $(BUILD)/tests/test-native-format \
	$(BUILD)/tests/test-native-relocate $(BUILD)/tests/test-native-dispatch \
	$(BUILD)/tests/x86-exit42 $(BUILD)/tests/x86-exit-add42 \
	$(BUILD)/tests/x86-exit-loop42 $(BUILD)/tests/x86-exit-memory42 \
	$(BUILD)/tests/x86-exit-call42 $(BUILD)/tests/x86-write-exit42 \
	$(BUILD)/tests/x86-stack-exit42 $(BUILD)/tests/x86-brk-exit42 \
	$(BUILD)/tests/x86-mmap-exit42 $(BUILD)/tests/x86-file-exit42 \
	$(BUILD)/tests/x86-open-error42 $(BUILD)/tests/x86-c-exit42 \
	$(BUILD)/tests/x86-indirect-call42 \
	$(BUILD)/tests/x86-runtime-indirect-call42 \
	$(BUILD)/tests/x86-helper-state42 \
	$(BUILD)/tests/x86-ifunc-like42 \
	$(BUILD)/tests/x86-auxv42 \
	$(BUILD)/tests/x86-addr32-call42 \
	$(BUILD)/tests/x86-tls42 \
	$(BUILD)/tests/x86-prlimit42 \
	$(BUILD)/tests/x86-getrandom42 \
	$(BUILD)/tests/x86-readlink42 \
	$(BUILD)/tests/x86-newfstatat42 \
	$(BUILD)/tests/x86-readlinkat42 \
	$(BUILD)/tests/x86-mprotect42 \
	$(BUILD)/tests/x86-fstat42 \
	$(BUILD)/tests/x86-entry-regs42 \
	$(BUILD)/tests/x86-long-tb-exit42 \
	$(BUILD)/tests/x86-exit-group42 \
	$(BUILD)/tests/x86-argv-env42 \
	$(BUILD)/tests/x86-static-hello $(BUILD)/tests/x86-glibc-hello
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
	sh -n scripts/compile-native-elf.sh scripts/compile-native-image.sh \
	  scripts/link-native-shell.sh
	$(BUILD)/tests/test-fallback-loader \
	  $(abspath $(BUILD)/tests/liblat-good.so) \
	  $(abspath $(BUILD)/tests/liblat-bad.so)
	$(BUILD)/tests/test-native-format $(BUILD)/tests/native-image
	$(BUILD)/tests/test-native-relocate
	$(BUILD)/tests/test-native-dispatch
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-exit42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] == 2'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-exit-add42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] == 2'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-exit-loop42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 4'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-exit-memory42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] == 2'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-exit-call42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 2; assert d["tbs"] >= 4'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-write-exit42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 3'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-stack-exit42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 6'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-brk-exit42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 6'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-mmap-exit42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 5'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-file-exit42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 10'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-open-error42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 4'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-c-exit42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] >= 3; assert d["tbs"] >= 7'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-indirect-call42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 2; assert d["tbs"] >= 4; assert d["open_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-runtime-indirect-call42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] >= 3; assert d["tbs"] >= 10; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-helper-state42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 15; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-ifunc-like42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] >= 3; assert d["tbs"] >= 8; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-auxv42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 20; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-addr32-call42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 2; assert d["tbs"] >= 8; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-tls42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] >= 2; assert d["tbs"] >= 20; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-prlimit42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 5; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-getrandom42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 5; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-readlink42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 6; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-newfstatat42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 6; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-readlinkat42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 6; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-mprotect42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 9; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-fstat42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 7; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-entry-regs42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 17; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-long-tb-exit42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 3; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-exit-group42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 1; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-argv-env42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 15; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-static-hello | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] >= 3; assert d["error_functions"] == 0'
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-glibc-hello | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] >= 1000; assert d["tbs"] >= 30000; assert d["error_functions"] == 0'
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
		native/runtime/relocate.c native/runtime/runtime-symbols.c \
		native/runtime/x86-linux-user.c \
		native/runtime/dispatch.c
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

test-native: all
	@test -n "$(RUNNER)" -a -n "$(X86_GUEST)" || \
	  { echo "usage: make test-native RUNNER=/path/to/runner X86_GUEST=/path/to/static-x86"; exit 2; }
	sh tests/test-bundle-runner.sh $(BUILD)/latc $(RUNNER) $(X86_GUEST) $(BUILD)/native-test

test-native-shell: all $(BUILD)/tests/test-native-format \
		$(BUILD)/tests/make-native-smoke \
		$(BUILD)/tests/make-native-state-smoke \
		$(BUILD)/tests/make-native-dispatch-smoke
	$(BUILD)/tests/test-native-format $(BUILD)/tests/native-image
	$(BUILD)/latc mark-native-x86 $(BUILD)/tests/native-image
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

test-native-long-tb: all $(BUILD)/tests/x86-long-tb-exit42
	@test -n "$(RUNNER)" || \
	  { echo "usage: make test-native-long-tb RUNNER=/path/to/runner"; exit 2; }
	sh tests/test-native-long-tb.sh $(BUILD)/latc $(RUNNER) \
	  $(BUILD)/tests/x86-long-tb-exit42 $(BUILD)/native-long-tb

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

test-spec-gzip-native: all
	@test -n "$(RUNNER)" -a -n "$(SPEC_GZIP)" -a -n "$(SPEC_GZIP_INPUT)" \
	  -a -n "$(SPEC_GZIP_SIZE)" -a -n "$(SPEC_GZIP_EXPECTED)" || \
	  { echo "usage: make test-spec-gzip-native RUNNER=... SPEC_GZIP=... SPEC_GZIP_INPUT=... SPEC_GZIP_SIZE=... SPEC_GZIP_EXPECTED=..."; exit 2; }
	sh spec2000/test-gzip-native.sh $(BUILD)/latc $(RUNNER) $(SPEC_GZIP) \
	  $(SPEC_GZIP_INPUT) $(SPEC_GZIP_SIZE) $(SPEC_GZIP_EXPECTED) \
	  $(BUILD)/spec-gzip-native

check-import:
	python3 scripts/check-import.py

clean:
	rm -rf $(BUILD)

-include $(CFG_OBJ:.o=.d) $(BUILD)/compiler/latc.d \
	$(BUILD)/compiler/profile.d $(BUILD)/format/bundle.d
