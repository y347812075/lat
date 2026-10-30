CC ?= cc
X86_CC ?= $(CC)
AR ?= ar
HOST_ARCH := $(shell uname -m)
AOT_V2_BUILD_ID := $(shell python3 scripts/compute-aot-v2-build-id.py ../..)
CFLAGS ?= -O2 -g -Wall -Wextra -Werror -std=c11
FUZZ_CC ?= clang
CPPFLAGS += -Icfg/include -I../../include
CPPFLAGS += -DLATC_BUILD_ID=\"$(AOT_V2_BUILD_ID)\"
CPPFLAGS += -Iformat -Ilat/include -Inative/include -Inative/format \
	-Inative/runtime -Iaot-v2/include -Iaot-v2/runtime \
	-Iaot-v2/compiler -Iaot-v2/common \
	$(shell pkg-config --cflags glib-2.0)
LDLIBS += $(shell pkg-config --libs glib-2.0)

CAPSTONE_DIR := ../../target/i386/latx/capstone_git
CPPFLAGS += -I$(CAPSTONE_DIR)/include
CAPSTONE_SRC := cs.c MCInst.c MCInstrDesc.c MCRegisterInfo.c MCInstPrinter.c \
	Mapping.c SStream.c utils.c arch/X86/X86Disassembler.c \
	arch/X86/X86DisassemblerDecoder.c arch/X86/X86InstPrinterCommon.c \
	arch/X86/X86ATTInstPrinter.c arch/X86/X86IntelInstPrinter.c \
	arch/X86/X86Mapping.c arch/X86/X86Module.c

BUILD := build
CFG_SRC := \
	cfg/src/common.c \
	cfg/src/elf_image.c \
	cfg/src/function_symbols.c \
	cfg/src/ijmp_resolve.c \
	cfg/src/cfg_decoder.c \
	cfg/src/cfg_return_proof.c \
	cfg/src/cfg_program.c
CFG_OBJ := $(CFG_SRC:%.c=$(BUILD)/%.o)
CAPSTONE_OBJ := $(CAPSTONE_SRC:%.c=$(BUILD)/capstone/%.o)
FORMAT_OBJ := $(BUILD)/format/bundle.o

.PHONY: all clean test test-native test-native-shell test-native-long-tb \
	 test-native-config-replay test-native-tu-config test-native-config-plan test-native-constants \
	 test-native-tu-extract \
	test-aot-native test-spec-analyze test-spec-gzip test-spec-gzip-aot \
		test-spec-gzip-native test-specint-native test-aot-v2 \
		test-specint-aot-v2 \
		test-aot-v2-translated test-aot-v2-pie test-aot-v2-runner \
		test-aot-v2-glibc-runner test-aot-v2-signal-runner \
		test-aot-v2-dynamic-runner test-aot-v2-dlopen-runner \
		test-aot-v2-dynamic-semantics test-aot-v2-invalidation \
		test-aot-v2-fork test-latcd-once \
		test-latcd-service test-latcd-runner test-aot-v2-real-app test-aot-v2-m4 \
		test-aot-v2-complex-apps test-aot-v2-complex-performance \
		test-aot-v2-sanitize test-aot-v2-tsan test-aot-v2-libfuzzer \
		test-aot-v2-source-sync test-prepare-runner-source \
		test-aot-v2-build-id \
		test-aot-v2-install \
		sync-aot-v2-sources check-import


all: $(BUILD)/latc $(BUILD)/latcd/latcd $(BUILD)/liblatc_cfg.a

$(BUILD)/tests/test-cache-export: tests/test-cache-export.c latcd/cache-export.c latcd/cache-export.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test-cache-export.c latcd/cache-export.c $(LDLIBS)

.PHONY: test-cache-export
test-cache-export: $(BUILD)/tests/test-cache-export
	$(BUILD)/tests/test-cache-export
test: test-cache-export

$(BUILD)/tests/test-broker-transport: tests/test-broker-transport.c latcd/broker-transport.c latcd/broker-transport.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test-broker-transport.c latcd/broker-transport.c
.PHONY: test-broker-transport
test-broker-transport: $(BUILD)/tests/test-broker-transport
	$(BUILD)/tests/test-broker-transport
test: test-broker-transport

$(BUILD)/tests/test-broker-source: tests/test-broker-source.c latcd/broker-source.c latcd/source-elf.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)
.PHONY: test-broker-source
test-broker-source: $(BUILD)/tests/test-broker-source $(BUILD)/tests/x86-exit42
	$(BUILD)/tests/test-broker-source $(BUILD)/tests/x86-exit42
test: test-broker-source

test-native-config-replay:
	@test -n "$(INSTALL_PREFIX)" -a -n "$(X86_GUEST)" -a -n "$(TBSET)" -a -n "$(WORK)" || \
	  { echo "usage: make test-native-config-replay INSTALL_PREFIX=... X86_GUEST=... TBSET=... WORK=..."; exit 2; }
	python3 tests/test-native-config-replay.py "$(INSTALL_PREFIX)" "$(X86_GUEST)" "$(TBSET)" "$(WORK)"

test-native-tu-config:
	@test -n "$(INSTALL_PREFIX)" -a -n "$(X86_GUEST)" -a -n "$(TBSET)" -a -n "$(WORK)" || \
	  { echo "usage: make test-native-tu-config INSTALL_PREFIX=... X86_GUEST=... TBSET=... WORK=..."; exit 2; }
	python3 tests/test-native-tu-config.py "$(INSTALL_PREFIX)" "$(X86_GUEST)" "$(TBSET)" "$(WORK)"

test-native-config-plan:
	@test -n "$(INSTALL_PREFIX)" -a -n "$(EXPORTS)" -a -n "$(EXPECTED)" -a -n "$(WORK)" || \
	  { echo "usage: make test-native-config-plan INSTALL_PREFIX=... EXPORTS=... EXPECTED=... WORK=..."; exit 2; }
	python3 tests/test-native-config-plan.py "$(INSTALL_PREFIX)/bin/latc" "$(EXPORTS)" "$(EXPECTED)" "$(WORK)"

test-native-tu-extract:
	@test -n "$(INSTALL_PREFIX)" -a -n "$(EXPORTS)" -a -n "$(PLANS)" -a -n "$(WORK)"
	python3 tests/test-native-tu-extract.py "$(INSTALL_PREFIX)/bin/latc" "$(EXPORTS)" "$(PLANS)" "$(WORK)"

$(BUILD)/liblatc_cfg.a: $(CFG_OBJ) $(CAPSTONE_OBJ)
	$(AR) rcs $@ $^

$(BUILD)/capstone/%.o: $(CAPSTONE_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) -O2 -g -std=gnu99 -w -DCAPSTONE_HAS_X86 \
	  -DCAPSTONE_USE_SYS_DYN_MEM -I$(CAPSTONE_DIR)/include \
	  -MMD -MP -c -o $@ $<

$(BUILD)/latc: $(BUILD)/compiler/latc.o $(BUILD)/compiler/tbset.o $(BUILD)/compiler/tbplan.o \
		$(BUILD)/aot-v2/common/tb-key-set.o \
		$(BUILD)/aot-v2/compiler/module-pack.o \
		$(BUILD)/aot-v2/compiler/module-inspect.o \
		$(BUILD)/aot-v2/runtime/elf-validate.o \
		$(BUILD)/aot-v2/common/translation-config.o \
		$(FORMAT_OBJ) $(BUILD)/native/format/native-image.o \
		$(BUILD)/native/format/native-tu-plan.o \
		$(BUILD)/native/format/native-tu-audit.o $(BUILD)/liblatc_cfg.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/latcd/latcd: $(BUILD)/latcd/main.o $(BUILD)/latcd/protocol.o \
		$(BUILD)/latcd/precompile.o \
		$(BUILD)/latcd/journal-store.o $(BUILD)/aot-v2/common/key-journal.o \
		$(BUILD)/aot-v2/common/translation-config.o \
		$(BUILD)/aot-v2/common/tb-key-set.o \
		$(BUILD)/aot-v2/runtime/cache-domain.o \
		$(BUILD)/aot-v2/runtime/cache-lifecycle.o \
		$(BUILD)/aot-v2/runtime/internal-fd-registry.o \
		$(BUILD)/aot-v2/compiler/module-inspect.o \
		$(BUILD)/aot-v2/runtime/elf-validate.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS) -pthread -ldl

$(BUILD)/tests/latcd-gc-timer-main.o: latcd/main.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DLATCD_GC_TIMER_TEST -MMD -MP -c -o $@ $<

$(BUILD)/tests/latcd-gc-timer: $(BUILD)/tests/latcd-gc-timer-main.o $(BUILD)/latcd/protocol.o \
	$(BUILD)/latcd/precompile.o $(BUILD)/latcd/journal-store.o $(BUILD)/latcd/cache-retirement.o \
	$(BUILD)/latcd/cache-capacity.o $(BUILD)/latcd/parson/parson.o $(BUILD)/latcd/source-elf.o \
	$(BUILD)/latcd/cache-export.o $(BUILD)/aot-v2/common/key-journal.o \
	$(BUILD)/aot-v2/common/translation-config.o $(BUILD)/aot-v2/common/tb-key-set.o \
	$(BUILD)/aot-v2/runtime/cache-domain.o $(BUILD)/aot-v2/runtime/cache-lifecycle.o \
	$(BUILD)/aot-v2/runtime/internal-fd-registry.o $(BUILD)/aot-v2/compiler/module-inspect.o \
	$(BUILD)/aot-v2/runtime/elf-validate.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS) -pthread -ldl

.PHONY: test-latcd-gc-timer
$(BUILD)/tests/gc-timer-runtime/liblat-aot-runtime.so.2: tests/gc-timer-runtime.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -shared -o $@ $<
$(BUILD)/tests/gc-timer-runtime/liblat-aot-runtime.so.2 $(BUILD)/tests/test-cache-retirement: latcd/main.c
test-latcd-gc-timer: all $(BUILD)/tests/latcd-gc-timer $(BUILD)/tests/test-cache-retirement $(BUILD)/tests/gc-timer-runtime/liblat-aot-runtime.so.2
	@work=$$(mktemp -d "$(TMPDIR)/latcd-gc-timer.XXXXXX"); \
	  trap 'if ! findmnt -rn -o TARGET | grep -F "$$work" >/dev/null && ! lsof +D "$$work" >/dev/null 2>&1; then rm -rf "$$work"; else echo "retained busy test directory: $$work" >&2; fi' EXIT; \
	  sh tests/test-latcd-gc-timer.sh "$(abspath $(BUILD)/tests/latcd-gc-timer)" \
	    "$(abspath $(BUILD)/tests/test-cache-retirement)" "$(abspath $(BUILD)/tests/test-cache-retirement)" \
	    "$(abspath $(BUILD)/tests/test-cache-retirement)" "$$work" "$(abspath $(BUILD)/tests/gc-timer-runtime)"
test: test-latcd-gc-timer

# Integration requires a matching configured installation and an x86 guest
# built from tests/x86-cache-retirement.S on the designated x86 toolchain.
.PHONY: test-latcd-gc-publication
test-latcd-gc-publication: $(BUILD)/tests/latcd-gc-timer
	@test -n "$(GC_INSTALL_PREFIX)" -a -n "$(GC_X86_GUEST)" -a -n "$(GC_TEST_WORK)"
	sh tests/test-latcd-gc-publication.sh "$(abspath $(BUILD)/tests/latcd-gc-timer)" \
	  "$(GC_INSTALL_PREFIX)/bin/latcd" "$(GC_INSTALL_PREFIX)/bin/latc" \
	  "$(GC_INSTALL_PREFIX)/bin/latx-x86_64" "$(GC_INSTALL_PREFIX)/lib" \
	  "$(GC_X86_GUEST)" "$(GC_TEST_WORK)"

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILD)/latcd/latcd $(BUILD)/tests/test-journal-store \
$(BUILD)/tests/test-latcd-channel $(BUILD)/tests/test-latcd-coverage: \
		$(BUILD)/latcd/cache-retirement.o $(BUILD)/latcd/cache-capacity.o \
		$(BUILD)/latcd/parson/parson.o \
		$(BUILD)/aot-v2/runtime/cache-domain.o

$(BUILD)/latcd/latcd $(BUILD)/tests/test-journal-store $(BUILD)/tests/test-latcd-channel $(BUILD)/tests/test-latcd-coverage: $(BUILD)/latcd/source-elf.o $(BUILD)/latcd/cache-export.o

$(BUILD)/tests/cache-capacity-testing.o: latcd/cache-capacity.c latcd/cache-capacity.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DLATCD_CAPACITY_TESTING -MMD -MP -c -o $@ $<

$(BUILD)/tests/test-cache-capacity: tests/test-cache-capacity.c $(BUILD)/tests/cache-capacity-testing.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DLATCD_CAPACITY_TESTING -o $@ $^ $(LDLIBS) -pthread -Wl,--wrap=unlinkat -Wl,--wrap=fsync

$(BUILD)/tests/test-capacity-watch-race: tests/test-capacity-watch-race.c latcd/cache-capacity.c latcd/cache-capacity.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDLIBS) -pthread

.PHONY: test-cache-capacity
test-cache-capacity: $(BUILD)/tests/test-cache-capacity $(BUILD)/tests/test-capacity-watch-race
	$(BUILD)/tests/test-cache-capacity
	$(BUILD)/tests/test-capacity-watch-race

test: test-cache-capacity

$(BUILD)/tests/cache-retirement-testing.o: latcd/cache-retirement.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DLATCD_RETIREMENT_TESTING -DLATCD_CAPACITY_TESTING -MMD -MP -c -o $@ $<

$(BUILD)/tests/test-cache-retirement: tests/test-cache-retirement.c \
		$(BUILD)/tests/cache-capacity-testing.o \
		$(BUILD)/tests/cache-retirement-testing.o $(BUILD)/latcd/parson/parson.o \
		$(BUILD)/aot-v2/runtime/cache-domain.o \
		$(BUILD)/aot-v2/runtime/cache-lifecycle.o \
		$(BUILD)/aot-v2/runtime/internal-fd-registry.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DLATCD_RETIREMENT_TESTING -DLATCD_CAPACITY_TESTING -o $@ $(filter-out latcd/main.c,$^) $(LDLIBS) -pthread \
  -Wl,--wrap=clock_gettime -Wl,--wrap=g_file_get_contents -Wl,--wrap=g_get_monotonic_time \
  -Wl,--wrap=lat_aot_v2_cache_source_lock -Wl,--wrap=lat_aot_v2_cache_lock_fd -Wl,--wrap=readdir -Wl,--wrap=lstat -Wl,--wrap=fstatat \
  -Wl,--wrap=unlinkat -Wl,--wrap=fsync

.PHONY: test-cache-retirement
test-cache-retirement: $(BUILD)/tests/test-cache-retirement
	$(BUILD)/tests/test-cache-retirement

test: test-cache-retirement

$(BUILD)/tests/cfg-fixture: tests/cfg-fixture.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-exit42: tests/x86-exit42.S
	@mkdir -p $(dir $@)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-cache-fd-close-sleep: tests/x86-cache-fd-close-sleep.S
	@mkdir -p $(dir $@)
	$(X86_CC) -nostdlib -static -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-bounded-pic: tests/x86-bounded-pic.S
	@mkdir -p $(dir $@)
	$(X86_CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-masked-pic: tests/x86-masked-pic.S
	@mkdir -p $(dir $@)
	$(X86_CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-pie-exit42: tests/x86-pie-exit42.S
	@mkdir -p $(dir $@)
	$(X86_CC) -nostdlib -pie -Wl,--no-dynamic-linker -Wl,--build-id=none \
	  -o $@ $<

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

$(BUILD)/tests/x86-aot-v2-invalidation: tests/x86-aot-v2-invalidation.c
	@mkdir -p $(dir $@)
	$(X86_CC) -O2 -g -Wall -Wextra -Werror -o $@ $< -ldl -pthread

$(BUILD)/tests/x86-aot-v2-fork: tests/x86-aot-v2-fork.c
	@mkdir -p $(dir $@)
	$(X86_CC) -O2 -g -Wall -Wextra -Werror -fPIE -pie \
	  -Wl,--build-id=none -o $@ $< -pthread

$(BUILD)/tests/x86-aot-v2-invalidation-plugin.so: \
		tests/x86-aot-v2-invalidation-plugin.S
	@mkdir -p $(dir $@)
	$(X86_CC) -nostdlib -shared -fPIC -Wl,-z,now -Wl,-z,relro \
	  -Wl,-e,latc_invalidation_entry \
	  -Wl,--build-id=sha1 -o $@ $<

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
	$(X86_CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-glibc-hello: tests/x86-glibc-hello.c
	@mkdir -p $(dir $@)
	$(X86_CC) -O2 -static -no-pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-signal-recover: tests/x86-signal-recover.c \
		tests/x86-signal-sites.S
	@mkdir -p $(dir $@)
	$(X86_CC) -O2 -static -no-pie -Wl,--build-id=none -o $@ $^

$(BUILD)/tests/x86-signal-recover.tbset: \
		$(BUILD)/tests/x86-signal-recover
	python3 tests/make-symbol-tbset.py $< \
	  'signal_.*_(site|fault|resume)' $@

$(BUILD)/tests/x86-dynamic-hello: tests/x86-glibc-hello.c
	@mkdir -p $(dir $@)
	$(X86_CC) -O2 -fPIE -pie -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-dlopen-plugin.so: tests/x86-dlopen-plugin.c \
		tests/x86-dlopen-signal.S
	@mkdir -p $(dir $@)
	$(X86_CC) -O2 -fPIC -shared -Wl,-e,latc_plugin_entry \
	  -Wl,--build-id=none -o $@ $^

$(BUILD)/tests/x86-dlopen-main: tests/x86-dlopen-main.c
	@mkdir -p $(dir $@)
	$(X86_CC) -O2 -fPIE -pie -Wl,--build-id=none -o $@ $< -ldl -pthread

$(BUILD)/tests/x86-semantics-startup.so: tests/x86-semantics-startup.c
	@mkdir -p $(dir $@)
	$(X86_CC) -O2 -fPIC -shared -Wl,-e,semantic_startup_entry \
	  -Wl,-soname,liblatc-semantics-startup.so -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-semantics-plugin.so: tests/x86-semantics-plugin.c \
		tests/x86-semantics-plugin.map
	@mkdir -p $(dir $@)
	$(X86_CC) -O2 -fPIC -shared -Wl,-e,semantic_plugin_entry \
	  -Wl,--version-script=tests/x86-semantics-plugin.map \
	  -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-semantics-preload.so: tests/x86-semantics-preload.c
	@mkdir -p $(dir $@)
	$(X86_CC) -O2 -fPIC -shared -Wl,-e,semantic_preload_entry \
	  -Wl,--build-id=none -o $@ $<

$(BUILD)/tests/x86-semantics-main: tests/x86-semantics-main.c \
		$(BUILD)/tests/x86-semantics-startup.so
	@mkdir -p $(dir $@)
	$(X86_CC) -O2 -fPIE -pie -rdynamic -Wl,--build-id=none \
	  -L$(BUILD)/tests -Wl,-rpath,/tmp \
	  -o $@ $< $(BUILD)/tests/x86-semantics-startup.so -ldl

$(BUILD)/tests/test-cfg: tests/test-cfg.c $(BUILD)/liblatc_cfg.a
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

test: all $(BUILD)/tests/cfg-fixture $(BUILD)/tests/test-cfg \
	$(BUILD)/tests/test-native-constants \
$(BUILD)/tests/test-native-migration-v12 \
	$(BUILD)/tests/test-native-tu-plan \
	$(BUILD)/tests/test-native-tu-extract \
	$(BUILD)/tests/test-native-tu-audit \
	$(BUILD)/tests/test-translation-config \
	$(BUILD)/tests/test-fallback-loader $(BUILD)/tests/test-native-format \
	$(BUILD)/tests/test-native-relocate $(BUILD)/tests/test-native-dispatch \
	$(BUILD)/tests/test-aot-recover-tu \
	$(BUILD)/tests/test-auto-config \
	$(BUILD)/tests/test-aot-v2-module-pack \
	$(BUILD)/tests/test-latcd-protocol \
	$(BUILD)/tests/test-latcd-client \
	$(BUILD)/tests/test-precompile \
	$(BUILD)/tests/test-aot-v2-guest-elf-map \
	$(BUILD)/tests/test-x86-linux-user \
	$(BUILD)/tests/x86-exit42 $(BUILD)/tests/x86-pie-exit42 \
	$(BUILD)/tests/x86-exit-add42 \
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
	sh tests/test-tbset.sh $(BUILD)/latc $(BUILD)/tests/cfg-fixture \
	  $(BUILD)/tests/cfg-tbset-bundle
	sh tests/test-aot-bundle.sh $(BUILD)/latc $(BUILD)/tests/cfg-fixture \
	  tests/fake.aot2 $(BUILD)/tests/cfg-aot-bundle
	sh tests/test-bundle-corruption.sh $(BUILD)/latc $(BUILD)/tests/cfg-bundle $(BUILD)/tests/cfg-bundle.bad
	sh tests/test-spec-tools.sh $(BUILD)/tests/spec-tools
	sh -n scripts/compile-native-elf.sh scripts/compile-native-image.sh \
	  scripts/link-native-shell.sh scripts/link-aot-v2-module.sh \
	  scripts/compile-aot-v2-module.sh scripts/build-aot-v2-runner.sh \
	  tests/test-aot-v2-runner.sh tests/test-aot-v2-glibc-runner.sh \
	  tests/test-aot-v2-signal-runner.sh tests/test-aot-v2-pie.sh \
	  tests/test-aot-v2-dynamic-runner.sh tests/test-aot-v2-dlopen-runner.sh \
	  tests/test-aot-v2-dynamic-semantics.sh \
	  tests/test-aot-v2-invalidation.sh tests/test-latcd-once.sh \
	  tests/test-aot-v2-fork.sh \
	  tests/test-aot-v2-cfi-entry.sh \
	  tests/fake-latc-invalid-module.sh tests/fake-latc-fail.sh \
	  tests/test-latcd-service.sh \
	  tests/fake-latc-slow.sh tests/fake-latc-cpu.sh \
	  tests/test-latcd-runner.sh tests/test-aot-v2-real-app.sh \
	  tests/test-aot-v2-complex-apps.sh tests/test-compile-native-one-pass.sh \
	  tests/test-compile-aot-native-direct.sh \
	  tests/test-old-aot-tu-replay-space.sh \
	  scripts/prepare-complex-rootfs.sh
	sh tests/test-compile-aot-native-direct.sh scripts/compile-aot.sh
	sh tests/test-compile-native-one-pass.sh scripts/compile-native-image.sh
	python3 tests/test-native-batching.py $(BUILD)/latc \
	  scripts/compile-native-image.sh
	python3 tests/test-check-aot-v2-coverage.py \
	  tests/check-aot-v2-coverage.py
	$(BUILD)/tests/test-fallback-loader \
	  $(abspath $(BUILD)/tests/liblat-good.so) \
	  $(abspath $(BUILD)/tests/liblat-bad.so)
	$(BUILD)/tests/test-native-format $(BUILD)/tests/native-image
	$(BUILD)/tests/test-native-format $(BUILD)/tests/base.native \
	  $(BUILD)/tests/delta.native $(BUILD)/tests/merged.native
	$(BUILD)/tests/test-native-relocate
	$(BUILD)/tests/test-native-migration-v12
	$(BUILD)/tests/test-native-tu-plan
	$(BUILD)/tests/test-native-tu-extract
	$(BUILD)/tests/test-native-tu-audit
	$(BUILD)/tests/test-native-constants $(BUILD)/tests/constant-base.native \
	  $(BUILD)/tests/constant-delta.native $(BUILD)/tests/constant-merged.native
	$(BUILD)/tests/test-native-dispatch
	$(BUILD)/tests/test-aot-recover-tu
	tests/test-old-aot-tu-replay-space.sh
	$(BUILD)/tests/test-aot-v2-module-pack
	$(BUILD)/tests/test-module-coverage $(abspath $(BUILD)/latc)
	$(BUILD)/tests/test-tb-key-set
	$(BUILD)/tests/test-key-journal
	$(BUILD)/tests/test-guest-fd-table
	$(BUILD)/tests/test-cache-lifecycle
	$(BUILD)/tests/test-journal-store
	$(BUILD)/tests/test-latcd-coverage
	$(BUILD)/tests/test-latcd-channel
	python3 tests/test-cache-gc-plan.py $(BUILD)/latcd/latcd
	python3 tests/test-cache-object-hold.py $(BUILD)/latcd/latcd
	$(BUILD)/tests/test-tbset-selection $(BUILD)/tests/cfg-fixture
	$(BUILD)/tests/test-tb-closure
	python3 tests/test-tbplan.py $(BUILD)/latc $(BUILD)/tests/cfg-fixture
	$(BUILD)/tests/test-static-capability $(BUILD)/tests/cfg-fixture
	$(BUILD)/tests/test-gpr-writes
	$(BUILD)/tests/test-gpr-constants
	$(BUILD)/tests/test-return-proof
	$(BUILD)/tests/test-bounded-pic
	$(BUILD)/tests/test-cfi-entry
	@if test -n "$(SPLIT_CFI_GUEST)"; then \
	  python3 tests/test-split-cfi-static.py $(BUILD)/latc "$(SPLIT_CFI_GUEST)"; \
	fi
	$(BUILD)/tests/test-elf-pointer
	@if test -n "$(CFI_ENTRY_GUEST)"; then \
	  python3 tests/test-cfi-static.py $(BUILD)/latc "$(CFI_ENTRY_GUEST)"; \
	fi
	@if test -n "$(MASKED_PIC_GUEST)"; then \
	  python3 tests/test-masked-pic-static.py $(BUILD)/latc \
	    "$(MASKED_PIC_GUEST)" $(BUILD)/tests/masked-pic.tbset; \
	fi
	@if test -n "$(BOUNDED_PIC_GUEST)"; then \
	  $(BUILD)/tests/test-tbset-selection $(BUILD)/tests/cfg-fixture \
	    "$(BOUNDED_PIC_GUEST)"; \
	fi
	$(BUILD)/tests/test-latcd-protocol
	$(BUILD)/tests/test-latcd-client
	mkdir -p "$${TMPDIR:-$$HOME/tmp}"
	TMPDIR="$${TMPDIR:-$$HOME/tmp}" $(BUILD)/tests/test-auto-config
	$(BUILD)/tests/test-precompile
	$(BUILD)/tests/test-translation-config
	$(BUILD)/tests/test-aot-v2-guest-elf-map \
	  $(BUILD)/tests/x86-pie-exit42 $(BUILD)/tests/x86-pie-exit42 \
	  $(BUILD)/tests/x86-exit42
	$(BUILD)/tests/test-x86-linux-user
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-exit42 | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["functions"] == 1; assert d["tbs"] == 2'
	LC_ALL=C readelf -h $(BUILD)/tests/x86-pie-exit42 | \
	  grep -Eq 'Type:.*DYN'
	! LC_ALL=C readelf -lW $(BUILD)/tests/x86-pie-exit42 | grep -q INTERP
	$(BUILD)/latc analyze --json $(BUILD)/tests/x86-pie-exit42 | \
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
	python3 spec2000/analyze-native-relocations.py \
	  $(BUILD)/tests/native-image | \
	  python3 -c 'import json,sys; d=json.load(sys.stdin)[0]; assert d["tb_count"] == 1; assert d["relocation_count"] == 1; assert d["pc_map_count"] == 0'
	$(MAKE) test-aot-v2
	$(MAKE) test-aot-v2-source-sync
	$(MAKE) test-prepare-runner-source
	python3 tests/test-tcg-jit-regions.py
	python3 tests/test-aot-v2-submission-signals.py
	python3 tests/test-native-search-data.py
	python3 tests/test-native-tu-relocations.py
	python3 tests/test-native-constant-export.py
	python3 tests/test-fwait-constant-emitter.py
	python3 tests/test-ir2-provenance.py
	python3 tests/test-final-provenance.py
	python3 tests/test-aot-metadata-buffer.py
	python3 tests/test-terminal-trap.py
	python3 tests/test-module-selection-environment.py scripts/compile-aot-v2-module.sh
	python3 tests/test-module-runtime-prefix.py
	$(MAKE) check-import

$(BUILD)/tests/test-latcd-protocol: \
		aot-v2/tests/test-latcd-protocol.c $(BUILD)/latcd/protocol.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

test: $(BUILD)/tests/test-module-coverage

test: $(BUILD)/tests/test-tb-key-set

test: $(BUILD)/tests/test-key-journal
test: $(BUILD)/tests/test-journal-store
test: $(BUILD)/tests/test-guest-fd-table
test: $(BUILD)/tests/test-cache-lifecycle

$(BUILD)/tests/test-cache-lifecycle: tests/test-cache-lifecycle.c \
		aot-v2/runtime/cache-lifecycle.c aot-v2/runtime/cache-lifecycle.h \
		aot-v2/runtime/internal-fd-registry.c \
		aot-v2/runtime/internal-fd-registry.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test-cache-lifecycle.c \
	  aot-v2/runtime/cache-lifecycle.c aot-v2/runtime/internal-fd-registry.c -pthread \
	  -Wl,--wrap=close -Wl,--wrap=pthread_cond_wait -Wl,--wrap=flock

$(BUILD)/tests/test-guest-fd-table: tests/test-guest-fd-table.c \
		aot-v2/common/guest-fd-table.c aot-v2/include/guest-fd-table.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ \
	  tests/test-guest-fd-table.c aot-v2/common/guest-fd-table.c \
	  $(LDLIBS) -pthread -Wl,--wrap=close -Wl,--wrap=fcntl \
	  -Wl,--wrap=pthread_mutex_lock -Wl,--wrap=g_try_malloc

$(BUILD)/tests/test-journal-store: aot-v2/tests/test-journal-store.c latcd/main.c \
		$(BUILD)/aot-v2/runtime/latcd-client.o \
		$(BUILD)/latcd/journal-store.o $(BUILD)/aot-v2/common/key-journal.o \
		$(BUILD)/aot-v2/common/translation-config.o $(BUILD)/latcd/protocol.o \
		$(BUILD)/latcd/precompile.o $(BUILD)/aot-v2/compiler/module-inspect.o \
		$(BUILD)/aot-v2/runtime/elf-validate.o $(BUILD)/aot-v2/common/tb-key-set.o \
		$(BUILD)/aot-v2/runtime/cache-lifecycle.o \
		$(BUILD)/aot-v2/runtime/internal-fd-registry.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ aot-v2/tests/test-journal-store.c \
	  $(filter %.o,$^) $(LDLIBS) -pthread -ldl

$(BUILD)/tests/test-key-journal: aot-v2/tests/test-key-journal.c \
		aot-v2/common/key-journal.c aot-v2/include/lat-key-journal.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ \
	  aot-v2/tests/test-key-journal.c aot-v2/common/key-journal.c -pthread

$(BUILD)/tests/test-tb-key-set: aot-v2/tests/test-tb-key-set.c \
		$(BUILD)/aot-v2/common/tb-key-set.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

test: $(BUILD)/tests/test-latcd-coverage
test: $(BUILD)/tests/test-latcd-channel

$(BUILD)/tests/test-latcd-channel: aot-v2/tests/test-latcd-channel.c \
		aot-v2/runtime/latcd-client.c $(BUILD)/latcd/protocol.o \
		$(BUILD)/latcd/precompile.o $(BUILD)/aot-v2/compiler/module-inspect.o \
		$(BUILD)/aot-v2/runtime/elf-validate.o \
		$(BUILD)/aot-v2/common/tb-key-set.o \
		$(BUILD)/aot-v2/runtime/cache-lifecycle.o \
		$(BUILD)/aot-v2/runtime/internal-fd-registry.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ \
	  aot-v2/tests/test-latcd-channel.c aot-v2/runtime/latcd-client.c \
	  $(filter %.o,$^) $(LDLIBS) -pthread -ldl

$(BUILD)/tests/test-latcd-channel: latcd/main.c

$(BUILD)/tests/test-latcd-channel $(BUILD)/tests/test-latcd-coverage: \
		$(BUILD)/latcd/journal-store.o $(BUILD)/aot-v2/common/key-journal.o \
		$(BUILD)/aot-v2/common/translation-config.o

test: $(BUILD)/tests/test-tbset-selection
test: $(BUILD)/tests/test-tb-closure
test: $(BUILD)/tests/test-static-capability
test: $(BUILD)/tests/test-gpr-writes
test: $(BUILD)/tests/test-gpr-constants
test: $(BUILD)/tests/test-return-proof

$(BUILD)/tests/test-return-proof: tests/test-return-proof.c $(BUILD)/liblatc_cfg.a
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-gpr-constants: tests/test-gpr-constants.c $(BUILD)/liblatc_cfg.a
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-gpr-writes: tests/test-gpr-writes.c $(BUILD)/liblatc_cfg.a
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-tb-closure: tests/test-tb-closure.c \
		$(BUILD)/compiler/tbset.o $(BUILD)/aot-v2/common/tb-key-set.o \
		$(BUILD)/liblatc_cfg.a
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -Icompiler -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-static-capability: tests/test-static-capability.c \
		$(BUILD)/compiler/tbset.o $(BUILD)/aot-v2/common/tb-key-set.o \
		$(BUILD)/liblatc_cfg.a
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -Icompiler -o $@ $^ $(LDLIBS)

test: $(BUILD)/tests/test-bounded-pic
test: $(BUILD)/tests/test-cfi-entry
test: $(BUILD)/tests/test-elf-pointer

$(BUILD)/tests/test-elf-pointer: tests/test-elf-pointer.c $(BUILD)/liblatc_cfg.a
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-cfi-entry: tests/test-cfi-entry.c $(BUILD)/liblatc_cfg.a
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-bounded-pic: tests/test-bounded-pic.c $(BUILD)/liblatc_cfg.a
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-tbset-selection: tests/test-tbset-selection.c \
		$(BUILD)/compiler/tbset.o $(BUILD)/aot-v2/common/tb-key-set.o \
		$(BUILD)/liblatc_cfg.a
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -Icompiler -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-latcd-coverage: aot-v2/tests/test-latcd-coverage.c \
		aot-v2/tests/elf-fixture.c $(BUILD)/latcd/protocol.o \
		$(BUILD)/latcd/precompile.o $(BUILD)/aot-v2/compiler/module-inspect.o \
		$(BUILD)/aot-v2/runtime/elf-validate.o \
		$(BUILD)/aot-v2/common/tb-key-set.o \
		$(BUILD)/aot-v2/runtime/cache-lifecycle.o \
		$(BUILD)/aot-v2/runtime/internal-fd-registry.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -Iaot-v2/tests -o $@ \
	  aot-v2/tests/test-latcd-coverage.c aot-v2/tests/elf-fixture.c \
	  $(filter %.o,$^) $(LDLIBS) -pthread -ldl

$(BUILD)/tests/test-latcd-coverage: latcd/main.c aot-v2/tests/test-module-coverage.c

$(BUILD)/tests/test-module-coverage: aot-v2/tests/test-module-coverage.c \
		aot-v2/tests/elf-fixture.c $(BUILD)/aot-v2/compiler/module-inspect.o \
		$(BUILD)/aot-v2/runtime/elf-validate.o \
		$(BUILD)/aot-v2/common/tb-key-set.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DMODULE_SNAPSHOT_TESTING -Iaot-v2/tests -o $@ $^ $(LDLIBS) -Wl,--wrap=pread

$(BUILD)/tests/test-aot-recover-tu: tests/test-aot-recover-tu.c \
		../../target/i386/latx/include/aot_recover_tu.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(abspath ../../target/i386/latx/include) \
	  -o $@ $<

$(BUILD)/tests/test-latcd-client: aot-v2/tests/test-latcd-client.c \
		aot-v2/runtime/latcd-client.c $(BUILD)/latcd/protocol.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

$(BUILD)/tests/test-precompile: tests/test-precompile.c \
		$(BUILD)/latcd/precompile.o $(BUILD)/latcd/protocol.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -Ilatcd -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-aot-v2-format: aot-v2/tests/test-format.c \
		$(BUILD)/aot-v2/runtime/elf-validate.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

$(BUILD)/tests/test-aot-v2-elf-mutate: \
		aot-v2/tests/test-elf-mutate.c aot-v2/tests/elf-fixture.c \
		$(BUILD)/aot-v2/runtime/elf-validate.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

$(BUILD)/tests/test-aot-v2-elf-mutate-sanitize: \
		aot-v2/tests/test-elf-mutate.c aot-v2/tests/elf-fixture.c \
		aot-v2/runtime/elf-validate.c
	@mkdir -p $(dir $@)
	$(FUZZ_CC) $(CPPFLAGS) $(CFLAGS) -O1 -fno-omit-frame-pointer \
	  -fsanitize=address,undefined -o $@ $^

$(BUILD)/tests/fuzz-aot-v2-elf: aot-v2/fuzz/fuzz-elf-validate.c \
		aot-v2/runtime/elf-validate.c
	@mkdir -p $(dir $@)
	$(FUZZ_CC) $(CPPFLAGS) $(CFLAGS) -O1 -fno-omit-frame-pointer \
	  -fsanitize=fuzzer,address,undefined -o $@ $^

test-aot-v2-sanitize: $(BUILD)/tests/test-aot-v2-elf-mutate-sanitize
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	  UBSAN_OPTIONS=halt_on_error=1 $<

test-aot-v2-libfuzzer: $(BUILD)/tests/fuzz-aot-v2-elf \
		$(BUILD)/tests/test-aot-v2-elf-mutate
	rm -rf $(BUILD)/tests/aot-v2-elf-corpus
	mkdir -p $(BUILD)/tests/aot-v2-elf-corpus
	$(BUILD)/tests/test-aot-v2-elf-mutate --write-seed \
	  $(BUILD)/tests/aot-v2-elf-corpus/valid-elf
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	  UBSAN_OPTIONS=halt_on_error=1 $(BUILD)/tests/fuzz-aot-v2-elf \
	  -runs=100000 -max_len=4096 $(BUILD)/tests/aot-v2-elf-corpus

$(BUILD)/tests/test-aot-v2-registry: aot-v2/tests/test-registry.c \
		$(BUILD)/aot-v2/runtime/registry.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ -pthread

$(BUILD)/tests/test-aot-v2-registry-tsan: aot-v2/tests/test-registry.c \
		aot-v2/runtime/registry.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -O1 -fno-omit-frame-pointer \
	  -fsanitize=thread -o $@ $^ -pthread

test-aot-v2-tsan: $(BUILD)/tests/test-aot-v2-registry-tsan
	TSAN_OPTIONS=halt_on_error=1 $<

ifeq ($(HOST_ARCH),loongarch64)
$(BUILD)/aot-v2/liblat-aot-runtime.so.2: aot-v2/runtime/runtime-abi.c \
		aot-v2/runtime/runtime-entry.S \
		aot-v2/runtime/runtime.map
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) -O2 -fPIC -shared -nostdlib \
	  -Wl,-soname,liblat-aot-runtime.so.2 \
	  -Wl,--version-script=aot-v2/runtime/runtime.map \
	  -Wl,--build-id=sha1 -o $@ aot-v2/runtime/runtime-abi.c \
	  aot-v2/runtime/runtime-entry.S

$(BUILD)/aot-v2/fixture.so: aot-v2/tests/fixture.c \
		aot-v2/tests/fixture-entry.S aot-v2/tests/module.map \
		$(BUILD)/aot-v2/liblat-aot-runtime.so.2
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) -O2 -fPIC -shared -nostdlib \
		  -Wl,-z,defs -Wl,-z,now -Wl,-z,relro \
		  -Wl,--unique=.text.lat.tu -Wl,--unique=.rodata.lat.tb \
		  -Wl,--unique=.rodata.lat.map \
		  -Wl,--unique=.data.rel.ro.lat.module \
	  -Wl,--version-script=aot-v2/tests/module.map \
	  -Wl,--build-id=sha1 \
	  -L$(BUILD)/aot-v2 -Wl,--no-as-needed \
	  -l:liblat-aot-runtime.so.2 -o $@ \
	  aot-v2/tests/fixture.c aot-v2/tests/fixture-entry.S
	chmod go-w $@

$(BUILD)/aot-v2/fixture-bad-descriptor.so: aot-v2/tests/fixture.c \
		aot-v2/tests/fixture-entry.S aot-v2/tests/module.map \
		$(BUILD)/aot-v2/liblat-aot-runtime.so.2
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) -O2 -fPIC -shared -nostdlib \
	  -DLAT_AOT_FIXTURE_DESCRIPTOR_SOURCE_BYTE=0x12 \
		  -Wl,-z,defs -Wl,-z,now -Wl,-z,relro \
		  -Wl,--unique=.text.lat.tu -Wl,--unique=.rodata.lat.tb \
		  -Wl,--unique=.rodata.lat.map \
		  -Wl,--unique=.data.rel.ro.lat.module \
	  -Wl,--version-script=aot-v2/tests/module.map \
	  -Wl,--build-id=sha1 \
	  -L$(BUILD)/aot-v2 -Wl,--no-as-needed \
	  -l:liblat-aot-runtime.so.2 -o $@ \
	  aot-v2/tests/fixture.c aot-v2/tests/fixture-entry.S
	chmod go-w $@

$(BUILD)/aot-v2/fixture-bad-pc-map.so: aot-v2/tests/fixture.c \
		aot-v2/tests/fixture-entry.S aot-v2/tests/module.map \
		$(BUILD)/aot-v2/liblat-aot-runtime.so.2
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) -O2 -fPIC -shared -nostdlib \
	  -DLAT_AOT_FIXTURE_BAD_PC_MAP=1 \
	  -Wl,-z,defs -Wl,-z,now -Wl,-z,relro \
	  -Wl,--unique=.text.lat.tu -Wl,--unique=.rodata.lat.tb \
	  -Wl,--unique=.rodata.lat.map \
	  -Wl,--unique=.data.rel.ro.lat.module \
	  -Wl,--version-script=aot-v2/tests/module.map \
	  -Wl,--build-id=sha1 \
	  -L$(BUILD)/aot-v2 -Wl,--no-as-needed \
	  -l:liblat-aot-runtime.so.2 -o $@ \
	  aot-v2/tests/fixture.c aot-v2/tests/fixture-entry.S
	chmod go-w $@

$(BUILD)/aot-v2/fixture-stack-delta.so: aot-v2/tests/fixture.c \
		aot-v2/tests/fixture-entry.S aot-v2/tests/module.map \
		$(BUILD)/aot-v2/liblat-aot-runtime.so.2
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) -O2 -fPIC -shared -nostdlib \
	  -DLAT_AOT_FIXTURE_STACK_DELTA=1 \
		  -Wl,-z,defs -Wl,-z,now -Wl,-z,relro \
		  -Wl,--unique=.rodata.lat.tb \
		  -Wl,--unique=.rodata.lat.map \
		  -Wl,--unique=.data.rel.ro.lat.module \
	  -Wl,--version-script=aot-v2/tests/module.map \
	  -Wl,--build-id=sha1 \
	  -L$(BUILD)/aot-v2 -Wl,--no-as-needed \
	  -l:liblat-aot-runtime.so.2 -o $@ \
	  aot-v2/tests/fixture.c aot-v2/tests/fixture-entry.S
	chmod go-w $@

$(BUILD)/tests/test-aot-v2-loader: aot-v2/tests/test-loader.c \
		$(BUILD)/aot-v2/runtime/module-loader.o \
		$(BUILD)/aot-v2/runtime/cache-lifecycle.o \
		$(BUILD)/aot-v2/runtime/internal-fd-registry.o \
		$(BUILD)/aot-v2/runtime/elf-validate.o \
		$(BUILD)/aot-v2/runtime/registry.o \
		$(BUILD)/aot-v2/liblat-aot-runtime.so.2
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ \
	  aot-v2/tests/test-loader.c \
	  $(BUILD)/aot-v2/runtime/module-loader.o \
	  $(BUILD)/aot-v2/runtime/cache-lifecycle.o \
	  $(BUILD)/aot-v2/runtime/internal-fd-registry.o \
	  $(BUILD)/aot-v2/runtime/elf-validate.o \
	  $(BUILD)/aot-v2/runtime/registry.o \
	  -L$(BUILD)/aot-v2 -Wl,--no-as-needed \
	  -l:liblat-aot-runtime.so.2 -ldl -pthread

$(BUILD)/tests/test-aot-v2-translated-module: \
		aot-v2/tests/test-translated-module.c \
		$(BUILD)/aot-v2/runtime/module-loader.o \
		$(BUILD)/aot-v2/runtime/cache-lifecycle.o \
		$(BUILD)/aot-v2/runtime/internal-fd-registry.o \
		$(BUILD)/aot-v2/runtime/elf-validate.o \
		$(BUILD)/aot-v2/runtime/registry.o \
		$(BUILD)/aot-v2/compiler/module-pack.o \
		$(BUILD)/native/format/native-image.o \
		$(BUILD)/aot-v2/common/translation-config.o \
		$(BUILD)/aot-v2/liblat-aot-runtime.so.2 \
		native/runtime/enter-x86.S native/runtime/guest-loader.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ \
	  aot-v2/tests/test-translated-module.c \
	  $(BUILD)/aot-v2/runtime/module-loader.o \
	  $(BUILD)/aot-v2/runtime/cache-lifecycle.o \
	  $(BUILD)/aot-v2/runtime/internal-fd-registry.o \
	  $(BUILD)/aot-v2/runtime/elf-validate.o \
	  $(BUILD)/aot-v2/runtime/registry.o \
	  $(BUILD)/aot-v2/compiler/module-pack.o \
	  $(BUILD)/native/format/native-image.o native/runtime/enter-x86.S \
	  $(BUILD)/aot-v2/common/translation-config.o \
	  native/runtime/guest-loader.c \
	  -L$(BUILD)/aot-v2 -Wl,--no-as-needed \
	  -l:liblat-aot-runtime.so.2 -ldl -pthread $(LDLIBS)

AOT_V2_NATIVE_TESTS := $(BUILD)/aot-v2/liblat-aot-runtime.so.2 \
	$(BUILD)/aot-v2/fixture.so \
	$(BUILD)/aot-v2/fixture-bad-descriptor.so \
	$(BUILD)/aot-v2/fixture-bad-pc-map.so \
	$(BUILD)/aot-v2/fixture-stack-delta.so \
	$(BUILD)/tests/test-aot-v2-loader
endif

test-aot-v2: $(BUILD)/tests/test-aot-v2-format \
		$(BUILD)/tests/test-aot-v2-elf-mutate \
		$(BUILD)/tests/test-aot-v2-registry $(AOT_V2_NATIVE_TESTS)
	$(BUILD)/tests/test-aot-v2-format
	$(BUILD)/tests/test-aot-v2-elf-mutate
	$(BUILD)/tests/test-aot-v2-registry
ifeq ($(HOST_ARCH),loongarch64)
	LC_ALL=C readelf -h $(BUILD)/aot-v2/fixture.so | grep -q 'DYN (Shared object file)'
	LC_ALL=C readelf -lW $(BUILD)/aot-v2/fixture.so | \
	  awk '/ LOAD / && $$0 ~ /W/ && $$0 ~ /E/ { bad=1 } END { exit bad }'
	LC_ALL=C readelf -d $(BUILD)/aot-v2/fixture.so | \
	  grep -q 'Shared library: \[liblat-aot-runtime.so.2\]'
	! LC_ALL=C readelf -d $(BUILD)/aot-v2/fixture.so | grep -Eq 'RPATH|RUNPATH'
	LC_ALL=C readelf --dyn-syms -W $(BUILD)/aot-v2/fixture.so | \
	  grep -q 'lat_aot_module_v2'
	LC_ALL=C readelf -SW $(BUILD)/aot-v2/fixture.so | grep -q '.note.lat.aot'
	LC_ALL=C readelf -SW $(BUILD)/aot-v2/fixture.so | grep -q '.rodata.lat.tb'
	LC_ALL=C readelf -SW $(BUILD)/aot-v2/fixture.so | grep -q '.rodata.lat.map'
	LC_ALL=C readelf -SW $(BUILD)/aot-v2/fixture.so | grep -q '.text.lat.tu'
	LC_ALL=C readelf -SW $(BUILD)/aot-v2/fixture.so | grep -q '.data.rel.ro.lat.module'
	LD_LIBRARY_PATH=$(abspath $(BUILD)/aot-v2) \
	  $(BUILD)/tests/test-aot-v2-loader \
	  $(abspath $(BUILD)/aot-v2/fixture.so)
	LD_LIBRARY_PATH=$(abspath $(BUILD)/aot-v2) \
	  $(BUILD)/tests/test-aot-v2-loader \
	  $(abspath $(BUILD)/aot-v2/fixture-stack-delta.so)
	LD_LIBRARY_PATH=$(abspath $(BUILD)/aot-v2) \
	  $(BUILD)/tests/test-aot-v2-loader --expect-reject \
	  $(abspath $(BUILD)/aot-v2/fixture-bad-descriptor.so)
	LD_LIBRARY_PATH=$(abspath $(BUILD)/aot-v2) \
	  $(BUILD)/tests/test-aot-v2-loader --expect-pc-map-reject \
	  $(abspath $(BUILD)/aot-v2/fixture-bad-pc-map.so)
endif

test-aot-v2-translated: all $(BUILD)/aot-v2/liblat-aot-runtime.so.2 \
		$(BUILD)/tests/test-aot-v2-translated-module
	@test -n "$(NATIVE_IMAGE)" || \
	  { echo "usage: make test-aot-v2-translated NATIVE_IMAGE=..."; exit 2; }
	scripts/link-aot-v2-module.sh $(BUILD)/latc $(NATIVE_IMAGE) \
	  $(BUILD)/aot-v2 $(BUILD)/aot-v2/translated-module.so
	LC_ALL=C readelf -lW $(BUILD)/aot-v2/translated-module.so | \
	  awk '/ LOAD / && $$0 ~ /W/ && $$0 ~ /E/ { bad=1 } END { exit bad }'
	LC_ALL=C readelf -rW $(BUILD)/aot-v2/translated-module.so | \
	  grep -q 'lat_aot_runtime_raise_syscall'
	LD_LIBRARY_PATH=$(abspath $(BUILD)/aot-v2) \
	  $(BUILD)/tests/test-aot-v2-translated-module \
	  $(abspath $(BUILD)/aot-v2/translated-module.so) \
	  $(abspath $(NATIVE_IMAGE)) $(AOT_V2_TRANSLATED_ARGS)

test-aot-v2-pie: all $(BUILD)/tests/test-aot-v2-translated-module
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)" \
	  -a -n "$(X86_GUEST)" || \
	  { echo "usage: make test-aot-v2-pie AOT_V2_RUNNER=... AOT_V2_RUNTIME_DIR=... X86_GUEST=..."; exit 2; }
	sh tests/test-aot-v2-pie.sh $(BUILD)/latc $(AOT_V2_RUNNER) \
	  $(AOT_V2_RUNTIME_DIR) $(X86_GUEST) \
	  $(BUILD)/tests/test-aot-v2-translated-module \
	  $(BUILD)/aot-v2-pie-test

test-aot-v2-runner: all
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)" \
	  -a -n "$(X86_GUEST)" -a -n "$(NATIVE_IMAGE)" || \
	  { echo "usage: make test-aot-v2-runner AOT_V2_RUNNER=... AOT_V2_RUNTIME_DIR=... X86_GUEST=... NATIVE_IMAGE=..."; exit 2; }
	sh tests/test-aot-v2-runner.sh $(BUILD)/latc $(AOT_V2_RUNNER) \
	  $(AOT_V2_RUNTIME_DIR) $(X86_GUEST) $(NATIVE_IMAGE) \
	  $(BUILD)/aot-v2-runner-test

test-latcd-once: all
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)" \
	  -a -n "$(X86_GUEST)" || \
	  { echo "usage: make test-latcd-once AOT_V2_RUNNER=... AOT_V2_RUNTIME_DIR=... X86_GUEST=..."; exit 2; }
	sh tests/test-latcd-once.sh $(BUILD)/latcd/latcd $(BUILD)/latc \
	  $(AOT_V2_RUNNER) $(AOT_V2_RUNTIME_DIR) $(X86_GUEST) \
	  $(BUILD)/latcd-once-test

test-latcd-service: all $(BUILD)/tests/test-cache-retirement
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)" \
	  -a -n "$(X86_GUEST)" || \
	  { echo "usage: make test-latcd-service AOT_V2_RUNNER=... AOT_V2_RUNTIME_DIR=... X86_GUEST=..."; exit 2; }
	sh tests/test-latcd-service.sh $(BUILD)/latcd/latcd $(BUILD)/latc \
	  $(AOT_V2_RUNNER) $(AOT_V2_RUNTIME_DIR) $(X86_GUEST) \
	  $(BUILD)/latcd-service-test $(BUILD)/tests/test-cache-retirement

test-latcd-runner: all $(BUILD)/tests/x86-static-hello \
		$(BUILD)/tests/x86-dynamic-hello
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)" \
	  -a -n "$(X86_ROOTFS)" || \
	  { echo "usage: make test-latcd-runner AOT_V2_RUNNER=... AOT_V2_RUNTIME_DIR=... X86_ROOTFS=..."; exit 2; }
	sh tests/test-latcd-runner.sh $(BUILD)/latcd/latcd $(BUILD)/latc \
	  $(AOT_V2_RUNNER) $(AOT_V2_RUNTIME_DIR) $(X86_ROOTFS) \
	  $(BUILD)/tests/x86-static-hello $(BUILD)/tests/x86-dynamic-hello \
	  $(BUILD)/latcd-runner-test

test-aot-v2-real-app: all
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)" \
	  -a -n "$(X86_ROOTFS)" -a -n "$(X86_APP)" || \
	  { echo "usage: make test-aot-v2-real-app AOT_V2_RUNNER=... AOT_V2_RUNTIME_DIR=... X86_ROOTFS=... X86_APP=..."; exit 2; }
	sh tests/test-aot-v2-real-app.sh $(BUILD)/latcd/latcd $(BUILD)/latc \
	  $(AOT_V2_RUNNER) $(AOT_V2_RUNTIME_DIR) $(X86_ROOTFS) $(X86_APP) \
	  $(BUILD)/aot-v2-real-app-test

test-aot-v2-complex-apps: all
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)" \
	  -a -n "$(X86_ROOTFS)" || \
	  { echo "usage: make test-aot-v2-complex-apps AOT_V2_RUNNER=... AOT_V2_RUNTIME_DIR=... X86_ROOTFS=..."; exit 2; }
	sh tests/test-aot-v2-complex-apps.sh $(BUILD)/latcd/latcd $(BUILD)/latc \
	  $(AOT_V2_RUNNER) $(AOT_V2_RUNTIME_DIR) $(X86_ROOTFS) \
	  $(BUILD)/aot-v2-complex-apps-test

test-aot-v2-complex-performance: all
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)" \
	  -a -n "$(X86_ROOTFS)" -a -n "$(AOT_V2_CACHE)" || \
	  { echo "usage: make test-aot-v2-complex-performance AOT_V2_RUNNER=... AOT_V2_RUNTIME_DIR=... X86_ROOTFS=... AOT_V2_CACHE=..."; exit 2; }
	python3 tests/test-aot-v2-complex-performance.py \
	  $(BUILD)/latcd/latcd $(BUILD)/latc $(AOT_V2_RUNNER) \
	  $(AOT_V2_RUNTIME_DIR) $(X86_ROOTFS) $(AOT_V2_CACHE) \
	  $(BUILD)/aot-v2-complex-performance-test

test-aot-v2-m4: all $(BUILD)/tests/x86-static-hello \
		$(BUILD)/tests/x86-glibc-hello $(BUILD)/tests/x86-signal-recover \
		$(BUILD)/tests/x86-signal-recover.tbset \
		$(BUILD)/tests/x86-dynamic-hello $(BUILD)/tests/x86-dlopen-main \
		$(BUILD)/tests/x86-dlopen-plugin.so \
		$(BUILD)/tests/x86-semantics-main \
		$(BUILD)/tests/x86-semantics-startup.so \
		$(BUILD)/tests/x86-semantics-plugin.so \
		$(BUILD)/tests/x86-semantics-preload.so
	@test -n "$(RUNNER)" -a -n "$(AOT_V2_RUNNER)" \
	  -a -n "$(AOT_V2_RUNTIME_DIR)" -a -n "$(X86_ROOTFS)" \
	  -a -n "$(SPEC_ROOT)" || \
	  { echo "usage: make test-aot-v2-m4 RUNNER=... AOT_V2_RUNNER=... AOT_V2_RUNTIME_DIR=... X86_ROOTFS=... SPEC_ROOT=..."; exit 2; }
	@mkdir -p $(BUILD)/aot-v2-m4
	LD_LIBRARY_PATH=$(dir $(RUNNER)) \
	  scripts/compile-native-image.sh $(BUILD)/latc $(RUNNER) \
	  $(BUILD)/tests/x86-glibc-hello \
	  $(BUILD)/aot-v2-m4/glibc.latnative
	LD_LIBRARY_PATH=$(dir $(RUNNER)) \
	  scripts/compile-native-image.sh $(BUILD)/latc $(RUNNER) \
	  $(BUILD)/tests/x86-signal-recover \
	  $(BUILD)/aot-v2-m4/signal.latnative \
	  $(BUILD)/tests/x86-signal-recover.tbset
	$(MAKE) test-latcd-once AOT_V2_RUNNER=$(AOT_V2_RUNNER) \
	  AOT_V2_RUNTIME_DIR=$(AOT_V2_RUNTIME_DIR) \
	  X86_GUEST=$(BUILD)/tests/x86-static-hello
	$(MAKE) test-latcd-service AOT_V2_RUNNER=$(AOT_V2_RUNNER) \
	  AOT_V2_RUNTIME_DIR=$(AOT_V2_RUNTIME_DIR) \
	  X86_GUEST=$(BUILD)/tests/x86-static-hello
	$(MAKE) test-latcd-runner AOT_V2_RUNNER=$(AOT_V2_RUNNER) \
	  AOT_V2_RUNTIME_DIR=$(AOT_V2_RUNTIME_DIR) X86_ROOTFS=$(X86_ROOTFS)
	$(MAKE) test-aot-v2-glibc-runner AOT_V2_RUNNER=$(AOT_V2_RUNNER) \
	  AOT_V2_RUNTIME_DIR=$(AOT_V2_RUNTIME_DIR) \
	  X86_GUEST=$(BUILD)/tests/x86-glibc-hello \
	  NATIVE_IMAGE=$(BUILD)/aot-v2-m4/glibc.latnative
	$(MAKE) test-aot-v2-signal-runner AOT_V2_RUNNER=$(AOT_V2_RUNNER) \
	  AOT_V2_RUNTIME_DIR=$(AOT_V2_RUNTIME_DIR) \
	  X86_GUEST=$(BUILD)/tests/x86-signal-recover \
	  NATIVE_IMAGE=$(BUILD)/aot-v2-m4/signal.latnative
	$(MAKE) test-aot-v2-dynamic-runner AOT_V2_RUNNER=$(AOT_V2_RUNNER) \
	  AOT_V2_RUNTIME_DIR=$(AOT_V2_RUNTIME_DIR) X86_ROOTFS=$(X86_ROOTFS) \
	  X86_GUEST=$(BUILD)/tests/x86-dynamic-hello
	$(MAKE) test-aot-v2-dlopen-runner AOT_V2_RUNNER=$(AOT_V2_RUNNER) \
	  AOT_V2_RUNTIME_DIR=$(AOT_V2_RUNTIME_DIR) X86_ROOTFS=$(X86_ROOTFS) \
	  X86_GUEST=$(BUILD)/tests/x86-dlopen-main \
	  X86_DSO=$(BUILD)/tests/x86-dlopen-plugin.so
	$(MAKE) test-aot-v2-dynamic-semantics AOT_V2_RUNNER=$(AOT_V2_RUNNER) \
	  AOT_V2_RUNTIME_DIR=$(AOT_V2_RUNTIME_DIR) X86_ROOTFS=$(X86_ROOTFS) \
	  X86_GUEST=$(BUILD)/tests/x86-semantics-main \
	  X86_STARTUP_DSO=$(BUILD)/tests/x86-semantics-startup.so \
	  X86_DSO=$(BUILD)/tests/x86-semantics-plugin.so \
	  X86_PRELOAD_DSO=$(BUILD)/tests/x86-semantics-preload.so
	LD_LIBRARY_PATH=$(dir $(RUNNER)) $(MAKE) test-specint-aot-v2 \
	  RUNNER=$(RUNNER) AOT_V2_RUNNER=$(AOT_V2_RUNNER) \
	  AOT_V2_RUNTIME_DIR=$(AOT_V2_RUNTIME_DIR) SPEC_ROOT=$(SPEC_ROOT)

test-aot-v2-glibc-runner: all
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)" \
	  -a -n "$(X86_GUEST)" -a -n "$(NATIVE_IMAGE)" || \
	  { echo "usage: make test-aot-v2-glibc-runner AOT_V2_RUNNER=... AOT_V2_RUNTIME_DIR=... X86_GUEST=... NATIVE_IMAGE=..."; exit 2; }
	sh tests/test-aot-v2-glibc-runner.sh $(BUILD)/latc $(AOT_V2_RUNNER) \
	  $(AOT_V2_RUNTIME_DIR) $(X86_GUEST) $(NATIVE_IMAGE) \
	  $(BUILD)/aot-v2-glibc-runner-test

test-aot-v2-signal-runner: all
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)" \
	  -a -n "$(X86_GUEST)" -a -n "$(NATIVE_IMAGE)" || \
	  { echo "usage: make test-aot-v2-signal-runner AOT_V2_RUNNER=... AOT_V2_RUNTIME_DIR=... X86_GUEST=... NATIVE_IMAGE=..."; exit 2; }
	sh tests/test-aot-v2-signal-runner.sh $(BUILD)/latc $(AOT_V2_RUNNER) \
	  $(AOT_V2_RUNTIME_DIR) $(X86_GUEST) $(NATIVE_IMAGE) \
	  $(BUILD)/aot-v2-signal-runner-test

test-aot-v2-dynamic-runner: all
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)" \
	  -a -n "$(X86_ROOTFS)" -a -n "$(X86_GUEST)" || \
	  { echo "usage: make test-aot-v2-dynamic-runner AOT_V2_RUNNER=... AOT_V2_RUNTIME_DIR=... X86_ROOTFS=... X86_GUEST=..."; exit 2; }
	sh tests/test-aot-v2-dynamic-runner.sh $(BUILD)/latc \
	  $(AOT_V2_RUNNER) $(AOT_V2_RUNTIME_DIR) $(X86_ROOTFS) \
	  $(X86_GUEST) $(BUILD)/aot-v2-dynamic-runner-test 30s

test-aot-v2-dlopen-runner: all
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)" \
	  -a -n "$(X86_ROOTFS)" -a -n "$(X86_GUEST)" \
	  -a -n "$(X86_DSO)" || \
	  { echo "usage: make test-aot-v2-dlopen-runner AOT_V2_RUNNER=... AOT_V2_RUNTIME_DIR=... X86_ROOTFS=... X86_GUEST=... X86_DSO=..."; exit 2; }
	sh tests/test-aot-v2-dlopen-runner.sh $(BUILD)/latc \
	  $(AOT_V2_RUNNER) $(AOT_V2_RUNTIME_DIR) $(X86_ROOTFS) \
	  $(X86_GUEST) $(X86_DSO) $(BUILD)/aot-v2-dlopen-runner-test 30s

test-aot-v2-dynamic-semantics: all
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)" \
	  -a -n "$(X86_ROOTFS)" -a -n "$(X86_GUEST)" \
	  -a -n "$(X86_STARTUP_DSO)" -a -n "$(X86_DSO)" \
	  -a -n "$(X86_PRELOAD_DSO)" || \
	  { echo "usage: make test-aot-v2-dynamic-semantics AOT_V2_RUNNER=... AOT_V2_RUNTIME_DIR=... X86_ROOTFS=... X86_GUEST=... X86_STARTUP_DSO=... X86_DSO=... X86_PRELOAD_DSO=..."; exit 2; }
	sh tests/test-aot-v2-dynamic-semantics.sh $(BUILD)/latc \
	  $(AOT_V2_RUNNER) $(AOT_V2_RUNTIME_DIR) $(X86_ROOTFS) \
	  $(X86_GUEST) $(X86_STARTUP_DSO) $(X86_DSO) \
	  $(X86_PRELOAD_DSO) $(BUILD)/aot-v2-dynamic-semantics-test 30s

test-aot-v2-invalidation: all \
		$(BUILD)/tests/x86-aot-v2-invalidation \
		$(BUILD)/tests/x86-aot-v2-invalidation-plugin.so
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)" \
	  -a -n "$(X86_ROOTFS)" || \
	  { echo "usage: make test-aot-v2-invalidation AOT_V2_RUNNER=... AOT_V2_RUNTIME_DIR=... X86_ROOTFS=..."; exit 2; }
	sh tests/test-aot-v2-invalidation.sh $(BUILD)/latc \
	  $(AOT_V2_RUNNER) $(AOT_V2_RUNTIME_DIR) $(X86_ROOTFS) \
	  $(BUILD)/tests/x86-aot-v2-invalidation \
	  $(BUILD)/tests/x86-aot-v2-invalidation-plugin.so \
	  $(BUILD)/aot-v2-invalidation-test 30s

test-aot-v2-fork: all $(BUILD)/tests/x86-aot-v2-fork
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)" \
	  -a -n "$(X86_ROOTFS)" || \
	  { echo "usage: make test-aot-v2-fork AOT_V2_RUNNER=... AOT_V2_RUNTIME_DIR=... X86_ROOTFS=..."; exit 2; }
	sh tests/test-aot-v2-fork.sh $(BUILD)/latc $(AOT_V2_RUNNER) \
	  $(AOT_V2_RUNTIME_DIR) $(X86_ROOTFS) \
	  $(BUILD)/tests/x86-aot-v2-fork $(BUILD)/aot-v2-fork-test

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
		$(BUILD)/native/format/native-image.o $(BUILD)/aot-v2/common/translation-config.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-native-constants: tests/test-native-constants.c \
		$(BUILD)/native/format/native-image.o $(BUILD)/aot-v2/common/translation-config.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

test-native-constants: all
	@test -n "$(INSTALL_PREFIX)" -a -n "$(X86_GUEST)" -a -n "$(TBSET)" -a -n "$(WORK)"
	python3 tests/test-native-constants.py "$(INSTALL_PREFIX)" "$(X86_GUEST)" "$(TBSET)" "$(WORK)"

.PHONY: test-final-provenance-export
$(BUILD)/tests/make-provenance-tu-bundle: tests/make-provenance-tu-bundle.c $(FORMAT_OBJ) $(BUILD)/liblatc_cfg.a
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

test-final-provenance-export: all $(BUILD)/tests/make-provenance-tu-bundle
	@test -n "$(INSTALL_PREFIX)" -a -n "$(X86_GUEST)" -a -n "$(TBSET)" -a -n "$(WORK)"
	python3 tests/test-final-provenance-export.py "$(INSTALL_PREFIX)" "$(X86_GUEST)" "$(TBSET)" "$(WORK)" "$(BUILD)/tests/make-provenance-tu-bundle"

test-fwait-constants: all
	@test -n "$(INSTALL_PREFIX)" -a -n "$(X86_GUEST)" -a -n "$(TBSET)" -a -n "$(WORK)"
	python3 tests/test-fwait-constants.py "$(INSTALL_PREFIX)" "$(X86_GUEST)" "$(TBSET)" "$(WORK)"

$(BUILD)/tests/test-native-migration-v12: tests/test-native-migration-v12.c \
	$(BUILD)/native/format/native-migration-v12.o \
	$(BUILD)/native/format/native-image.o \
	$(BUILD)/aot-v2/common/translation-config.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-native-tu-plan: tests/test-native-tu-plan.c \
		$(BUILD)/native/format/native-tu-plan.o \
		$(BUILD)/native/format/native-tu-audit.o \
		$(BUILD)/native/format/native-image.o \
		$(BUILD)/aot-v2/common/tb-key-set.o \
		$(BUILD)/aot-v2/common/translation-config.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-native-tu-extract: tests/test-native-tu-extract.c \
		$(BUILD)/native/format/native-tu-plan.o \
		$(BUILD)/native/format/native-tu-audit.o \
		$(BUILD)/native/format/native-image.o \
		$(BUILD)/aot-v2/common/tb-key-set.o \
		$(BUILD)/aot-v2/common/translation-config.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-native-tu-audit: tests/test-native-tu-audit.c \
		$(BUILD)/native/format/native-tu-audit.o \
		$(BUILD)/native/format/native-image.o \
		$(BUILD)/aot-v2/common/translation-config.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-native-relocate: tests/test-native-relocate.c \
		native/runtime/relocate.c native/runtime/runtime-symbols.c \
		native/runtime/x86-linux-user.c \
		native/runtime/dispatch.c native/runtime/dispatch-x86.S
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

$(BUILD)/tests/test-native-dispatch: tests/test-native-dispatch.c \
		native/runtime/dispatch.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

$(BUILD)/tests/test-aot-v2-module-pack: \
		tests/test-aot-v2-module-pack.c \
		$(BUILD)/aot-v2/common/translation-config.o \
		$(BUILD)/aot-v2/compiler/module-pack.o \
		$(BUILD)/native/format/native-image.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-auto-config: CFLAGS += -D_GNU_SOURCE -Wwrite-strings
$(BUILD)/tests/test-auto-config: aot-v2/tests/test-auto-config.c \
		aot-v2/runtime/auto-config.c aot-v2/runtime/latcd-client.c $(BUILD)/latcd/protocol.o
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-translation-config: aot-v2/tests/test-translation-config.c \
		aot-v2/common/translation-config.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-aot-v2-guest-elf-map: \
		aot-v2/tests/test-guest-elf-map.c \
		aot-v2/runtime/guest-elf-map.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/test-x86-linux-user: tests/test-x86-linux-user.c \
		native/runtime/x86-linux-user.c
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

test-specint-native: all
	@test -n "$(RUNNER)" -a -n "$(SPEC_ROOT)" || \
	  { echo "usage: make test-specint-native RUNNER=... SPEC_ROOT=... [SPEC_BENCHMARK=181.mcf]"; exit 2; }
	python3 spec2000/run-specint-native.py --latc $(BUILD)/latc \
	  --runner $(RUNNER) --spec-root $(SPEC_ROOT) \
	  --workdir $(BUILD)/specint-native \
	  $(if $(SPEC_BENCHMARK),--benchmark $(SPEC_BENCHMARK),)

test-specint-aot-v2: all
	@test -n "$(RUNNER)" -a -n "$(AOT_V2_RUNNER)" \
	  -a -n "$(AOT_V2_RUNTIME_DIR)" -a -n "$(SPEC_ROOT)" || \
	  { echo "usage: make test-specint-aot-v2 RUNNER=... AOT_V2_RUNNER=... AOT_V2_RUNTIME_DIR=... SPEC_ROOT=... [SPEC_BENCHMARK=181.mcf]"; exit 2; }
	python3 spec2000/run-specint-aot-v2.py --latc $(BUILD)/latc \
	  --exporter $(RUNNER) --aot-runner $(AOT_V2_RUNNER) \
	  --runtime-dir $(AOT_V2_RUNTIME_DIR) --spec-root $(SPEC_ROOT) \
	  --workdir $(BUILD)/specint-aot-v2 \
	  $(if $(SPEC_BENCHMARK),--benchmark $(SPEC_BENCHMARK),)

test-aot-v2-source-sync:
	python3 tests/test-aot-v2-source-sync.py \
	  scripts/sync-aot-v2-sources.py

test-prepare-runner-source:
	python3 tests/test-prepare-runner-source.py \
	  scripts/prepare-runner-source.py $(abspath ../..)

test-aot-v2-build-id:
	python3 tests/test-aot-v2-build-id.py

test-aot-v2-install:
	@test -n "$(INSTALL_PREFIX)" -a -n "$(X86_ROOTFS)" \
	  -a -n "$(X86_GUEST)" || \
	  { echo "usage: make test-aot-v2-install INSTALL_PREFIX=... X86_ROOTFS=... X86_GUEST=..."; exit 2; }
	sh tests/test-aot-v2-install.sh $(INSTALL_PREFIX) $(X86_ROOTFS) \
	  $(X86_GUEST) $(BUILD)/aot-v2-install-test

.PHONY: test-posix-lock-lifetime
test-posix-lock-lifetime: $(BUILD)/tests/test-posix-lock-lifetime
	@test -n "$(WORK)" || { echo "usage: make test-posix-lock-lifetime WORK=..."; exit 2; }
	timeout 30 $(BUILD)/tests/test-posix-lock-lifetime "$(WORK)"

$(BUILD)/tests/test-posix-lock-lifetime: tests/test-posix-lock-lifetime.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< -pthread

.PHONY: test-aot-v2-journal-fd
test-aot-v2-journal-fd:
	@test -n "$(INSTALL_PREFIX)" -a -n "$(GUEST_DIR)" -a -n "$(WORK)" || \
	  { echo "usage: make test-aot-v2-journal-fd INSTALL_PREFIX=... GUEST_DIR=... WORK=..."; exit 2; }
	sh tests/test-aot-v2-journal-fd.sh "$(INSTALL_PREFIX)" "$(GUEST_DIR)" "$(WORK)"

.PHONY: test-aot-v2-journal-fork
test-aot-v2-journal-fork:
	@test -n "$(INSTALL_PREFIX)" -a -n "$(X86_ROOTFS)" -a -n "$(X86_GUEST)" \
	  -a -n "$(FIXTURE_DIR)" -a -n "$(WORK)" || \
	  { echo "usage: make test-aot-v2-journal-fork INSTALL_PREFIX=... X86_ROOTFS=... X86_GUEST=... FIXTURE_DIR=... WORK=..."; exit 2; }
	sh tests/test-aot-v2-journal-fork.sh "$(INSTALL_PREFIX)" "$(X86_ROOTFS)" \
	  "$(X86_GUEST)" "$(WORK)" 60 "$(FIXTURE_DIR)"

.PHONY: test-latcd-async-flush
test-latcd-async-flush:
	@test -n "$(INSTALL_PREFIX)" -a -n "$(X86_GUEST)" -a -n "$(WORK)" || \
	  { echo "usage: make test-latcd-async-flush INSTALL_PREFIX=... X86_GUEST=... WORK=..."; exit 2; }
	python3 tests/test-latcd-async-flush.py "$(INSTALL_PREFIX)" "$(X86_GUEST)" "$(WORK)"
	python3 tests/test-latcd-async-flush.py "$(INSTALL_PREFIX)" "$(X86_GUEST)" "$(WORK)-deferred" --deferred
	python3 tests/test-latcd-async-flush.py "$(INSTALL_PREFIX)" "$(X86_GUEST)" "$(WORK)-static-failure" --static-failure
	python3 tests/test-latcd-async-flush.py "$(INSTALL_PREFIX)" "$(X86_GUEST)" "$(WORK)-static-duplicate" --static-duplicate

sync-aot-v2-sources:
	python3 scripts/sync-aot-v2-sources.py

check-import:
	python3 scripts/check-import.py

clean:
	rm -rf $(BUILD)

-include $(CFG_OBJ:.o=.d) $(BUILD)/compiler/latc.d \
	$(wildcard $(BUILD)/latcd/*.d) \
	$(BUILD)/tests/cache-retirement-testing.d \
	$(BUILD)/compiler/tbset.d $(BUILD)/format/bundle.d \
	$(BUILD)/native/format/native-tu-plan.d \
	$(BUILD)/native/format/native-tu-audit.d \
	$(BUILD)/native/format/native-image.d \
	$(BUILD)/aot-v2/compiler/module-pack.d \
	$(BUILD)/aot-v2/runtime/elf-validate.d \
	$(BUILD)/aot-v2/runtime/registry.d \
	$(BUILD)/aot-v2/runtime/module-loader.d

.PHONY: test-aot-v2-direct-closure
test-aot-v2-direct-closure: all $(BUILD)/tests/x86-direct-closure
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)"
	sh tests/test-aot-v2-direct-closure.sh $(abspath $(BUILD)/latc) \
	  $(AOT_V2_RUNNER) $(AOT_V2_RUNTIME_DIR) \
	  $(abspath $(BUILD)/tests/x86-direct-closure) \
	  $(abspath $(BUILD)/aot-v2-direct-closure-test)

$(BUILD)/tests/x86-direct-closure: tests/x86-direct-closure.S
	@mkdir -p $(dir $@)
	$(X86_CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

.PHONY: test-invalidation-stats
test-invalidation-stats:
	python3 tests/test-normalize-invalidation-stats.py

test: test-invalidation-stats

.PHONY: test-aot-v2-thread-env
.PHONY: test-aot-v2-static-vector-fallback
test-aot-v2-static-vector-fallback: all $(BUILD)/tests/x86-static-vector-fallback
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)"
	sh tests/test-aot-v2-static-vector-fallback.sh "$(abspath $(BUILD)/latc)" \
	  "$(AOT_V2_RUNNER)" "$(AOT_V2_RUNTIME_DIR)" \
	  "$(abspath $(BUILD)/tests/x86-static-vector-fallback)" \
	  "$(abspath $(BUILD)/aot-v2-static-vector-fallback-test)"

$(BUILD)/tests/x86-static-vector-fallback: tests/x86-static-vector-fallback.S
	@mkdir -p $(dir $@)
	$(X86_CC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<

.PHONY: test-aot-v2-autostart
test-aot-v2-autostart:
	@test -n "$(INSTALL_PREFIX)" -a -n "$(X86_GUEST)"
	sh tests/test-aot-v2-autostart.sh "$(INSTALL_PREFIX)" "$(X86_GUEST)" \
	  "$$(mktemp -d "$${TMPDIR:-$$HOME/tmp}/lat-aa.XXXXXX")"

.PHONY: test-aot-v2-source-fd
test-aot-v2-source-fd:
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)" \
	  -a -n "$(X86_ROOTFS)" -a -n "$(AOT_V2_LATCD)"
	sh tests/test-aot-v2-source-fd.sh "$(AOT_V2_LATCD)" \
	  "$(abspath $(BUILD)/latc)" "$(AOT_V2_RUNNER)" \
	  "$(AOT_V2_RUNTIME_DIR)" "$(X86_ROOTFS)" \
	  "$(abspath $(BUILD)/aot-v2-source-fd-test)"

test-aot-v2-thread-env:
	@test -n "$(AOT_V2_RUNNER)" -a -n "$(AOT_V2_RUNTIME_DIR)" \
	  -a -n "$(X86_ROOTFS)"
	sh tests/test-aot-v2-thread-env.sh $(AOT_V2_RUNNER) \
	  $(AOT_V2_RUNTIME_DIR) $(X86_ROOTFS) \
	  $(abspath $(BUILD)/aot-v2-thread-env-test)
