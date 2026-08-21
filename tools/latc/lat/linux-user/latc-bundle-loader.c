#include "qemu/osdep.h"

#include "latc-bundle-loader.h"
#include "latc-bundle-format.h"

#include "accel/tcg/internal.h"
#include "exec/exec-all.h"
#include "jrra.h"
#include "tcg/tcg.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int bundle_self_fd = -1;
static LatcDiskFooter bundle_footer;
static bool pretranslation_complete;
static uint64_t stat_cfg_tbs, stat_profiled, stat_pretranslated, stat_failed;
static uint64_t stat_continuation_tbs, stat_edge_target_tbs;
static uint64_t stat_interior_target_tbs;
static uint64_t stat_same_extent, stat_shorter_extent, stat_longer_extent;
static uint64_t stat_runtime_tb_gen_calls, stat_runtime_first_pc;
static uint64_t stat_runtime_tb_gen_attempts;
static uint64_t stat_runtime_program_tb_gen_calls;
static uint64_t stat_runtime_system_tb_gen_calls;
static uint64_t stat_runtime_program_tb_gen_attempts;
static uint64_t stat_runtime_system_tb_gen_attempts;
static uint32_t stat_runtime_first_cflags;
static bool stat_pretranslation_disabled;
static bool stat_aot_cache_hit;
static uint64_t stat_bundle_verify_ns, stat_guest_extract_ns;
static uint64_t stat_aot_prepare_ns;
static LatcDiskExecRange *bundle_exec_ranges;
static uint64_t bundle_exec_range_count;

static char *expand_pid_path(const char *pattern)
{
    GString *path = g_string_new(NULL);
    char pid[32];
    snprintf(pid, sizeof(pid), "%ld", (long)getpid());
    for (const char *p = pattern; *p; p++) {
        if (p[0] == '%' && p[1] == 'p') {
            g_string_append(path, pid);
            p++;
        } else {
            g_string_append_c(path, *p);
        }
    }
    return g_string_free(path, false);
}

static void write_stats(void)
{
    const char *stats_pattern = getenv("LATC_STATS_OUT");
    if (!stats_pattern || !*stats_pattern) return;
    char *stats_path = expand_pid_path(stats_pattern);
    FILE *stats = fopen(stats_path, "w");
    if (!stats) {
        g_free(stats_path);
        return;
    }
    fprintf(stats, "{\"pid\":%ld,\"cfg_tbs\":%llu,\"profiled_tbs\":%llu,"
            "\"pretranslated\":%llu,\"continuation_tbs\":%llu,"
            "\"edge_target_tbs\":%llu,\"interior_target_tbs\":%llu,"
            "\"failed\":%llu,"
            "\"same_extent\":%llu,\"shorter_than_cfg\":%llu,"
            "\"longer_than_cfg\":%llu,\"runtime_tb_gen_calls\":%llu,"
            "\"runtime_tb_gen_attempts\":%llu,"
            "\"runtime_program_tb_gen_calls\":%llu,"
            "\"runtime_system_tb_gen_calls\":%llu,"
            "\"runtime_program_tb_gen_attempts\":%llu,"
            "\"runtime_system_tb_gen_attempts\":%llu,"
            "\"runtime_first_pc\":%llu,\"runtime_first_cflags\":%u,"
            "\"pretranslation_disabled\":%s,\"aot_cache_hit\":%s,"
            "\"bundle_verify_ns\":%llu,\"guest_extract_ns\":%llu,"
            "\"aot_prepare_ns\":%llu}\n",
            (long)getpid(), (unsigned long long)stat_cfg_tbs,
            (unsigned long long)stat_profiled,
            (unsigned long long)stat_pretranslated,
            (unsigned long long)stat_continuation_tbs,
            (unsigned long long)stat_edge_target_tbs,
            (unsigned long long)stat_interior_target_tbs,
            (unsigned long long)stat_failed,
            (unsigned long long)stat_same_extent,
            (unsigned long long)stat_shorter_extent,
            (unsigned long long)stat_longer_extent,
            (unsigned long long)stat_runtime_tb_gen_calls,
            (unsigned long long)stat_runtime_tb_gen_attempts,
            (unsigned long long)stat_runtime_program_tb_gen_calls,
            (unsigned long long)stat_runtime_system_tb_gen_calls,
            (unsigned long long)stat_runtime_program_tb_gen_attempts,
            (unsigned long long)stat_runtime_system_tb_gen_attempts,
            (unsigned long long)stat_runtime_first_pc,
            stat_runtime_first_cflags,
            stat_pretranslation_disabled ? "true" : "false",
            stat_aot_cache_hit ? "true" : "false",
            (unsigned long long)stat_bundle_verify_ns,
            (unsigned long long)stat_guest_extract_ns,
            (unsigned long long)stat_aot_prepare_ns);
    fclose(stats);
    g_free(stats_path);
}

static bool program_address(uint64_t guest_pc)
{
    for (uint64_t i = 0; i < bundle_exec_range_count; i++) {
        LatcDiskExecRange *range = &bundle_exec_ranges[i];
        if (guest_pc >= range->start && guest_pc - range->start < range->size)
            return true;
    }
    return false;
}

static size_t x86_nop_size(const uint8_t *code, size_t available)
{
    static const struct {
        uint8_t size;
        uint8_t bytes[9];
    } nops[] = {
        { 9, { 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 } },
        { 8, { 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 } },
        { 7, { 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00 } },
        { 6, { 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00 } },
        { 5, { 0x0f, 0x1f, 0x44, 0x00, 0x00 } },
        { 4, { 0x0f, 0x1f, 0x40, 0x00 } },
        { 3, { 0x0f, 0x1f, 0x00 } },
        { 2, { 0x66, 0x90 } },
        { 1, { 0x90 } },
    };
    for (size_t i = 0; i < G_N_ELEMENTS(nops); i++) {
        if (available >= nops[i].size &&
            !memcmp(code, nops[i].bytes, nops[i].size)) {
            return nops[i].size;
        }
    }
    return 0;
}

void latc_bundle_note_tb_attempt(uint64_t guest_pc, uint32_t cflags)
{
    if (bundle_self_fd < 0 || !pretranslation_complete) return;
    bool program_pc = program_address(guest_pc);
    if (!stat_runtime_tb_gen_attempts) {
        stat_runtime_first_pc = guest_pc;
        stat_runtime_first_cflags = cflags;
    }
    stat_runtime_tb_gen_attempts++;
    if (program_pc) stat_runtime_program_tb_gen_attempts++;
    else stat_runtime_system_tb_gen_attempts++;
    const char *profile_path = getenv("LATC_PROFILE_OUT");
    if (profile_path && *profile_path) {
        FILE *profile = fopen(profile_path, "a");
        if (profile) {
            fprintf(profile, "0x%llx 1\n", (unsigned long long)guest_pc);
            fclose(profile);
        }
    }
    /* Keep the evidence valid even when the guest terminates via _exit. */
    write_stats();
    if (getenv("LATC_STRICT_AOT") ||
        (program_pc && getenv("LATC_STRICT_PROGRAM_AOT"))) {
        fprintf(stderr, "latc: strict AOT rejected runtime TB generation at 0x%llx\n",
                (unsigned long long)guest_pc);
        _exit(125);
    }
}

void latc_bundle_note_tb_generated(uint64_t guest_pc, uint32_t cflags)
{
    (void)cflags;
    if (bundle_self_fd < 0 || !pretranslation_complete) return;
    stat_runtime_tb_gen_calls++;
    if (program_address(guest_pc)) stat_runtime_program_tb_gen_calls++;
    else stat_runtime_system_tb_gen_calls++;
}

static int copy_range(int src, uint64_t offset, uint64_t size, int dst)
{
    unsigned char buffer[64 * 1024];
    while (size) {
        size_t want = size < sizeof(buffer) ? (size_t)size : sizeof(buffer);
        ssize_t got = pread(src, buffer, want, (off_t)offset);
        if (got <= 0) return -1;
        size_t done = 0;
        while (done < (size_t)got) {
            ssize_t put = write(dst, buffer + done, (size_t)got - done);
            if (put <= 0) return -1;
            done += (size_t)put;
        }
        offset += (uint64_t)got;
        size -= (uint64_t)got;
    }
    return lseek(dst, 0, SEEK_SET) < 0 ? -1 : 0;
}

static int verify_range(int fd, uint64_t offset, uint64_t size,
                        const char expected[64])
{
    unsigned char buffer[64 * 1024];
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    while (size) {
        size_t want = size < sizeof(buffer) ? (size_t)size : sizeof(buffer);
        ssize_t got = pread(fd, buffer, want, (off_t)offset);
        if (got != (ssize_t)want) {
            g_checksum_free(sum);
            return -1;
        }
        g_checksum_update(sum, buffer, want);
        offset += want;
        size -= want;
    }
    int match = memcmp(g_checksum_get_string(sum), expected, 64) == 0;
    g_checksum_free(sum);
    return match ? 0 : -1;
}

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    return clock_gettime(CLOCK_MONOTONIC, &ts) ? 0 :
        (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static bool cached_aot_matches(const char *path, const char *marker_path,
                               const LatcDiskFooter *footer)
{
    struct stat aot_st, marker_st;
    if (lstat(path, &aot_st) || lstat(marker_path, &marker_st) ||
        !S_ISREG(aot_st.st_mode) || !S_ISREG(marker_st.st_mode) ||
        aot_st.st_uid != geteuid() || marker_st.st_uid != geteuid() ||
        (aot_st.st_mode & 0222) || aot_st.st_size != (off_t)footer->aot_size)
        return false;
    FILE *marker = fopen(marker_path, "r");
    if (!marker) return false;
    char digest[65] = {0};
    unsigned long long dev, ino, size, sec, nsec;
    int fields = fscanf(marker, "%64s %llu %llu %llu %llu %llu",
                        digest, &dev, &ino, &size, &sec, &nsec);
    fclose(marker);
    return fields == 6 && !memcmp(digest, footer->aot_sha256, 64) &&
        dev == (unsigned long long)aot_st.st_dev &&
        ino == (unsigned long long)aot_st.st_ino &&
        size == (unsigned long long)aot_st.st_size &&
        sec == (unsigned long long)aot_st.st_mtim.tv_sec &&
        nsec == (unsigned long long)aot_st.st_mtim.tv_nsec;
}

static int install_cached_aot(int self, const LatcDiskFooter *footer,
                              const char *path, const char *marker_path)
{
    char *tmp = g_strdup_printf("%s.tmp.%ld", path, (long)getpid());
    char *marker_tmp = g_strdup_printf("%s.tmp.%ld", marker_path,
                                       (long)getpid());
    int fd = -1, marker_fd = -1, rc = -1;
    unlink(tmp);
    unlink(marker_tmp);
    fd = open(tmp, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0 || copy_range(self, footer->aot_offset,
                             footer->aot_size, fd) || fsync(fd) ||
        fchmod(fd, 0400) || close(fd)) {
        if (fd >= 0) close(fd);
        fd = -1;
        goto out;
    }
    fd = -1;
    if (rename(tmp, path)) goto out;
    struct stat st;
    if (stat(path, &st)) goto out;
    marker_fd = open(marker_tmp, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC,
                     0600);
    if (marker_fd < 0 ||
        dprintf(marker_fd, "%.64s %llu %llu %llu %llu %llu\n",
                footer->aot_sha256,
                (unsigned long long)st.st_dev,
                (unsigned long long)st.st_ino,
                (unsigned long long)st.st_size,
                (unsigned long long)st.st_mtim.tv_sec,
                (unsigned long long)st.st_mtim.tv_nsec) < 0 ||
        fsync(marker_fd) || fchmod(marker_fd, 0400) || close(marker_fd)) {
        if (marker_fd >= 0) close(marker_fd);
        marker_fd = -1;
        goto out;
    }
    marker_fd = -1;
    if (rename(marker_tmp, marker_path)) goto out;
    rc = 0;
out:
    if (fd >= 0) close(fd);
    if (marker_fd >= 0) close(marker_fd);
    if (rc) {
        unlink(tmp);
        unlink(marker_tmp);
    }
    g_free(tmp);
    g_free(marker_tmp);
    return rc;
}

int latc_bundle_inject_argv(int *argc, char ***argv)
{
    int self = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (self < 0) return 0;
    struct stat st;
    LatcDiskFooter footer;
    int rc = 0;
    if (fstat(self, &st) || st.st_size < (off_t)sizeof(footer) ||
        pread(self, &footer, sizeof(footer), st.st_size - (off_t)sizeof(footer)) !=
            (ssize_t)sizeof(footer)) goto out;
    if (memcmp(footer.magic, LATC_BUNDLE_MAGIC, 8) != 0) goto out;
    if (footer.version != LATC_BUNDLE_VERSION ||
        footer.footer_size != sizeof(footer) ||
        footer.guest_offset != footer.runner_size ||
        footer.cfg_offset != footer.guest_offset + footer.guest_size ||
        footer.aot_offset != footer.cfg_offset + footer.cfg_size ||
        footer.aot_offset + footer.aot_size + sizeof(footer) != (uint64_t)st.st_size ||
        (footer.aot_size && (!footer.aot_name[0] ||
                            footer.aot_name[sizeof(footer.aot_name) - 1] ||
                            strchr(footer.aot_name, '/')))) {
        errno = EINVAL; rc = -1; goto out;
    }
    uint64_t started = monotonic_ns();
    if (verify_range(self, footer.guest_offset, footer.guest_size,
                     footer.guest_sha256)) {
        errno = EINVAL; rc = -1; goto out;
    }
    stat_bundle_verify_ns = monotonic_ns() - started;
    char automatic_guest[PATH_MAX];
    const char *named_guest = getenv("LATC_NAMED_GUEST");
    if ((!named_guest || !*named_guest) && footer.aot_size) {
        snprintf(automatic_guest, sizeof(automatic_guest),
                 "/tmp/latc-%.16s-x86-guest", footer.guest_sha256);
        named_guest = automatic_guest;
    }
    started = monotonic_ns();
    int guest = named_guest && *named_guest ?
        open(named_guest, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0700) :
        (int)syscall(SYS_memfd_create, "latc-x86-guest", 0);
    if (guest < 0 || copy_range(self, footer.guest_offset,
                                footer.guest_size, guest)) {
        if (guest >= 0) close(guest);
        rc = -1; goto out;
    }
    if (named_guest && *named_guest) {
        const struct timespec times[2] = {
            { .tv_nsec = UTIME_OMIT },
            { .tv_sec = 1, .tv_nsec = 0 },
        };
        if (futimens(guest, times)) {
            close(guest); rc = -1; goto out;
        }
    }
    stat_guest_extract_ns = monotonic_ns() - started;
    bundle_footer = footer;
    bundle_self_fd = self;
    self = -1;
    if (footer.aot_size) {
        started = monotonic_ns();
        const char *home = getenv("HOME");
        char *cache_dir = home && *home ?
            g_build_filename(home, ".cache", "latx", NULL) : NULL;
        char *aot_path = cache_dir ?
            g_build_filename(cache_dir, footer.aot_name, NULL) : NULL;
        char *marker_path = aot_path ?
            g_strdup_printf("%s.latc-cache", aot_path) : NULL;
        if (!cache_dir || !aot_path || !marker_path ||
            g_mkdir_with_parents(cache_dir, 0700) ||
            strlen(aot_path) >= PATH_MAX || strlen(marker_path) >= PATH_MAX) {
            g_free(marker_path);
            g_free(cache_dir); g_free(aot_path); close(guest); rc = -1; goto out;
        }
        stat_aot_cache_hit = cached_aot_matches(aot_path, marker_path, &footer);
        if (!stat_aot_cache_hit &&
            (verify_range(bundle_self_fd, footer.aot_offset, footer.aot_size,
                          footer.aot_sha256) ||
             install_cached_aot(bundle_self_fd, &footer, aot_path,
                                marker_path))) {
            g_free(marker_path); g_free(cache_dir); g_free(aot_path);
            close(guest); rc = -1; goto out;
        }
        stat_aot_prepare_ns = monotonic_ns() - started;
        g_free(marker_path);
        g_free(cache_dir);
        g_free(aot_path);
        setenv("LATX_AOT", "1", 1);
        setenv("LATC_DISABLE_PRETRANSLATE", "1", 1);
    }
    char *guest_path = named_guest && *named_guest ? strdup(named_guest) : NULL;
    if (!guest_path && asprintf(&guest_path, "/proc/self/fd/%d", guest) < 0) {
        close(guest); rc = -1; goto out;
    }
    char **old = *argv;
    char **next = calloc((size_t)*argc + 3, sizeof(*next));
    if (!next) { free(guest_path); close(guest); rc = -1; goto out; }
    next[0] = old[0];
    next[1] = strdup("--");
    next[2] = guest_path;
    for (int i = 1; i < *argc; i++) next[i + 2] = old[i];
    if (!next[1]) {
        free(next); free(guest_path); close(guest); rc = -1; goto out;
    }
    *argc += 2;
    *argv = next;
    rc = 1;
out:
    if (self >= 0) close(self);
    return rc;
}

static int read_cfg(void *buffer, size_t size, uint64_t offset)
{
    return bundle_self_fd >= 0 &&
           pread(bundle_self_fd, buffer, size,
                 (off_t)(bundle_footer.cfg_offset + offset)) == (ssize_t)size ? 0 : -1;
}

void latc_bundle_pretranslate(struct CPUState *cpu)
{
    if (bundle_self_fd < 0 || !cpu) return;
    LatcDiskCfgHeader header;
    if (read_cfg(&header, sizeof(header), 0) ||
        memcmp(header.magic, LATC_CFG_MAGIC, 8) ||
        header.version != LATC_CFG_VERSION || header.record_size != sizeof(header)) {
        fprintf(stderr, "latc: invalid embedded CFG\n");
        return;
    }
    uint64_t range_offset = sizeof(header) +
        header.function_count * sizeof(LatcDiskFunction);
    bundle_exec_range_count = header.exec_range_count;
    bundle_exec_ranges = calloc(header.exec_range_count,
                                sizeof(*bundle_exec_ranges));
    if (header.exec_range_count && (!bundle_exec_ranges ||
        read_cfg(bundle_exec_ranges,
                 header.exec_range_count * sizeof(*bundle_exec_ranges),
                 range_offset))) {
        free(bundle_exec_ranges);
        bundle_exec_ranges = NULL;
        bundle_exec_range_count = 0;
        fprintf(stderr, "latc: invalid embedded executable ranges\n");
        return;
    }
    if (getenv("LATC_DISABLE_PRETRANSLATE")) {
        stat_cfg_tbs = header.tb_count;
        stat_pretranslation_disabled = true;
        pretranslation_complete = true;
        write_stats();
        return;
    }
    uint64_t tb_offset = sizeof(header) +
        header.function_count * sizeof(LatcDiskFunction) +
        header.exec_range_count * sizeof(LatcDiskExecRange);
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    target_ulong current_pc, cs_base;
    uint32_t flags;
    cpu_get_tb_cpu_state(env, &current_pc, &cs_base, &flags);
    (void)current_pc;
    uint32_t cflags = curr_cflags(cpu);
    uint64_t translated = 0, continuations = 0, edge_targets = 0;
    uint64_t interior_targets = 0;
    uint64_t failed = 0, profiled = 0;
    uint64_t same_extent = 0, shorter_extent = 0, longer_extent = 0;
    GHashTable *translated_pcs = g_hash_table_new(g_direct_hash,
                                                  g_direct_equal);

    /* Profiled TBs are translated first; an empty profile keeps old behavior. */
    for (unsigned pass = 0; pass < 2; pass++) {
        for (uint64_t i = 0; i < header.tb_count; i++) {
            LatcDiskTb disk_tb;
            if (read_cfg(&disk_tb, sizeof(disk_tb),
                         tb_offset + i * sizeof(disk_tb))) {
                failed++;
                continue;
            }
            bool is_profiled = disk_tb.profile_count != 0;
            if ((pass == 0) != is_profiled) continue;
            profiled += pass == 0;
            target_ulong pc = disk_tb.start;
            bool first = true;
            while (pc < disk_tb.end) {
                mmap_lock();
                TranslationBlock *tb = tb_gen_code(cpu, pc, cs_base,
                                                   flags, cflags);
                if (tb) {
                    jrra_pre_translate((void **)&tb, 1, cpu, flags, cflags);
                }
                mmap_unlock();
                if (!tb) {
                    failed++;
                    break;
                }
                translated++;
                g_hash_table_add(translated_pcs,
                                 (gpointer)(uintptr_t)pc);
                uint64_t tb_end = (uint64_t)pc + tb->size;
                if (first) {
                    uint64_t cfg_size = disk_tb.end - disk_tb.start;
                    if (tb->size == cfg_size) {
                        same_extent++;
                    } else if (tb->size < cfg_size) {
                        shorter_extent++;
                        if (getenv("LATC_DEBUG_CFG")) {
                            fprintf(stderr, "latc: shorter TB pc=0x%llx cfg=%llu lat=%u\n",
                                    (unsigned long long)disk_tb.start,
                                    (unsigned long long)cfg_size, tb->size);
                        }
                    } else {
                        /* CFG blocks stop at incoming targets; LAT TBs need not. */
                        longer_extent++;
                    }
                    first = false;
                }
                if (tb_end >= disk_tb.end) {
                    break;
                }
                if (!tb->size) {
                    break;
                }
                pc = tb_end;
                continuations++;
            }
        }
    }
    for (uint64_t i = 0; i < header.tb_count; i++) {
        LatcDiskTb disk_tb;
        if (read_cfg(&disk_tb, sizeof(disk_tb),
                     tb_offset + i * sizeof(disk_tb))) {
            failed++;
            continue;
        }
        uint64_t pc = disk_tb.start;
        while (pc < disk_tb.end) {
            size_t nop = x86_nop_size((const void *)(uintptr_t)pc,
                                      disk_tb.end - pc);
            if (!nop) break;
            pc += nop;
        }
        if (pc == disk_tb.start || pc >= disk_tb.end ||
            g_hash_table_contains(translated_pcs,
                                  (gpointer)(uintptr_t)pc)) {
            continue;
        }
        mmap_lock();
        TranslationBlock *tb = tb_gen_code(cpu, pc, cs_base,
                                           flags, cflags);
        if (tb) {
            jrra_pre_translate((void **)&tb, 1, cpu, flags, cflags);
        }
        mmap_unlock();
        if (!tb) {
            failed++;
            continue;
        }
        translated++;
        interior_targets++;
        g_hash_table_add(translated_pcs, (gpointer)(uintptr_t)pc);
    }
    uint64_t edge_offset = tb_offset +
        header.tb_count * sizeof(LatcDiskTb);
    for (uint64_t i = 0; i < header.edge_count; i++) {
        LatcDiskEdge edge;
        if (read_cfg(&edge, sizeof(edge),
                     edge_offset + i * sizeof(edge))) {
            failed++;
            continue;
        }
        if (!edge.to || !program_address(edge.to) ||
            g_hash_table_contains(translated_pcs,
                                  (gpointer)(uintptr_t)edge.to)) {
            continue;
        }
        target_ulong pc = edge.to;
        mmap_lock();
        TranslationBlock *tb = tb_gen_code(cpu, pc, cs_base,
                                           flags, cflags);
        if (tb) {
            jrra_pre_translate((void **)&tb, 1, cpu, flags, cflags);
        }
        mmap_unlock();
        if (!tb) {
            failed++;
            continue;
        }
        translated++;
        edge_targets++;
        g_hash_table_add(translated_pcs, (gpointer)(uintptr_t)pc);
    }
    g_hash_table_destroy(translated_pcs);
    stat_cfg_tbs = header.tb_count;
    stat_profiled = profiled;
    stat_pretranslated = translated;
    stat_continuation_tbs = continuations;
    stat_edge_target_tbs = edge_targets;
    stat_interior_target_tbs = interior_targets;
    stat_failed = failed;
    stat_same_extent = same_extent;
    stat_shorter_extent = shorter_extent;
    stat_longer_extent = longer_extent;
    pretranslation_complete = true;
    write_stats();
}
