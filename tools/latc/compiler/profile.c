#define _GNU_SOURCE

#include "profile.h"

#include <errno.h>
#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char *error, size_t size, const char *message)
{
    if (error && size) snprintf(error, size, "%s", message);
    return -1;
}

static int source_digest(const char *path, char digest[65],
                         char *error, size_t error_size)
{
    gchar *contents = NULL;
    gsize size = 0;
    GError *gerror = NULL;
    if (!g_file_get_contents(path, &contents, &size, &gerror)) {
        if (error && error_size) {
            snprintf(error, error_size, "%s: %s", path,
                     gerror ? gerror->message : "cannot read source");
        }
        g_clear_error(&gerror);
        return -1;
    }
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(checksum, (const guchar *)contents, size);
    g_strlcpy(digest, g_checksum_get_string(checksum), 65);
    g_checksum_free(checksum);
    g_free(contents);
    return 0;
}

static int parse_v2_header(const char *path, size_t line_no, char *p,
                           const char *source_path,
                           char *error, size_t error_size)
{
    static const char prefix[] = "LATC_PROFILE_V2";
    p += sizeof(prefix) - 1;
    while (*p == ' ' || *p == '\t') p++;
    char expected[65];
    size_t length = 0;
    while (g_ascii_isxdigit(p[length])) length++;
    char *end = p + length;
    while (*end == ' ' || *end == '\t' || *end == '\r') end++;
    if (length != 64 || (*end && *end != '\n' && *end != '#')) {
        if (error && error_size) {
            snprintf(error, error_size,
                     "%s:%zu: expected LATC_PROFILE_V2 SOURCE_SHA256",
                     path, line_no);
        }
        return -1;
    }
    if (source_digest(source_path, expected, error, error_size)) return -1;
    if (g_ascii_strncasecmp(p, expected, 64)) {
        if (error && error_size) {
            snprintf(error, error_size,
                     "%s:%zu: profile source SHA-256 does not match %s",
                     path, line_no, source_path);
        }
        return -1;
    }
    return 0;
}

int latc_profile_apply(const char *path, const char *source_path,
                       CfgProgram *program,
                       bool ignore_outside_exec, size_t *matched,
                       size_t *unmatched, size_t *ignored,
                       char *error, size_t error_size)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        if (error && error_size)
            snprintf(error, error_size, "%s: %s", path, strerror(errno));
        return -1;
    }
    size_t hit = 0, miss = 0, skip = 0, line_no = 0;
    bool v2 = false, saw_data = false;
    char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, fp) >= 0) {
        line_no++;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '\n' || *p == '#') continue;
        if (!saw_data &&
            !strncmp(p, "LATC_PROFILE_V2", sizeof("LATC_PROFILE_V2") - 1)) {
            if (parse_v2_header(path, line_no, p, source_path,
                                error, error_size)) {
                free(line); fclose(fp); return -1;
            }
            v2 = true;
            saw_data = true;
            continue;
        }
        saw_data = true;
        errno = 0;
        char *end = NULL;
        uint64_t pc = strtoull(p, &end, 0);
        if (errno || end == p) goto malformed;
        p = end;
        uint64_t raw_flags = CFG_TB_CODE64;
        if (v2) {
            raw_flags = strtoull(p, &end, 0);
            if (errno || end == p || raw_flags > UINT32_MAX ||
                !(raw_flags & CFG_TB_CODE64) ||
                (raw_flags & ~(CFG_TB_CODE64 | CFG_TB_PARALLEL))) {
                goto malformed;
            }
            p = end;
        }
        errno = 0;
        uint64_t count = strtoull(p, &end, 0);
        if (errno || end == p || count == 0) goto malformed;
        while (*end == ' ' || *end == '\t' || *end == '\r') end++;
        if (*end && *end != '\n' && *end != '#') goto malformed;
        bool found = false;
        size_t template_index = SIZE_MAX;
        for (size_t i = 0; i < program->tb_count; i++) {
            if (program->tbs[i].start != pc) continue;
            if (template_index == SIZE_MAX) template_index = i;
            if (program->tbs[i].semantic_flags == (uint32_t)raw_flags) {
                uint64_t old = program->tbs[i].profile_count;
                program->tbs[i].profile_count = UINT64_MAX - old < count ?
                    UINT64_MAX : old + count;
                found = true;
                break;
            }
        }
        if (found) {
            hit++;
        } else if (cfg_program_address_is_executable(program, pc)) {
            CfgTb *next = realloc(program->tbs,
                                  (program->tb_count + 1) * sizeof(*next));
            if (!next) {
                free(line); fclose(fp);
                return fail(error, error_size, "out of memory adding profile TB");
            }
            program->tbs = next;
            CfgTb added = template_index != SIZE_MAX ?
                program->tbs[template_index] : (CfgTb) {
                    .start = pc,
                    .end = pc + 1,
                    .terminator_pc = pc,
                    .terminator = CFG_TB_FALLTHROUGH,
                };
            added.profile_count = count;
            added.semantic_flags = (uint32_t)raw_flags;
            added.first_edge = 0;
            added.edge_count = 0;
            program->tbs[program->tb_count++] = added;
            miss++;
        } else if (ignore_outside_exec) {
            skip++;
        } else {
            free(line); fclose(fp);
            if (error && error_size)
                snprintf(error, error_size,
                         "%s:%zu: address 0x%" PRIx64
                         " is outside executable ELF sections",
                         path, line_no, pc);
            return -1;
        }
        continue;
malformed:
        free(line);
        fclose(fp);
        if (error && error_size)
            snprintf(error, error_size, v2 ?
                     "%s:%zu: expected RVA FLAGS COUNT" :
                     "%s:%zu: expected ADDRESS COUNT", path, line_no);
        return -1;
    }
    free(line);
    if (ferror(fp)) {
        fclose(fp);
        return fail(error, error_size, "failed to read profile");
    }
    fclose(fp);
    if (matched) *matched = hit;
    if (unmatched) *unmatched = miss;
    if (ignored) *ignored = skip;
    return 0;
}
