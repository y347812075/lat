#define _GNU_SOURCE

#include "profile.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char *error, size_t size, const char *message)
{
    if (error && size) snprintf(error, size, "%s", message);
    return -1;
}

int latc_profile_apply(const char *path, CfgProgram *program,
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
    char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, fp) >= 0) {
        line_no++;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '\n' || *p == '#') continue;
        errno = 0;
        char *end = NULL;
        uint64_t pc = strtoull(p, &end, 0);
        if (errno || end == p) goto malformed;
        p = end;
        uint64_t count = strtoull(p, &end, 0);
        if (errno || end == p || count == 0) goto malformed;
        while (*end == ' ' || *end == '\t' || *end == '\r') end++;
        if (*end && *end != '\n' && *end != '#') goto malformed;
        bool found = false;
        for (size_t i = 0; i < program->tb_count; i++) {
            if (program->tbs[i].start == pc) {
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
            program->tbs[program->tb_count++] = (CfgTb){
                .start = pc,
                .end = pc + 1,
                .terminator_pc = pc,
                .profile_count = count,
                .terminator = CFG_TB_FALLTHROUGH,
            };
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
            snprintf(error, error_size, "%s:%zu: expected ADDRESS COUNT",
                     path, line_no);
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
