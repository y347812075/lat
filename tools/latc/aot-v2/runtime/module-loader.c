#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "module-loader.h"

#include "cache-lifecycle.h"
#include "elf-validate.h"

#include <dlfcn.h>
#include <dirent.h>
#include "internal-fd-registry.h"
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail(char *error, size_t error_size, const char *format, ...)
{
    if (error && error_size) {
        va_list arguments;
        va_start(arguments, format);
        vsnprintf(error, error_size, format, arguments);
        va_end(arguments);
    }
    return -1;
}

/* Recognition only: no execution, compatibility admission, or fd reclamation.
 * Bounded pread avoids mapping arbitrary inherited files that may be truncated. */
static bool inherited_aot_fd(int fd, struct stat *status)
{
    Elf64_Ehdr header;
    if (fstat(fd, status) || !S_ISREG(status->st_mode) ||
        (status->st_mode & (S_IWGRP | S_IWOTH)) ||
        pread(fd, &header, sizeof(header), 0) != sizeof(header) ||
        memcmp(header.e_ident, ELFMAG, SELFMAG) ||
        header.e_ident[EI_CLASS] != ELFCLASS64 ||
        header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_type != ET_DYN ||
        header.e_machine != EM_LOONGARCH || header.e_phentsize != sizeof(Elf64_Phdr) ||
        !header.e_phnum || header.e_phnum > 128 || header.e_phoff > 1024 * 1024)
        return false;
    for (unsigned i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (pread(fd, &phdr, sizeof(phdr), header.e_phoff + i * sizeof(phdr)) != sizeof(phdr))
            return false;
        if (phdr.p_type != PT_NOTE || phdr.p_filesz > 65536 ||
            phdr.p_offset > INT64_MAX - 65536) continue;
        uint64_t offset = 0;
        while (offset + sizeof(Elf64_Nhdr) <= phdr.p_filesz) {
            Elf64_Nhdr note;
            if (pread(fd, &note, sizeof(note), phdr.p_offset + offset) != sizeof(note))
                return false;
            offset += sizeof(note);
            uint64_t names = ((uint64_t)note.n_namesz + 3) & ~UINT64_C(3);
            uint64_t desc = ((uint64_t)note.n_descsz + 3) & ~UINT64_C(3);
            if (names > phdr.p_filesz - offset || desc > phdr.p_filesz - offset - names)
                return false;
            if (note.n_type == LAT_AOT_V2_NOTE_TYPE &&
                note.n_namesz == sizeof(LAT_AOT_V2_NOTE_NAME) &&
                note.n_descsz == sizeof(LatAotNoteV2)) {
                char name[sizeof(LAT_AOT_V2_NOTE_NAME)];
                LatAotNoteV2 value;
                if (pread(fd, name, sizeof(name), phdr.p_offset + offset) == sizeof(name) &&
                    !memcmp(name, LAT_AOT_V2_NOTE_NAME, sizeof(name)) &&
                    pread(fd, &value, sizeof(value), phdr.p_offset + offset + names) == sizeof(value) &&
                    lat_aot_v2_magic_valid(value.magic) &&
                    value.abi_version == LAT_AOT_V2_ABI_VERSION &&
                    value.struct_size == sizeof(value)) return true;
            }
            offset += names + desc;
        }
    }
    return false;
}

int lat_aot_v2_module_retain_inherited(uint64_t *count, uint64_t *bytes,
                                      char *error, size_t error_size)
{
    if (!count || !bytes) { errno = EINVAL; return -1; }
    *count = *bytes = 0;
    /* Startup only, before guest execution or other fd-mutating threads. */
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return fail(error, error_size, "cannot inspect inherited AOT pins: %s", strerror(errno));
    lat_aot_v2_internal_fd_allocation_lock();
    int result = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        char *end;
        unsigned long number = strtoul(entry->d_name, &end, 10);
        if (!*entry->d_name || *end || number > INT32_MAX || (int)number == dirfd(directory)) continue;
        int fd = number;
        int flags = fcntl(fd, F_GETFD);
        int mode = fcntl(fd, F_GETFL);
        if (flags < 0 || (flags & FD_CLOEXEC) || mode < 0 ||
            (mode & O_ACCMODE) != O_RDONLY) continue;
        struct stat status;
        if (!inherited_aot_fd(fd, &status)) continue;
        if (lat_aot_v2_internal_fd_register_locked(fd)) { result = -1; break; }
        (*count)++;
        *bytes += status.st_size;
    }
    int saved = errno;
    lat_aot_v2_internal_fd_unlock();
    closedir(directory);
    errno = saved;
    return result ? fail(error, error_size, "cannot protect inherited AOT pins: %s", strerror(errno)) : 0;
}

static int descriptor_matches_note(const LatAotModuleV2 *descriptor,
                                   const LatAotNoteV2 *note,
                                   char *error, size_t error_size)
{
    if (!descriptor || !lat_aot_v2_magic_valid(descriptor->magic) ||
        descriptor->abi_version != LAT_AOT_V2_ABI_VERSION ||
        descriptor->struct_size != sizeof(*descriptor)) {
        return fail(error, error_size, "AOT descriptor ABI is invalid");
    }
    if (descriptor->module_flags != note->module_flags ||
        descriptor->required_features != note->required_features ||
        memcmp(descriptor->source_sha256, note->source_sha256,
               sizeof(note->source_sha256)) ||
        memcmp(descriptor->codegen_id, note->codegen_id,
               sizeof(note->codegen_id)) ||
        memcmp(descriptor->tbset_digest, note->tbset_digest,
               sizeof(note->tbset_digest))) {
        return fail(error, error_size,
                    "AOT descriptor does not match its ELF note");
    }
    Dl_info info;
    if (!dladdr(descriptor, &info) || !info.dli_fbase) {
        return fail(error, error_size, "cannot locate the loaded AOT ELF");
    }
    const unsigned char *base = info.dli_fbase;
    const Elf64_Ehdr *header = (const void *)base;
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) ||
        header->e_phentsize != sizeof(Elf64_Phdr) || !header->e_phnum) {
        return fail(error, error_size, "loaded AOT ELF header is invalid");
    }
    const Elf64_Phdr *phdrs = (const void *)(base + header->e_phoff);
    uintptr_t text_begin = (uintptr_t)descriptor->text_begin;
    uintptr_t text_end = (uintptr_t)descriptor->text_end;
    uintptr_t tb_begin = (uintptr_t)descriptor->tb_begin;
    uintptr_t tb_end = (uintptr_t)descriptor->tb_end;
    uintptr_t pc_begin = (uintptr_t)descriptor->pc_map_begin;
    uintptr_t pc_end = (uintptr_t)descriptor->pc_map_end;
    uintptr_t slot_begin = (uintptr_t)descriptor->guest_slot_begin;
    uintptr_t slot_end = (uintptr_t)descriptor->guest_slot_end;
    if (!text_begin || text_end <= text_begin || !tb_begin || tb_end < tb_begin ||
        (tb_end - tb_begin) % sizeof(LatAotTbV2) || pc_end < pc_begin ||
        (pc_end - pc_begin) % sizeof(LatAotPcMapV2) || slot_end < slot_begin ||
        (slot_end - slot_begin) % sizeof(LatAotGuestSlotV2)) {
        return fail(error, error_size, "AOT descriptor ranges are invalid");
    }
    int text_ok = 0;
    int tb_ok = 0;
    int pc_ok = pc_begin == pc_end;
    int slot_ok = slot_begin == slot_end;
    for (size_t i = 0; i < header->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) {
            continue;
        }
        uintptr_t begin = (uintptr_t)base + phdrs[i].p_vaddr;
        uintptr_t end = begin + phdrs[i].p_memsz;
        if (end < begin) {
            return fail(error, error_size, "loaded AOT segment overflows");
        }
        if (text_begin >= begin && text_end <= end &&
            (phdrs[i].p_flags & (PF_R | PF_W | PF_X)) == (PF_R | PF_X)) {
            text_ok = 1;
        }
        if (tb_begin >= begin && tb_end <= end &&
            (phdrs[i].p_flags & PF_R) && !(phdrs[i].p_flags & PF_W)) {
            tb_ok = 1;
        }
        if (pc_begin >= begin && pc_end <= end &&
            (phdrs[i].p_flags & PF_R) && !(phdrs[i].p_flags & PF_W)) {
            pc_ok = 1;
        }
        if (slot_begin >= begin && slot_end <= end &&
            (phdrs[i].p_flags & PF_R) && !(phdrs[i].p_flags & PF_W)) {
            slot_ok = 1;
        }
    }
    if (!text_ok || !tb_ok || !pc_ok || !slot_ok) {
        return fail(error, error_size,
                    "AOT descriptor points outside permitted segments");
    }
    uint64_t text_size = text_end - text_begin;
    size_t pc_count = (pc_end - pc_begin) / sizeof(LatAotPcMapV2);
    for (size_t i = 0; i < pc_count; i++) {
        const LatAotPcMapV2 *map = &descriptor->pc_map_begin[i];
        const uint32_t known_flags = LAT_AOT_PC_MAP_DYNAMIC_STATE |
            LAT_AOT_PC_MAP_STACK_POINTER_DELTA;
        const int has_stack_delta = map->flags &
            LAT_AOT_PC_MAP_STACK_POINTER_DELTA;
        if (!map->guest_rva ||
            map->host_offset_begin >= map->host_offset_end ||
            map->host_offset_end > text_size ||
            !(map->flags & LAT_AOT_PC_MAP_DYNAMIC_STATE) ||
            (map->flags & ~known_flags) ||
            (!!map->state_record_offset != !!has_stack_delta) ||
            (i && descriptor->pc_map_begin[i - 1].host_offset_end >
                  map->host_offset_begin)) {
            return fail(error, error_size,
                        "AOT PC map entry %zu is invalid", i);
        }
    }
    size_t slot_count = (slot_end - slot_begin) / sizeof(LatAotGuestSlotV2);
    int two_level = !!(descriptor->module_flags &
                       LAT_AOT_MODULE_TWO_LEVEL_GUEST_SLOTS);
    int three_level = !!(descriptor->module_flags &
                         LAT_AOT_MODULE_THREE_LEVEL_GUEST_SLOTS);
    if (two_level && three_level) {
        return fail(error, error_size,
                    "AOT guest slot table has conflicting formats");
    }
    size_t slot_limit = three_level ? LAT_AOT_V2_GUEST_ADDRESS_LIMIT :
        (two_level ? LAT_AOT_V2_TWO_LEVEL_GUEST_ADDRESS_LIMIT :
                     LAT_AOT_V2_CONTEXT_GUEST_SLOT_LIMIT);
    if (slot_count > slot_limit) {
        return fail(error, error_size, "AOT guest slot table is too large");
    }
    for (size_t i = 0; i < slot_count; i++) {
        const LatAotGuestSlotV2 *slot = &descriptor->guest_slot_begin[i];
        size_t page = i / LAT_AOT_V2_GUEST_PAGE_SLOT_COUNT;
        size_t root = three_level ?
            page / LAT_AOT_V2_GUEST_PAGE_SLOT_COUNT : page;
        size_t middle = page % LAT_AOT_V2_GUEST_PAGE_SLOT_COUNT;
        int32_t expected_fp_offset = (two_level || three_level) ?
            -(int32_t)((root + 1) * 8) : -(int32_t)((i + 1) * 8);
        uint32_t expected_page_offset = three_level ?
            (uint32_t)((middle * 8) << 16) |
                (uint32_t)((i % LAT_AOT_V2_GUEST_PAGE_SLOT_COUNT) * 8) :
            (two_level ?
                (i % LAT_AOT_V2_GUEST_PAGE_SLOT_COUNT) * 8 : 0);
        if (slot->reserved != expected_page_offset ||
            slot->fp_offset != expected_fp_offset) {
            return fail(error, error_size, "AOT guest slot table is invalid");
        }
    }
    if (!(descriptor->module_flags & (LAT_AOT_MODULE_SYNTHETIC_FIXTURE |
                                      LAT_AOT_MODULE_M1_TEST_ONLY)) &&
        (!(descriptor->module_flags & LAT_AOT_MODULE_PRECISE_PC_MAP) ||
         pc_begin == pc_end)) {
        return fail(error, error_size, "AOT precise PC map is empty");
    }
    return 0;
}

int lat_aot_v2_module_open(const char *path,
                           const LatAotExpectedV2 *expected,
                           LatAotLoadedModuleV2 *module,
                           char *error, size_t error_size)
{
    if (!path || !expected || !module) {
        errno = EINVAL;
        return fail(error, error_size, "invalid AOT module arguments");
    }
    memset(module, 0, sizeof(*module));
    module->backing_fd = -1;
    lat_aot_v2_internal_fd_allocation_lock();
    /* Keep the lease across exec until a trusted handoff can release it. */
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        int saved = errno;
        lat_aot_v2_internal_fd_unlock();
        errno = saved;
        return fail(error, error_size, "cannot open AOT module: %s",
                    strerror(errno));
    }
    if (lat_aot_v2_cache_lock_fd(fd, LOCK_SH | LOCK_NB,
                                 error, error_size) ||
        lat_aot_v2_cache_object_available(path, error, error_size) ||
        lat_aot_v2_internal_fd_register_locked(fd)) {
        int saved = errno;
        close(fd);
        lat_aot_v2_internal_fd_unlock();
        errno = saved;
        if (saved == ENOMEM) {
            return fail(error, error_size,
                        "cannot protect AOT module fd: out of memory");
        }
        return -1;
    }
    LatAotNoteV2 note;
    if (lat_aot_v2_elf_validate_fd(fd, expected, &note,
                                   error, error_size)) {
        lat_aot_v2_internal_fd_unregister_close_locked(fd);
        lat_aot_v2_internal_fd_unlock();
        return -1;
    }
    char fd_path[64];
    int length = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    if (length < 0 || (size_t)length >= sizeof(fd_path)) {
        lat_aot_v2_internal_fd_unregister_close_locked(fd);
        lat_aot_v2_internal_fd_unlock();
        errno = ENAMETOOLONG;
        return fail(error, error_size, "AOT module fd path is too long");
    }
    dlerror();
    void *handle = dlopen(fd_path, RTLD_NOW | RTLD_LOCAL);
    const char *dl_error = dlerror();
    if (!handle) {
        lat_aot_v2_internal_fd_unregister_close_locked(fd);
        lat_aot_v2_internal_fd_unlock();
        return fail(error, error_size, "cannot load AOT module: %s",
                    dl_error ? dl_error : "unknown dlopen failure");
    }
    dlerror();
    const LatAotModuleV2 *descriptor =
        dlsym(handle, LAT_AOT_V2_DESCRIPTOR_SYMBOL);
    dl_error = dlerror();
    if (dl_error || descriptor_matches_note(descriptor, &note,
                                            error, error_size)) {
        if (dl_error) {
            fail(error, error_size, "cannot resolve AOT descriptor: %s",
                 dl_error);
        }
        dlclose(handle);
        lat_aot_v2_internal_fd_unregister_close_locked(fd);
        lat_aot_v2_internal_fd_unlock();
        return -1;
    }
    module->dl_handle = handle;
    module->backing_fd = fd;
    module->descriptor = descriptor;
    module->note = note;
    lat_aot_v2_internal_fd_unlock();
    return 0;
}
