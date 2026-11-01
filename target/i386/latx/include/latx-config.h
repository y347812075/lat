/*
 * SPDX-FileCopyrightText: 2021-2026 LAT Project Authors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _LATX_CONFIG_H_
#define _LATX_CONFIG_H_

#include "latx-types.h"
#include "optimize-config.h"
#include "exec/exec-all.h"
#include "latx-disassemble-trace.h"
#include "lat-translation-config.h"

extern void *interpret_glue;
extern ADDR context_switch_bt_to_native;
#if defined(CONFIG_LATX_KZT)
int target_latx_emit_callback_bridge(
    void *code_buf_addr, void (*callback)(CPUX86State *));
#endif

int target_latx_host(CPUArchState *env, struct TranslationBlock *tb, int max_insns);
int target_latx_prologue(void *code_buf_addr);
void latx_interpret_glue_init(void);
int target_latx_epilogue(void *code_buf_addr);
int target_latx_fpu_rotate(void *code_buf_addr);
void latx_tb_set_jmp_target(struct TranslationBlock *, int, struct TranslationBlock *);

#ifdef CONFIG_LATX_DEBUG
void latx_before_exec_trace_tb(CPUArchState *env, struct TranslationBlock *tb);
void latx_after_exec_trace_tb(CPUArchState *env, struct TranslationBlock *tb);
void latx_profile(void);
void trace_tb_execution(struct TranslationBlock *tb);
#endif
void latx_guest_stack_init(CPUArchState *env);

void latx_init_fpu_regs(CPUArchState *env);
void latx_lsenv_init(CPUArchState *env);
void latx_lsenv_init_translation_thread(CPUArchState *env);
void latx_lsenv_destroy(void);
void latx_dt_init(void);
void ht_pc_thunk_insert(uint32_t thunk_addr, int reg_index);
int ht_pc_thunk_lookup(uint32_t thunk_addr);
void ht_pc_thunk_invalidate(uint32_t start, uint32_t end);
void latx_handle_args(char *filename);
GString *latx_translation_config_json(const LatTranslationConfig *snapshot);
void latx_translation_config_capture(CPUX86State *env, uint32_t cflags,
                                    LatTranslationConfig *output);
bool latx_translation_config_native_domain(void);
int latx_translation_config_apply(const LatTranslationConfig *config,
                                 char *error, size_t error_size);
int latx_translation_config_verify(CPUX86State *env, uint32_t cflags,
    const LatTranslationConfig *expected, char *error, size_t error_size);
void latx_translation_config_set_native_replay(const LatTranslationConfig *config);
void latx_translation_config_bind_thread(void);
void latx_translation_config_unbind_thread(void);
bool latx_translation_config_native_replay_digest(uint8_t digest[32]);
GBytes *latx_translation_config_native_replay_bytes(void);

#ifdef CONFIG_LATX_TU
void target_disasm(struct TranslationBlock *tb, int max_insns);
#endif

#ifdef CONFIG_LATX_LARGE_CC
#define B_STUB_SIZE 8
#else
#define B_STUB_SIZE 4
#endif

#ifdef CONFIG_LATX_LAZYLINK
#undef  B_STUB_SIZE
#define B_STUB_SIZE 0
#endif

#endif /* _LATX_CONFIG_H_ */
