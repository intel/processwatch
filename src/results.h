/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#pragma once

#include <inttypes.h>
#include "process_info.h"

#ifdef TMA
#include "bpf/tma/perf_slots.h"
#else
#include "bpf/insn/insn.h"
#endif

#ifndef TMA

/* Only the function signature differs between the perf_buffer and ringbuffer versions */
#ifdef INSNPROF_LEGACY_PERF_BUFFER
static void handle_sample(void *ctx, int cpu, void *data, unsigned int data_sz) {
#else
static int handle_sample(void *ctx, void *data, size_t data_sz) {
#endif

  struct insn_info *insn_info;
  int category, mnemonic;
  int interval_index;
  uint32_t hash;
#ifdef CAPSTONE 
  cs_insn *insn;
  int i, count;
#else
  ZyanStatus status;
#endif

  insn_info = data;

#ifdef CAPSTONE 
  #ifdef ARM
    count = cs_disasm(handle, insn_info->insn, 4, 0, 0, &insn);
  #else
    count = cs_disasm(handle, insn_info->insn, 15, 0, 0, &insn);
  #endif
#else
  status = ZydisDecoderDecodeInstruction(&results->decoder,
                                         ZYAN_NULL,
                                         insn_info->insn, 15,
                                         &results->decoded_insn);
#endif
  if(pthread_rwlock_wrlock(&results_lock) != 0) {
    fprintf(stderr, "Failed to grab write lock! Aborting.\n");
    exit(1);
  }
  
  category = -1;
  mnemonic = -1;

  hash = djb2(insn_info->name);
  update_process_info(insn_info->pid, insn_info->name, hash);

  /* Store this result in the per-process array */
  interval_index = get_interval_proc_arr_index(insn_info->pid);

#ifdef CAPSTONE 
  if(count) {
    mnemonic = insn[0].id;
    results->interval->insn_count[mnemonic]++;
    results->interval->proc_insn_count[mnemonic][interval_index]++;

    // Capstone (LLVM) puts some instructions in 0, 1 or more groups
    for (i = 0; i < insn[0].detail->groups_count; i++) {
      category = insn[0].detail->groups[i];
      results->interval->cat_count[category]++;
      results->interval->proc_cat_count[category][interval_index]++;
    }
    cs_free(insn, count);
  }
#else
  if(ZYAN_SUCCESS(status)) {
    category = results->decoded_insn.meta.category;
    mnemonic = results->decoded_insn.mnemonic;
    results->interval->cat_count[category]++;
    results->interval->insn_count[mnemonic]++;
  }
#endif
  else {
    results->interval->num_failed++;
    results->interval->proc_num_failed[interval_index]++;
    results->num_failed++;
  }

  results->interval->num_samples++;
  results->interval->proc_num_samples[interval_index]++;
  results->interval->pids[interval_index] = insn_info->pid;
  results->num_samples++;

  if(pthread_rwlock_unlock(&results_lock) != 0) {
    fprintf(stderr, "Failed to unlock the lock! Aborting.\n");
    exit(1);
  }
  
#ifndef INSNPROF_LEGACY_PERF_BUFFER
  return 0;
#endif
}

#endif /* TMA */

static void init_results() {
  results = calloc(1, sizeof(results_t));
  if(!results) {
    fprintf(stderr, "Failed to allocate memory! Aborting.\n");
    exit(1);
  }
  results->interval = calloc(1, sizeof(interval_results_t));
  
  /* Grow the per-process arrays to the first size class */
  grow_interval_proc_arrs();
  
#ifdef TMA
#else
#ifndef CAPSTONE 
  /* Initialize Zydis, which we use to disassemble instructions */
  ZydisDecoderInit(&results->decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  ZydisFormatterInit(&results->formatter, ZYDIS_FORMATTER_STYLE_INTEL);
#endif
#endif
}

static int clear_interval_results() {
  int i;
  
  memset(results->interval->proc_num_samples, 0, results->interval->proc_arr_size * sizeof(uint64_t));
  memset(results->interval->proc_num_failed, 0, results->interval->proc_arr_size * sizeof(uint64_t));
  memset(results->interval->pids, 0, results->interval->proc_arr_size * sizeof(uint32_t));
  results->interval->num_samples = 0;
  results->interval->num_failed = 0;
  
#ifdef TMA
  int n, x;

  for(i = 0; i < bpf_info->tma->num_metrics; i++) {
    for(x = 0; x < bpf_info->nr_cpus; x++) {
      for(n = 0; n < bpf_info->tma->metrics[i].num_events; n++) {
        memset(bpf_info->tma->metrics[i].proc_vals[x][n], 0, results->interval->proc_arr_size * sizeof(double));
      }
      memset(bpf_info->tma->metrics[i].vals[x], 0, bpf_info->tma->metrics[i].num_events * sizeof(double));
    }
  }
  memset(results->interval->proc_tma_cycles, 0, results->interval->proc_arr_size * sizeof(double));
  memset(results->interval->proc_tma_instructions, 0, results->interval->proc_arr_size * sizeof(double));

#else

  for(i = 0; i < CATEGORY_MAX_VALUE; i++) {
    memset(results->interval->proc_cat_count[i], 0, results->interval->proc_arr_size * sizeof(uint64_t));
  }
  for(i = 0; i < MNEMONIC_MAX_VALUE; i++) {
    memset(results->interval->proc_insn_count[i], 0, results->interval->proc_arr_size * sizeof(uint64_t));
  }
  
  /* Per-category or per-instruction arrays */
  memset(results->interval->cat_count, 0, CATEGORY_MAX_VALUE * sizeof(uint64_t));
  memset(results->interval->insn_count, 0, MNEMONIC_MAX_VALUE * sizeof(uint64_t));
  
#endif
  
  results->interval->pid_ctr = 0;
  results->interval_num++;
  
  return 0;
}

static void deinit_results() {
  int i;
  process_t **proc_arr;
  
  if(!results) {
    return;
  }

  for(i = 0; i <= results->process_info.max_pid; i++) {
    proc_arr = results->process_info.arr[i];
    if(!proc_arr) continue;
    while(*proc_arr) {
      free((*proc_arr)->name);
      free(*proc_arr);
      proc_arr++;
    }
    free(results->process_info.arr[i]);
  }
  
#ifdef TMA
#else
  free(results->interval->pids);
  free(results->interval->proc_num_samples);
  free(results->interval->proc_num_failed);
  free(results->interval->proc_percent);
  free(results->interval->proc_failed_percent);
  for(i = 0; i < CATEGORY_MAX_VALUE; i++) {
    free(results->interval->proc_cat_count[i]);
    free(results->interval->proc_cat_percent[i]);
  }
  for(i = 0; i < MNEMONIC_MAX_VALUE; i++) {
    free(results->interval->proc_insn_count[i]);
    free(results->interval->proc_insn_percent[i]);
  }
#endif
  free(results->interval);
  free(results);
}

static double get_ringbuf_used() {
  uint64_t size, avail;

  avail = ring__avail_data_size(ring_buffer__ring(bpf_info->rb, 0));
  size = ring__size(ring_buffer__ring(bpf_info->rb, 0));
  return ((double) avail) / size;
}
