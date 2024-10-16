/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#pragma once

#include <inttypes.h>
#include "process_info.h"
#include "bpf/insn/insn.h"

/* Only the function signature differs between the perf_buffer and ringbuffer versions */
#ifdef INSNPROF_LEGACY_PERF_BUFFER
static void handle_sample(void *ctx, int cpu, void *data, unsigned int data_sz) {
#else
static int handle_sample(void *ctx, void *data, size_t data_sz) {
#endif

  struct insn_info *insn_info;
  int category, mnemonic, success;
  int interval_index;
  uint32_t hash;

  insn_info = data;
  success = 0;
  
  category = -1;
  mnemonic = -1;

  #ifdef __x86_64__
    ZyanStatus status;
    status = ZydisDecoderDecodeInstruction(&results->decoder,
                                           ZYAN_NULL,
                                           insn_info->insn, 15,
                                           &results->decoded_insn);
    if(ZYAN_SUCCESS(status)) {
      success = 1;
      mnemonic = results->decoded_insn.mnemonic;
      category = results->decoded_insn.meta.category;
    }
  #elif __aarch64__
    int count;
    cs_insn *insn;
    count = cs_disasm(handle, insn_info->insn, 4, 0, 0, &insn);
    if(count) {
      success = 1;
      mnemonic = insn[0].id;
    }
  #endif
  
  if(pthread_rwlock_wrlock(&results_lock) != 0) {
    fprintf(stderr, "Failed to grab write lock! Aborting.\n");
    exit(1);
  }
  
  hash = djb2(insn_info->name);
  update_process_info(insn_info->pid, insn_info->name, hash);

  /* Store this result in the per-process array */
  interval_index = get_interval_proc_arr_index(insn_info->pid);

  if(success) {
    results->interval->insn_count[mnemonic]++;
    results->interval->proc_insn_count[mnemonic][interval_index]++;

#ifdef __x86_64__
    results->interval->cat_count[results->decoded_insn.meta.category]++;
    results->interval->proc_cat_count[category][interval_index]++;
#elif __aarch64__
    int i;
    // Capstone (LLVM) puts some instructions in 0, 1 or more groups
    for (i = 0; i < insn[0].detail->groups_count; i++) {
      category = insn[0].detail->groups[i];
      results->interval->cat_count[category]++;
      results->interval->proc_cat_count[category][interval_index]++;
    }
    cs_free(insn, count);
#endif
    
  } else {
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

static void init_results() {
  results = calloc(1, sizeof(results_t));
  if(!results) {
    fprintf(stderr, "Failed to allocate memory! Aborting.\n");
    exit(1);
  }
  results->interval = calloc(1, sizeof(interval_results_t));
  
#ifdef __x86_64__
  ZydisDecoderInit(&results->decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  ZydisFormatterInit(&results->formatter, ZYDIS_FORMATTER_STYLE_INTEL);
#endif
  
  /* Grow the per-process arrays to the first size class */
  grow_interval_proc_arrs();
}

static int clear_interval_results() {
  int i;
  
  memset(results->interval->proc_num_samples, 0, results->interval->proc_arr_size * sizeof(uint64_t));
  memset(results->interval->proc_num_failed, 0, results->interval->proc_arr_size * sizeof(uint64_t));
  memset(results->interval->pids, 0, results->interval->proc_arr_size * sizeof(uint32_t));
  results->interval->num_samples = 0;
  results->interval->num_failed = 0;
  
  for(i = 0; i < CATEGORY_MAX_VALUE; i++) {
    memset(results->interval->proc_cat_count[i], 0, results->interval->proc_arr_size * sizeof(uint64_t));
  }
  for(i = 0; i < MNEMONIC_MAX_VALUE; i++) {
    memset(results->interval->proc_insn_count[i], 0, results->interval->proc_arr_size * sizeof(uint64_t));
  }
  
  /* Per-category or per-instruction arrays */
  memset(results->interval->cat_count, 0, CATEGORY_MAX_VALUE * sizeof(uint64_t));
  memset(results->interval->insn_count, 0, MNEMONIC_MAX_VALUE * sizeof(uint64_t));
  
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
  free(results->interval);
  free(results);
}

static double get_ringbuf_used() {
  uint64_t size, avail;

  avail = ring__avail_data_size(ring_buffer__ring(bpf_info->rb, 0));
  size = ring__size(ring_buffer__ring(bpf_info->rb, 0));
  return ((double) avail) / size;
}
