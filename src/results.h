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
static void update_pid(uint32_t pid, int cat, int insn, char *name) {
  int interval_index;
  uint32_t hash;
  
  hash = djb2(name);
  update_process_info(pid, name, hash);
  
  /* Store this result in the per-process array */
  interval_index = get_interval_proc_arr_index(pid);
  
  if((cat != -1) && (insn != -1)) {
    /* Only do this if the decoding worked */
    results->interval->proc_cat_count[cat][interval_index]++;
    results->interval->proc_insn_count[insn][interval_index]++;
  } else {
    results->interval->proc_num_failed[interval_index]++;
  }
  
  results->interval->proc_num_samples[interval_index]++;
  results->interval->pids[interval_index] = pid;
}

/* Only the function signature differs between the perf_buffer and ringbuffer versions */
#ifdef INSNPROF_LEGACY_PERF_BUFFER
static void handle_sample(void *ctx, int cpu, void *data, unsigned int data_sz) {
#else
static int handle_sample(void *ctx, void *data, size_t data_sz) {
#endif

  struct insn_info *insn_info;
  ZyanStatus status;
  int category, mnemonic;
  
  insn_info = data;
  
  status = ZydisDecoderDecodeInstruction(&results->decoder,
                                         ZYAN_NULL,
                                         insn_info->insn, 15,
                                         &results->decoded_insn);
  if(pthread_rwlock_wrlock(&results_lock) != 0) {
    fprintf(stderr, "Failed to grab write lock! Aborting.\n");
    exit(1);
  }
  
  category = -1;
  mnemonic = -1;
  if(ZYAN_SUCCESS(status)) {
    results->interval->cat_count[results->decoded_insn.meta.category]++;
    results->interval->insn_count[results->decoded_insn.mnemonic]++;
    category = results->decoded_insn.meta.category;
    mnemonic = results->decoded_insn.mnemonic;
  } else {
    results->interval->num_failed++;
    results->num_failed++;
  }
  
  results->interval->num_samples++;
  results->num_samples++;
  update_pid((uint32_t) insn_info->pid, category, mnemonic, insn_info->name);
  
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
  /* Initialize Zydis, which we use to disassemble instructions */
  ZydisDecoderInit(&results->decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  ZydisFormatterInit(&results->formatter, ZYDIS_FORMATTER_STYLE_INTEL);
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

  for(i = 0; i < ZYDIS_CATEGORY_MAX_VALUE; i++) {
    memset(results->interval->proc_cat_count[i], 0, results->interval->proc_arr_size * sizeof(uint64_t));
  }
  for(i = 0; i < ZYDIS_MNEMONIC_MAX_VALUE; i++) {
    memset(results->interval->proc_insn_count[i], 0, results->interval->proc_arr_size * sizeof(uint64_t));
  }
  
  /* Per-category or per-instruction arrays */
  memset(results->interval->cat_count, 0, ZYDIS_CATEGORY_MAX_VALUE * sizeof(uint64_t));
  memset(results->interval->insn_count, 0, ZYDIS_MNEMONIC_MAX_VALUE * sizeof(uint64_t));
  
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
  for(i = 0; i < ZYDIS_CATEGORY_MAX_VALUE; i++) {
    free(results->interval->proc_cat_count[i]);
    free(results->interval->proc_cat_percent[i]);
  }
  for(i = 0; i < ZYDIS_MNEMONIC_MAX_VALUE; i++) {
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
