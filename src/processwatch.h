/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#pragma once

#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <inttypes.h>

#ifdef TMA
#include "tma_metrics.h"
#else
#include <Zydis/Zydis.h>
#endif

/**
 pw_opts_t
 **
 Stores preprocessed command-line options.
*/
struct pw_opts_t {
  char *csv_filename;
  FILE *csv_file;
  unsigned int interval_time, runtime;
  int pid;
  unsigned char show_mnemonics : 1;
  unsigned int sample_period;
  
  char **col_strs;
  int col_strs_len;
  int *cols;
  int cols_len;
};

/**
  bpf_info_t
  **
  Stores information needed to attach to the BPF program.
  Also includes the ring_buffer, which we'll use to collect
  data from the BPF program.
**/
typedef struct {
#ifdef TMA
  struct perf_slots_bpf *obj;
#else
  struct insn_bpf *obj;
#endif

  /* The BPF programs and links */
  struct bpf_program **prog;
  struct bpf_map **map;
  struct bpf_link **links;
  size_t num_links;
  int nr_cpus;
  char pmu_name[32];
  
#ifdef TMA
  /* Instead of a ring buffer, TMA uses file descriptors */
  struct tma_bpf_info_t *tma;
#else
  struct ring_buffer *rb;
  struct perf_buffer *pb;
#endif
  
} bpf_info_t;


/**
  process_t
  **
  Stores information about a process. We store pointers to
  these in the `process_info` array: one for each
  process that we've seen.
**/
typedef struct {
  int index;
  char *name;
  uint32_t name_hash;
} process_t;

#define MAX_PROCESSES 4194304

/**
  process_arr_t
  **
  This is an array of lists of processes.
  The first dimension is keyed on the PID of the process,
  and the value is a pointer to an array of process_t pointers.
  This array is NULL-terminated.
  **
  The header process_info.h initializes, grows, and accesses this array.
**/
typedef struct {
  process_t **arr[MAX_PROCESSES];
  int       max_pid;
} process_arr_t;


/**
  interval_results_t
  **
  Stores all profiling information. Most of this is cleared
  each interval. We categorize each instruction that we see,
  and each array has one value per instruction category.
  We also have per-process arrays, which dynamically grow
  as we see more processes. Gets updated by `results.h`.
**/
typedef struct {
  /* TOTALS
     insn = instruction (mnemonic)
     cat = category */
#ifdef TMA

  double    tma_metric[NUM_TMA_METRICS];
  double    *proc_tma_metric[NUM_TMA_METRICS];
  double    *proc_tma_cycles, *proc_tma_instructions;
  
#else

  uint64_t  cat_count[ZYDIS_CATEGORY_MAX_VALUE];
  uint64_t  insn_count[ZYDIS_MNEMONIC_MAX_VALUE];
  double    cat_percent[ZYDIS_CATEGORY_MAX_VALUE];
  double    insn_percent[ZYDIS_MNEMONIC_MAX_VALUE];
  
  /* PER PROCESS
     insn = instruction (mnemonic)
     cat = category
     proc = process */
  uint64_t  *proc_cat_count[ZYDIS_CATEGORY_MAX_VALUE];
  uint64_t  *proc_insn_count[ZYDIS_MNEMONIC_MAX_VALUE];
  double    *proc_cat_percent[ZYDIS_CATEGORY_MAX_VALUE];
  double    *proc_insn_percent[ZYDIS_MNEMONIC_MAX_VALUE];
  
#endif

  int       num_samples;
  int       *proc_num_samples;

  /* Keep track of PIDs */
  int       proc_arr_size;
  int       pid_ctr;
  uint32_t  *pids;
} interval_results_t;


/**
  results_t
  **
  Stores overall profiling information. Includes an interval_results_t,
  which is cleared each interval.
**/
typedef struct {

#ifdef TMA

  double    tma_metric[NUM_TMA_METRICS];
  double    *proc_tma_metric[NUM_TMA_METRICS];
  
#else

  /* Instruction and category counts and percentages.
     NOT per-interval; overall. */
  uint64_t  cat_count[ZYDIS_CATEGORY_MAX_VALUE];
  double    cat_percent[ZYDIS_CATEGORY_MAX_VALUE];
  uint64_t  insn_count[ZYDIS_MNEMONIC_MAX_VALUE];
  double    insn_percent[ZYDIS_MNEMONIC_MAX_VALUE];
  
  /* Per-process (but NOT per-interval) profiling */
  uint64_t  *proc_cat_count[ZYDIS_CATEGORY_MAX_VALUE];
  uint64_t  *proc_insn_count[ZYDIS_MNEMONIC_MAX_VALUE];
  double    *proc_cat_percent[ZYDIS_CATEGORY_MAX_VALUE];
  double    *proc_insn_percent[ZYDIS_MNEMONIC_MAX_VALUE];
  
  /* ZYDIS DISASSEMBLER */
  ZydisDecoder            decoder;
  ZydisFormatter          formatter;
  ZydisDecodedInstruction decoded_insn;
  
#endif

  int       num_samples;
  int       *proc_num_samples;
  
  /* Bookkeeping */
  uint64_t  interval_num;
  
  int       pid_ctr;
  int       proc_arr_size;
  
  process_arr_t process_info;
  
  /* The interval */
  interval_results_t *interval;
} results_t;

/* Need these globals outside of insnprof.c */
extern results_t *results;
extern bpf_info_t *bpf_info;
extern pthread_rwlock_t results_lock;
extern struct pw_opts_t pw_opts;

/* Reading from BPF and storing the results */
#include "results.h"
#include "detect_pmu.h"
#include "setup_bpf.h"
#include "process_info.h"
#include "tma.h"

/* The UI */
#include "ui/utils.h"
#include "ui/interactive.h"
#include "ui/csv.h"
