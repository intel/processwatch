/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#pragma once

#include <errno.h>
#include <inttypes.h>

#ifdef __x86_64__
#include <Zydis/Zydis.h>
#elif __aarch64__
/* Include Capstone, then libbpf.
   This fixes a double-define conflict with the bpf_insn identifier. */
#include <capstone/capstone.h>
#endif

#ifdef __aarch64__
#define bpf_insn cs_bpf_insn
#endif

#include <linux/bpf.h>
#include <bpf/libbpf.h>

#ifdef __aarch64__
#undef cs_bpf_insn
csh handle;
#endif

/* Maximums */
#ifdef __x86_64__
#define MNEMONIC_MAX_VALUE ZYDIS_MNEMONIC_MAX_VALUE
#define CATEGORY_MAX_VALUE ZYDIS_CATEGORY_MAX_VALUE
#define EXTENSION_MAX_VALUE ZYDIS_ISA_EXT_MAX_VALUE
#elif __aarch64__
#define MNEMONIC_MAX_VALUE (AArch64_INS_ALIAS_END-1)
#define CATEGORY_MAX_VALUE (AArch64_GRP_ENDING-1)
#endif

/**
 pw_opts_t
 **
 Stores preprocessed command-line options.
*/
struct pw_opts_t {
  char csv;
  unsigned int interval_time, num_intervals;
  int pid;
  unsigned char show_mnemonics : 1;
  unsigned char show_extensions : 1;
  unsigned int sample_period;
  
  char *btf_custom_path;
  
  char **col_strs;
  int col_strs_len;
  int *cols;
  int cols_len;
  
  char list;
  char debug;
  char all;
};

/**
  bpf_info_t
  **
  Stores information needed to attach to the BPF program.
  Also includes the ring_buffer, which we'll use to collect
  data from the BPF program.
**/
typedef struct {
  struct insn_bpf *obj;

  /* The BPF programs and links */
  struct bpf_program **prog;
  struct bpf_map **map;
  struct bpf_link **links;
  size_t num_links;
  int nr_cpus;
  char pmu_name[32];
  
  struct ring_buffer *rb;
  struct perf_buffer *pb;
  
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
  /*
     TOTALS
     insn = instruction (mnemonic)
     cat = category
     ext = extension
  */

  uint64_t  cat_count[CATEGORY_MAX_VALUE+1];
  uint64_t  insn_count[MNEMONIC_MAX_VALUE+1];
  double    cat_percent[CATEGORY_MAX_VALUE+1];
  double    insn_percent[MNEMONIC_MAX_VALUE+1];
  double    failed_percent;
  
  /*
     PER PROCESS
     insn = instruction (mnemonic)
     cat = category
     ext = extension
     proc = process
  */
  uint64_t  *proc_cat_count[CATEGORY_MAX_VALUE+1];
  uint64_t  *proc_insn_count[MNEMONIC_MAX_VALUE+1];
  double    *proc_cat_percent[CATEGORY_MAX_VALUE+1];
  double    *proc_insn_percent[MNEMONIC_MAX_VALUE+1];
  double    *proc_percent;
  double    *proc_failed_percent;
  
  /* Only for x86, also include ISA extensions */
  #ifdef __x86_64__
  uint64_t  ext_count[EXTENSION_MAX_VALUE+1];
  double    ext_percent[EXTENSION_MAX_VALUE+1];
  uint64_t  *proc_ext_count[EXTENSION_MAX_VALUE+1];
  double    *proc_ext_percent[EXTENSION_MAX_VALUE+1];
  #endif
  
  /* Per-interval counts */
  uint64_t  num_samples;
  uint64_t  num_failed;
  
  /* Per-interval per-process counts */
  uint64_t  *proc_num_samples;
  uint64_t  *proc_num_failed;

  /* Keep track of PIDs */
  int       proc_arr_size;
  int       pid_ctr;
  uint32_t  *pids;
  
  /* Ringbuffer stats */
  double ringbuf_used;
} interval_results_t;


/**
  results_t
  **
  Stores overall profiling information. Includes an interval_results_t,
  which is cleared each interval.
**/
typedef struct {
  /* Bookkeeping */
  int      pid_ctr;
  uint64_t interval_num;
  uint64_t num_samples;
  uint64_t num_failed;
  double   failed_percent;
  
  process_arr_t process_info;
  
#ifdef __x86_64__
  ZydisDecoder            decoder;
  ZydisFormatter          formatter;
  ZydisDecodedInstruction decoded_insn;
#endif
  
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
#include "kerninfo.h"
#include "setup_bpf.h"
#include "process_info.h"

/* The UI */
#include "ui/utils.h"
#include "ui/interactive.h"
#include "ui/csv.h"
