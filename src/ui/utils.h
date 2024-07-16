/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#pragma once

double get_interval_ringbuf_used() {
  return results->interval->ringbuf_used;
}

double get_interval_proc_percent_samples(int proc_index) {
  return results->interval->proc_percent[proc_index];
}

double get_interval_proc_percent_failed(int proc_index) {
  return results->interval->proc_failed_percent[proc_index];
}

uint64_t get_interval_proc_num_samples(int proc_index) {
  return results->interval->proc_num_samples[proc_index];
}

uint64_t get_interval_num_samples() {
  return results->interval->num_samples;
}

#ifdef TMA

const char *get_name(int index) {
  return bpf_info->tma->metrics[index].shortname;
}

int get_max_value() {
  return 0;
}

double get_interval_metric(int index) {
  return results->interval->tma_metric[index];
}

double get_interval_proc_metric(int proc_index, int index) {
  return results->interval->proc_tma_metric[index][proc_index];
}

#else

const char *get_name(int index) {
  if(pw_opts.show_mnemonics) {
    return cs_insn_name(handle, index);
  } else {
    return cs_group_name(handle, index);
  }
}

int get_max_value() {
  if(pw_opts.show_mnemonics) {
    return MNEMONIC_MAX_VALUE;
  } else {
    return CATEGORY_MAX_VALUE;
  }
}

double get_interval_percent(int index) {
  if(pw_opts.show_mnemonics) {
    return results->interval->insn_percent[index];
  } else {
    if(index >= CATEGORY_MAX_VALUE) {
      fprintf(stderr, "Tried to access a per-interval category percent that doesn't exist. Aborting.\n");
      exit(1);
    }
    return results->interval->cat_percent[index];
  }
}

double get_interval_failed_percent() {
  return results->interval->failed_percent;
}

double get_interval_proc_percent(int proc_index, int index) {
  if(pw_opts.show_mnemonics) {
    return results->interval->proc_insn_percent[index][proc_index];
  } else {
    if(index >= CATEGORY_MAX_VALUE) {
      fprintf(stderr, "Tried to access a per-interval category percent that doesn't exist. Aborting.\n");
      exit(1);
    }
    return results->interval->proc_cat_percent[index][proc_index];
  }
}

#endif

enum qsort_val_type {
  QSORT_INTERVAL_PID,
  QSORT_INTERVAL_CAT_COUNT,
  QSORT_INTERVAL_CAT_PERCENT,
  QSORT_INTERVAL_INSN_COUNT,
  QSORT_INTERVAL_INSN_PERCENT,
  QSORT_PID,
  QSORT_CAT_PERCENT,
  QSORT_INSN_PERCENT
};

#define swap(a, b, t) \
  t = *a; \
  *a = *b; \
  *b = t;

#ifdef TMA
#define get_value(val, val_type, set) \
  switch(val_type) { \
    case QSORT_INTERVAL_PID: \
      set = results->interval->proc_tma_cycles[val]; \
      break; \
  }
#else
#define get_value(val, val_type, set) \
  switch(val_type) { \
    case QSORT_INTERVAL_PID: \
      set = results->interval->proc_num_samples[val]; \
      break; \
    case QSORT_INTERVAL_CAT_COUNT: \
      set = results->interval->cat_count[val]; \
      break; \
    case QSORT_INTERVAL_CAT_PERCENT: \
      set = results->interval->cat_percent[val]; \
      break; \
    case QSORT_INTERVAL_INSN_COUNT: \
      set = results->interval->insn_count[val]; \
      break; \
    case QSORT_INTERVAL_INSN_PERCENT: \
      set = results->interval->insn_percent[val]; \
      break; \
    default: \
      fprintf(stderr, "Invalid val_type! Aborting.\n"); \
      exit(1); \
      break; \
  }
#endif
  
#ifdef TMA
#define partition(vals, val_type, low, high, partition_index) \
  switch(val_type) { \
    case QSORT_INTERVAL_PID: \
      partition_index = double_partition(vals, val_type, low, high); \
      break; \
  }
#else
#define partition(vals, val_type, low, high, partition_index) \
  switch(val_type) { \
    case QSORT_INTERVAL_PID: \
      partition_index = int_partition(vals, val_type, low, high); \
      break; \
    case QSORT_INTERVAL_CAT_COUNT: \
      partition_index = int_partition(vals, val_type, low, high); \
      break; \
    case QSORT_INTERVAL_CAT_PERCENT: \
      partition_index = double_partition(vals, val_type, low, high); \
      break; \
    case QSORT_INTERVAL_INSN_COUNT: \
      partition_index = int_partition(vals, val_type, low, high); \
      break; \
    case QSORT_INTERVAL_INSN_PERCENT: \
      partition_index = double_partition(vals, val_type, low, high); \
      break; \
    case QSORT_PID: \
      partition_index = int_partition(vals, val_type, low, high); \
      break; \
    case QSORT_CAT_PERCENT: \
      partition_index = double_partition(vals, val_type, low, high); \
      break; \
    case QSORT_INSN_PERCENT: \
      partition_index = double_partition(vals, val_type, low, high); \
      break; \
    default: \
      fprintf(stderr, "Invalid partition_index! Aborting.\n"); \
      exit(1); \
      break; \
  }
#endif
  
int int_partition(int *vals, int val_type, int low, int high) {
  int pivot, i, j, j_val, pivot_val, tmp;

  pivot = high;
  i = low - 1;
  get_value(vals[pivot], val_type, pivot_val);
  for(j = low; j < high; j++) {
    get_value(vals[j], val_type, j_val);
    if(j_val > pivot_val) {
      i++;
      swap(&vals[i], &vals[j], tmp);
    }
  }
  swap(&vals[i + 1], &vals[high], tmp);

  return i + 1;
}

int double_partition(int *vals, int val_type, int low, int high) {
  int pivot, i, j;
  double j_val, pivot_val,
         tmp;

  pivot = high;
  i = low - 1;
  get_value(vals[pivot], val_type, pivot_val);
  for(j = low; j < high; j++) {
    get_value(vals[j], val_type, j_val);
    if(j_val > pivot_val) {
      i++;
      swap(&vals[i], &vals[j], tmp);
    }
  }
  swap(&vals[i + 1], &vals[high], tmp);

  return i + 1;
}
  
void quicksort(int *vals, int val_type, int low, int high) {
  int partition_index;

  if(low >= high) return;

  partition(vals, val_type, low, high, partition_index);
  quicksort(vals, val_type, low, partition_index - 1);
  quicksort(vals, val_type, partition_index + 1, high);
}

int *sort_interval_pids(int *num_pids) {
  int *pids, i, num_procs;
  
  num_procs = results->interval->pid_ctr;
  
  /* Copy all the PIDs into an array, unsorted. */
  pids = calloc(num_procs, sizeof(int));
  if(!pids) {
    fprintf(stderr, "Failed to allocate memory! Aborting.\n");
    exit(1);
  }
  for(i = 0; i < num_procs; i++) {
    pids[i] = i;
  }
  
  quicksort(pids, QSORT_INTERVAL_PID, 0, num_procs - 1);
  
  *num_pids = num_procs;
  return pids;
}

int *sort_pids(int *num_pids) {
  int *pids, i, num_procs;
  
  num_procs = results->pid_ctr;
  
  /* Copy all the PIDs into an array, unsorted. */
  pids = calloc(num_procs, sizeof(int));
  if(!pids) {
    fprintf(stderr, "Failed to allocate memory! Aborting.\n");
    exit(1);
  }
  for(i = 0; i < num_procs; i++) {
    pids[i] = i;
  }
  
  quicksort(pids, QSORT_PID, 0, num_procs - 1);
  
  *num_pids = num_procs;
  return pids;
}

/**
  calculate_interval_percentages
  **
  For each instruction category and mnemonic, calculate:
  1. Systemwide percentages.
  2. Per-process percentages.
**/
void calculate_interval_percentages() {
  int i, n;
  
  if(!(results->interval->num_samples)) {
    return;
  }
  
  results->interval->failed_percent = ((double) results->interval->num_failed) /
                                                results->interval->num_samples * 100;
  
  for(i = 0; i < results->interval->proc_arr_size; i++) {
    results->interval->proc_percent[i] = ((double) results->interval->proc_num_samples[i]) /
                                                   results->interval->num_samples * 100;
    results->interval->proc_failed_percent[i] = ((double) results->interval->proc_num_failed[i]) /
                                                   results->interval->num_samples * 100;
  }
  
  for(i = 0; i < CATEGORY_MAX_VALUE; i++) {
    results->interval->cat_percent[i] = ((double) results->interval->cat_count[i]) /
                                                  results->interval->num_samples * 100;
    for(n = 0; n < results->interval->proc_arr_size; n++) {
      if(!(results->interval->proc_num_samples[n])) continue;
      results->interval->proc_cat_percent[i][n] = ((double) results->interval->proc_cat_count[i][n]) /
                                                            results->interval->proc_num_samples[n] * 100;
    }
  }
  
  for(i = 0; i < MNEMONIC_MAX_VALUE; i++) {
    results->interval->insn_percent[i] = ((double) results->interval->insn_count[i]) /
                                                   results->interval->num_samples * 100;
    for(n = 0; n < results->interval->proc_arr_size; n++) {
      if(!(results->interval->proc_num_samples[n])) continue;
      results->interval->proc_insn_percent[i][n] = ((double) results->interval->proc_insn_count[i][n]) /
                                                             results->interval->proc_num_samples[n] * 100;
    }
  }
}
