/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#pragma once

int get_interval_proc_num_samples(int proc_index) {
  return results->interval->proc_num_samples[proc_index];
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


int get_proc_num_samples(int proc_index) {
  return results->proc_num_samples[proc_index];
}


const char *get_name(int index) {
  if(pw_opts.show_mnemonics) {
    return ZydisMnemonicGetString(index);
  } else {
    return ZydisCategoryGetString(index);
  }
}

int get_max_value() {
  if(pw_opts.show_mnemonics) {
    return ZYDIS_MNEMONIC_MAX_VALUE;
  } else {
    return ZYDIS_CATEGORY_MAX_VALUE;
  }
}

double get_interval_percent(int index) {
  if(pw_opts.show_mnemonics) {
    return results->interval->insn_percent[index];
  } else {
    if(index >= ZYDIS_CATEGORY_MAX_VALUE) {
      fprintf(stderr, "Tried to access a per-interval category percent that doesn't exist. Aborting.\n");
      exit(1);
    }
    return results->interval->cat_percent[index];
  }
}

double get_interval_proc_percent(int proc_index, int index) {
  if(pw_opts.show_mnemonics) {
    return results->interval->proc_insn_percent[index][proc_index];
  } else {
    if(index >= ZYDIS_CATEGORY_MAX_VALUE) {
      fprintf(stderr, "Tried to access a per-interval category percent that doesn't exist. Aborting.\n");
      exit(1);
    }
    return results->interval->proc_cat_percent[index][proc_index];
  }
}

double get_percent(int index) {
  if(pw_opts.show_mnemonics) {
    return results->insn_percent[index];
  } else {
    if(index >= ZYDIS_CATEGORY_MAX_VALUE) {
      fprintf(stderr, "Tried to access a per-interval category percent that doesn't exist. Aborting.\n");
      exit(1);
    }
    return results->cat_percent[index];
  }
}

double get_proc_percent(int proc_index, int index) {
  if(pw_opts.show_mnemonics) {
    return results->proc_insn_percent[index][proc_index];
  } else {
    if(index >= ZYDIS_CATEGORY_MAX_VALUE) {
      fprintf(stderr, "Tried to access a per-interval category percent that doesn't exist. Aborting.\n");
      exit(1);
    }
    return results->proc_cat_percent[index][proc_index];
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
    case QSORT_PID: \
      set = results->proc_num_samples[val]; \
      break; \
    case QSORT_CAT_PERCENT: \
      set = results->cat_percent[val]; \
      break; \
    case QSORT_INSN_PERCENT: \
      set = results->insn_percent[val]; \
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

#define filter_name(i) \
  if(pw_opts.filter_string) { \
    if(strncmp(pw_opts.filter_string, \
               get_name(i), \
               strlen(get_name(i)) > pw_opts.filter_string_len ? pw_opts.filter_string_len : strlen(get_name(i))) \
               != 0) { \
        continue; \
    } \
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

#ifdef TMA

#else
int *sort_interval_cats(int *num_cats) {
  int *cats, cat, i;
  
  /*  Count the number of categories that actually have values */
  *num_cats = 0;
  for(i = 0; i < ZYDIS_CATEGORY_MAX_VALUE; i++) {
    if(results->interval->cat_count[i] == 0) {
      continue;
    }
    filter_name(i);
    (*num_cats)++;
  }
  
  if(*num_cats == 0) {
    return NULL;
  }
  
  /* Make an array of all non-zero categories */
  cats = malloc(sizeof(int) * (*num_cats));
  if(!cats) {
    fprintf(stderr, "Failed to allocate memory! Aborting.\n");
    exit(1);
  }
  cat = 0;
  for(i = 0; i < ZYDIS_CATEGORY_MAX_VALUE; i++) {
    if(results->interval->cat_count[i] == 0) {
      continue;
    }
    filter_name(i);
    cats[cat++] = i;
  }
  
  quicksort(cats, QSORT_INTERVAL_CAT_PERCENT, 0, cat - 1);
  
  return cats;
}

int *sort_interval_insns(int *num_insns) {
  int *insns, insn, i;
  
  /*  Count the number of instructions that actually have values */
  *num_insns = 0;
  for(i = 0; i < ZYDIS_MNEMONIC_MAX_VALUE; i++) {
    if(results->interval->insn_count[i] == 0) {
      continue;
    }
    filter_name(i);
    (*num_insns)++;
  }
  
  if(*num_insns == 0) {
    return NULL;
  }
  
  /* Allocate the return array */
  insns = malloc(sizeof(int) * (*num_insns));
  if(!insns) {
    fprintf(stderr, "Failed to allocate memory! Aborting.\n");
    exit(1);
  }
  
  /* Fill in the indices into the return array */
  insn = 0;
  for(i = 0; i < ZYDIS_MNEMONIC_MAX_VALUE; i++) {
    if(results->interval->insn_count[i] == 0) {
      continue;
    }
    filter_name(i);
    insns[insn++] = i;
  }
  
  /* Sort the indices by the chosen metric */
  quicksort(insns, QSORT_INTERVAL_INSN_PERCENT, 0, insn - 1);
  
  return insns;
}

int *sort_cats(int *num_cats) {
  int *cats, cat, i;
  
  /*  Count the number of categories that actually have values */
  *num_cats = 0;
  for(i = 0; i < ZYDIS_CATEGORY_MAX_VALUE; i++) {
    if(results->cat_percent[i] == 0) {
      continue;
    }
    filter_name(i);
    (*num_cats)++;
  }
  
  if(*num_cats == 0) {
    return NULL;
  }
  
  /* Make an array of all non-zero categories */
  cats = malloc(sizeof(int) * (*num_cats));
  if(!cats) {
    fprintf(stderr, "Failed to allocate memory! Aborting.\n");
    exit(1);
  }
  cat = 0;
  for(i = 0; i < ZYDIS_CATEGORY_MAX_VALUE; i++) {
    if(results->cat_percent[i] == 0) {
      continue;
    }
    filter_name(i);
    cats[cat++] = i;
  }
  
  quicksort(cats, QSORT_CAT_PERCENT, 0, cat - 1);
  
  return cats;
}

int *sort_insns(int *num_insns) {
  int *insns, insn, i;
  
  /*  Count the number of instructions that actually have values */
  *num_insns = 0;
  for(i = 0; i < ZYDIS_MNEMONIC_MAX_VALUE; i++) {
    if(results->insn_count[i] == 0) {
      continue;
    }
    filter_name(i);
    (*num_insns)++;
  }
  
  if(*num_insns == 0) {
    return NULL;
  }
  
  insns = malloc(sizeof(int) * (*num_insns));
  if(!insns) {
    fprintf(stderr, "Failed to allocate memory! Aborting.\n");
    exit(1);
  }
  insn = 0;
  for(i = 0; i < ZYDIS_MNEMONIC_MAX_VALUE; i++) {
    if(results->insn_count[i] == 0) {
      continue;
    }
    filter_name(i);
    insns[insn++] = i;
  }
  
  quicksort(insns, QSORT_INSN_PERCENT, 0, insn - 1);
  
  return insns;
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
  
  for(i = 0; i < ZYDIS_CATEGORY_MAX_VALUE; i++) {
    if(!(results->num_samples)) continue;
    results->cat_percent[i] = ((double) results->cat_count[i]) / results->num_samples * 100;
    if(!(results->interval->num_samples)) continue;
    results->interval->cat_percent[i] = ((double) results->interval->cat_count[i]) / results->interval->num_samples * 100;
    for(n = 0; n < results->interval->proc_arr_size; n++) {
      if(!(results->interval->proc_num_samples[n])) continue;
      results->interval->proc_cat_percent[i][n] = ((double) results->interval->proc_cat_count[i][n]) / results->interval->proc_num_samples[n] * 100;
    }
  }
  
  for(i = 0; i < ZYDIS_MNEMONIC_MAX_VALUE; i++) {
    if(!(results->num_samples)) continue;
    results->insn_percent[i] = ((double) results->insn_count[i]) / results->num_samples * 100;
    if(!(results->interval->num_samples)) continue;
    results->interval->insn_percent[i] = ((double) results->interval->insn_count[i]) / results->interval->num_samples * 100;
    for(n = 0; n < results->interval->proc_arr_size; n++) {
      if(!(results->interval->proc_num_samples[n])) continue;
      results->interval->proc_insn_percent[i][n] = ((double) results->interval->proc_insn_count[i][n]) / results->interval->proc_num_samples[n] * 100;
    }
  }
}

/**
  calculate_percentages
  **
  For each instruction category and mnemonic, calculate:
  1. Systemwide percentages.
  2. Per-process percentages.
**/
void calculate_percentages() {
  int i, n;
  
  for(i = 0; i < ZYDIS_CATEGORY_MAX_VALUE; i++) {
    if(!(results->num_samples)) continue;
    results->cat_percent[i] = ((double) results->cat_count[i]) / results->num_samples * 100;
    for(n = 0; n < results->proc_arr_size; n++) {
      if(!(results->proc_num_samples[n])) continue;
      results->proc_cat_percent[i][n] = ((double) results->proc_cat_count[i][n]) / results->proc_num_samples[n] * 100;
    }
  }
  
  for(i = 0; i < ZYDIS_MNEMONIC_MAX_VALUE; i++) {
    if(!(results->num_samples)) continue;
    results->insn_percent[i] = ((double) results->insn_count[i]) / results->num_samples * 100;
    for(n = 0; n < results->proc_arr_size; n++) {
      if(!(results->proc_num_samples[n])) continue;
      results->proc_insn_percent[i][n] = ((double) results->proc_insn_count[i][n]) / results->proc_num_samples[n] * 100;
    }
  }
}

#endif /* TMA */

#ifndef TMA
/*
Summary
=======

Instructions sampled: X

Top 10 Categories:
  ADD    40.84%
  BINARY 20.23%
  ...
*/
void print_results_summary() {
  int i, n, index,
      *pids, num_pids,
      *sorted_indices, num_indices,
      max_col_len, max_first_col_len,
      len;
  process_t *process;
  
  
  calculate_percentages();
  if(pw_opts.show_mnemonics) {
    sorted_indices = sort_insns(&num_indices);
  } else {
    sorted_indices = sort_cats(&num_indices);
  }
  if(!sorted_indices) {
    return;
  }
  pids = sort_pids(&num_pids);
  if(!pids) {
    free(sorted_indices);
    return;
  }
  
  printf("SUMMARY\n");
  printf("=======\n");
  printf("\n");
  printf("Instructions sampled: %d\n", results->num_samples);
  printf("\n");
  printf("Top 10 ");
  if(pw_opts.show_mnemonics) {
    printf("Mnemonics:\n");
  } else {
    printf("Categories:\n");
  }
  if(num_indices > 10) num_indices = 10;
  if(num_pids > 10) num_pids = 10;
  
  /* Calculate the maximum column lengths */
  max_first_col_len = TASK_COMM_LEN + 1;
  max_col_len = 0;
  for(i = 0; i < num_indices; i++) {
    len = strlen(get_name(sorted_indices[i]));
    if(len > max_col_len) max_col_len = len;
  }
  max_col_len += 2;
  if(max_col_len < 8) max_col_len = 8;
  
  printf("%-*s", max_first_col_len, " ");
  for(i = 0; i < num_indices; i++) {
    printf("%*s", max_col_len, get_name(sorted_indices[i]));
  }
  printf("\n");
  
  for(i = 0; i < num_pids; i++) {
    index = pids[i];
    process = get_process_info_with_index(index);
    if(!process) continue;
    if(!get_proc_num_samples(index)) break;
    
    printf("%-*s", max_first_col_len, process->name);
    for(n = 0; n < num_indices; n++) {
      printf("%*.*lf%%", max_col_len - 1, 2, get_proc_percent(index, sorted_indices[n]));
    }
    printf("\n");
  }
  
  free(sorted_indices);
  free(pids);
  
}
#endif
