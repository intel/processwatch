/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#pragma once

#include <assert.h>

#define resize_array(ptr, old_size, new_size, datatype, new_value, iterator) \
  ptr = realloc(ptr, new_size * sizeof(datatype)); \
  if(!ptr) { \
    fprintf(stderr, "Failed to allocate more memory! Aborting.\n"); \
    exit(1); \
  } \
  for(iterator = old_size; iterator < new_size; iterator++) { \
    ptr[iterator] = new_value; \
  } \

/**
  grow_interval_proc_arrs: This grows the per-process arrays in
  the `interval_results_t` struct. It ensures that the per-process
  array can store up to `pid_ctr + 1` values.
**/
#define INITIAL_SIZE 64
static void grow_interval_proc_arrs() {
  int old_size, new_size, i, n;
  
  /* We don't need to allocate anything */
  if((results->interval->pid_ctr <= results->interval->proc_arr_size - 1) &&
     (results->interval->proc_arr_size != 0)) {
    return;
  }
  
  /* Figure out the old size and new size */
  old_size = results->interval->proc_arr_size;
  if(old_size == 0) {
    new_size = INITIAL_SIZE;
  } else {
    new_size = (results->interval->proc_arr_size * 2);
  }
  
  /* Per-process totals */
  resize_array(results->interval->proc_percent, old_size, new_size, double, 0, n);
  resize_array(results->interval->proc_failed_percent, old_size, new_size, double, 0, n);
  resize_array(results->interval->proc_num_samples, old_size, new_size, uint64_t, 0, n);
  resize_array(results->interval->proc_num_failed, old_size, new_size, uint64_t, 0, n);
  resize_array(results->interval->pids, old_size, new_size, uint32_t, 0, n);
  
#ifdef TMA
  int x, y;

  resize_array(results->interval->proc_tma_cycles, old_size, new_size, double, 0, n);
  resize_array(results->interval->proc_tma_instructions, old_size, new_size, double, 0, n);
  for(i = 0; i < bpf_info->tma->num_metrics; i++) {
    for(y = 0; y < bpf_info->nr_cpus; y++) {
      for(x = 0; x < bpf_info->tma->metrics[i].num_events; x++) {
        resize_array(bpf_info->tma->metrics[i].proc_vals[y][x], old_size, new_size, double, 0, n);
      }
      resize_array(bpf_info->tma->metrics[i].proc_expr[y], old_size, new_size, te_expr *, NULL, n);
    }
    resize_array(results->interval->proc_tma_metric[i], old_size, new_size, double, 0, n);
  }

#else
  
  /* CATEGORIES */
  for(i = 0; i < ZYDIS_CATEGORY_MAX_VALUE; i++) {
    resize_array(results->interval->proc_cat_count[i], old_size, new_size, uint64_t, 0, n);
    resize_array(results->interval->proc_cat_percent[i], old_size, new_size, double, 0, n);
  }
  
  /* MNEMONICS */
  for(i = 0; i < ZYDIS_MNEMONIC_MAX_VALUE; i++) {
    resize_array(results->interval->proc_insn_count[i], old_size, new_size, uint64_t, 0, n);
    resize_array(results->interval->proc_insn_percent[i], old_size, new_size, double, 0, n);
  }
  
#endif
  
  results->interval->proc_arr_size = new_size;
  
  return;
}

static uint32_t djb2(char *name) {
  uint32_t hash = 5381;
  int c;
  
  while((c = *name++)) {
    hash = ((hash << 5) + hash) + c;
  }
  
  return hash;
}

/**
  get_num_process_info
  **
  Get the number of processes that have been associated with this PID thus far.
**/
static int get_num_process_info(uint32_t pid) {
  int num_procs;
  process_t **ptr;
  process_t **proc_arr;
  
  proc_arr = results->process_info.arr[pid];
  if(!proc_arr) {
    return 0;
  }
  
  num_procs = 0;
  ptr = &(proc_arr[0]);
  while(*ptr) {
    num_procs++;
    ptr++;
  }
  
  return num_procs;
}

/**
  get_interval_process_info
  **
  Gets the process_t pointer for the latest process that's using this PID.
**/
static process_t *get_interval_process_info(uint32_t pid) {
  int num_procs;
  
  num_procs = get_num_process_info(pid);
  if(!num_procs) return NULL;
  return results->process_info.arr[pid][num_procs - 1];
}

/**
  get_process_info
  **
  Returns a process_t to the process with the given PID, hash of the name.
  If not found, returns NULL.
**/
static process_t *get_process_info(uint32_t pid, uint32_t hash) {
  process_t *process;
  process_t **proc_arr;
  int i;
  
  proc_arr = results->process_info.arr[pid];
  if(!proc_arr) {
    return NULL;
  }
  
  /* Iterate over the processes and grab the one whose
     hash matches */
  i = 0;
  process = proc_arr[i];
  while(process) {
    if(process->name_hash == hash) {
      return process;
    }
    process = proc_arr[++i];
  }
  
  return NULL;
}

/**
  update_one_process_info
  **
  We've seen this PID before, but now the process name is different,
  so the OS is reusing PIDs. Add this PID to the array in `process_info`.
**/
static void update_one_process_info(uint32_t pid, char *name, uint32_t hash, int num_procs) {
  process_t *process;
  
  /* Here, we're adding 2 additional elements because
     we need one for the NULL terminator, and another
     for the new process. */
  results->process_info.arr[pid] = realloc(results->process_info.arr[pid],
                                           (num_procs + 2) * sizeof(process_t *));
  process = malloc(sizeof(process_t));
  if(!process) {
    fprintf(stderr, "Failed to allocate memory! Aborting.\n");
    exit(1);
  }
  process->name = strdup(name);
  process->name_hash = hash;
  process->index = results->pid_ctr++;
  results->process_info.arr[pid][num_procs] = process;
  results->process_info.arr[pid][num_procs + 1] = NULL;
}

/**
  add_process_info
  **
  If we haven't seen this PID at all, create a new array of process_t pointers.
**/
static void add_process_info(uint32_t pid, char *name, uint32_t hash) {
  process_t *process;
  
  /* Allocate the new process_t */
  process = malloc(sizeof(process_t));
  if(!process) {
    fprintf(stderr, "Failed to allocate memory! Aborting.\n");
    exit(1);
  }
  process->name = strdup(name);
  process->name_hash = hash;
  process->index = results->pid_ctr++;
  
  /* Now add that process_t to the process_arr_t struct */
  results->process_info.arr[pid] = (process_t **) malloc(sizeof(process_t *) * 2);
  results->process_info.arr[pid][0] = process;
  results->process_info.arr[pid][1] = NULL;
}

static void update_process_info(uint32_t pid, char *name, uint32_t hash) {
  int num_procs;
  process_t *process;
  
  /* First, get the array of process_t pointers. */
  num_procs = get_num_process_info(pid);
  if(num_procs > 0) {
    process = get_process_info(pid, hash);
    if(!process) {
      update_one_process_info(pid, name, hash, num_procs);
    }
  } else {
    add_process_info(pid, name, hash);
  }
  
  /* Update the maximum PID we've seen */
  if(pid > results->process_info.max_pid) {
    results->process_info.max_pid = pid;
  }
}

static int get_interval_proc_arr_index(uint32_t pid) {
  int i;
  
  /* Have we seen this PID this interval? */
  for(i = 0; i < results->interval->pid_ctr; i++) {
    if(results->interval->pids[i] == pid) {
      return i;
    }
  }
  
  /* Increment the counter, thus choosing an index for this process
     in the proc_* arrays. */
  i = results->interval->pid_ctr++;
  grow_interval_proc_arrs();
  
  return i;
}
