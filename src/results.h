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
  int interval_index, index;
  uint32_t hash;
  
  hash = djb2(name);
  update_process_info(pid, name, hash);
  
  /* Store this result in the per-process array */
  interval_index = get_interval_proc_arr_index(pid);
  results->interval->proc_cat_count[cat][interval_index]++;
  results->interval->proc_insn_count[insn][interval_index]++;
  results->interval->proc_num_samples[interval_index]++;
  results->interval->pids[interval_index] = pid;
  
  /* Store this result overall, too */
  index = get_proc_arr_index(pid, name, hash);
  results->proc_cat_count[cat][index]++;
  results->proc_insn_count[insn][index]++;
  results->proc_num_samples[index]++;
}

#ifdef INSNPROF_LEGACY_PERF_BUFFER

static void handle_sample(void *ctx, int cpu, void *data, unsigned int data_sz) {
  struct insn_info *insn_info;
  
  insn_info = data;
  if(ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&results->decoder,
                                                ZYAN_NULL,
                                                insn_info->insn, 15,
                                                &results->decoded_insn))) {
    if(pthread_rwlock_wrlock(&results_lock) != 0) {
      fprintf(stderr, "Failed to grab write lock! Aborting.\n");
      exit(1);
    }
    results->interval->cat_count[results->decoded_insn.meta.category]++;
    results->interval->insn_count[results->decoded_insn.mnemonic]++;
    results->cat_count[results->decoded_insn.meta.category]++;
    results->insn_count[results->decoded_insn.mnemonic]++;
    update_pid(insn_info->pid,
               results->decoded_insn.meta.category,
               results->decoded_insn.mnemonic,
               insn_info->name);
    results->interval->num_samples++;
    results->num_samples++;
    if(pthread_rwlock_unlock(&results_lock) != 0) {
      fprintf(stderr, "Failed to unlock the lock! Aborting.\n");
      exit(1);
    }
  }
}

#else

static int handle_sample(void *ctx, void *data, size_t data_sz) {
  struct insn_info *insn_info;
/*   int i; */
  
  insn_info = data;
  
  /* Print out the instruction bytes for debugging */
/*   for(i = 0; i < 7; i++) { */
/*     printf("%02x ", (unsigned) insn_info->insn[i]); */
/*   } */
/*   printf("\n"); */

  if(ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&results->decoder,
                                                ZYAN_NULL,
                                                insn_info->insn, 15,
                                                &results->decoded_insn))) {
    if(pthread_rwlock_wrlock(&results_lock) != 0) {
      fprintf(stderr, "Failed to grab write lock! Aborting.\n");
      exit(1);
    }
    results->interval->cat_count[results->decoded_insn.meta.category]++;
    results->interval->insn_count[results->decoded_insn.mnemonic]++;
    results->cat_count[results->decoded_insn.meta.category]++;
    results->insn_count[results->decoded_insn.mnemonic]++;
    update_pid((uint32_t) insn_info->pid,
               results->decoded_insn.meta.category,
               results->decoded_insn.mnemonic,
               insn_info->name);
    results->interval->num_samples++;
    results->num_samples++;
    if(pthread_rwlock_unlock(&results_lock) != 0) {
      fprintf(stderr, "Failed to unlock the lock! Aborting.\n");
      exit(1);
    }
  }
/*   else { */
/*     printf("FAILED: "); */
/*     for(i = 0; i < 7; i++) { */
/*       printf("%02x ", (unsigned) insn_info->insn[i]); */
/*     } */
/*     printf("\n"); */
/*   } */
  
  return 0;
}

#endif
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
  
  memset(results->interval->proc_num_samples, 0, results->interval->proc_arr_size * sizeof(int));
  memset(results->interval->pids, 0, results->interval->proc_arr_size * sizeof(uint32_t));
  results->interval->num_samples = 0;
  
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
  for(i = 0; i < ZYDIS_CATEGORY_MAX_VALUE; i++) {
    free(results->interval->proc_cat_count[i]);
    free(results->interval->proc_cat_percent[i]);
    free(results->proc_cat_count[i]);
    free(results->proc_cat_percent[i]);
  }
  for(i = 0; i < ZYDIS_MNEMONIC_MAX_VALUE; i++) {
    free(results->interval->proc_insn_count[i]);
    free(results->interval->proc_insn_percent[i]);
    free(results->proc_insn_count[i]);
    free(results->proc_insn_percent[i]);
  }
  free(results->proc_num_samples);
#endif
  free(results->interval);
  free(results);
}
