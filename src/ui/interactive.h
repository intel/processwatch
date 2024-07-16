/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#pragma once

#include "utils.h"

static int  pid_col_width = 8;
static int  name_col_width = 16;
static int  col_width = 8;
static int  cols_fit = 0;
static int  rows_fit = 0;
static int  tot_screen_width = 0;
static int  tot_screen_height = 0;
static char tmp_str[8];

/* The sorted_interval struct stores the sorted
   indices, PIDs, and process names of all
   processes that we're displaying this interval.
   We store this information so that, on successive
   intervals, we can recall the exact order in which
   we displayed the processes (in the case of the user
   pausing the interface). We regenerate this struct when
   we want to display a regular (non-paused) interval. */
struct sorted_interval {
  int *pid_indices,
      *pids, num_pids;
  char **proc_names;
};
static struct sorted_interval *sorted_interval = NULL;

char *truncate_uint64(uint64_t val, char *str, int size) {
  memset(str, 0, size);
  if(val < 10000) {
    /* Less than 10k, just print the whole number */
    snprintf(str, size, "%-*.*" PRIu64, col_width, col_width, val);
  } else if((val >= 10000) && (val < 1000000)) {
    /* More than 10k and less than 1m, add "k" suffix */
    snprintf(str, size, "%" PRIu64 "k", val / 1000);
  } else {
    /* More than 1m, add "m" suffix */
    snprintf(str, size, "%" PRIu64 "m", val / 1000000);
  }
  return str;
}

void update_screen(struct sorted_interval **sortint_arg) {
  int i, n, index;
  process_t *process;
  char *column_name;
  struct sorted_interval *sortint = *sortint_arg;
  
  /* If the user passes in NULL, initialize and sort.
     If it's a valid pointer instead, leave it alone */
  if(!sortint) {
    sortint = malloc(sizeof(struct sorted_interval));
    if(!sortint) {
      fprintf(stderr, "Failed to allocate memory! Aborting.\n");
      exit(1);
    }
    
    /* Sort the PIDs and store them in 'sortint'. */
    sortint->pid_indices = sort_interval_pids(&(sortint->num_pids));
    sortint->pids = calloc(sortint->num_pids, sizeof(int));
    if(!(sortint->pids)) {
      fprintf(stderr, "Failed to allocate memory! Aborting.\n");
      exit(1);
    }
    sortint->proc_names = calloc(sortint->num_pids, sizeof(char *));
    if(!(sortint->proc_names)) {
      fprintf(stderr, "Failed to allocate memory! Aborting.\n");
      exit(1);
    }
    for(i = 0; i < sortint->num_pids; i++) {
      index = sortint->pid_indices[i];
      process = get_interval_process_info(results->interval->pids[index]);
      if(!process) continue;
      if(!get_interval_proc_num_samples(index)) continue;
      sortint->pids[i] = results->interval->pids[index];
      sortint->proc_names[i] = realloc(sortint->proc_names[i],
                                       sizeof(char) * (strlen(process->name) + 1));
      strcpy(sortint->proc_names[i], process->name);
    }
    
    
    *sortint_arg = sortint;
  }
  
  /****************************************************************************
                                    HEADER
  ****************************************************************************/
  printf("\n");
  printf("%-*s %-*s", pid_col_width, "PID", name_col_width, "NAME");
  if(pw_opts.debug) {
    /* Only print debug stuff */
    printf(" %-*.*s", col_width, col_width, "%ERROR");
    printf(" %-*.*s", col_width, col_width, "%RINGBUF");
  } else {
    /* Print chosen instruction groups */
    for(i = 0; i < pw_opts.cols_len; i++) {
      printf(" ");
      column_name = (char*)get_name(pw_opts.cols[i]);
      if (!strncmp(column_name, "Has", 3)) column_name += 3;
      printf("%-*.*s", col_width, col_width, column_name);
    }
  }
  printf(" %-*.*s", col_width, col_width, "%TOTAL");
  printf(" %-*.*s", col_width, col_width, "TOTAL");
  printf("\n");
  
  /****************************************************************************
                                 ALL PIDS
  ****************************************************************************/
  printf("%-*s ", pid_col_width, "ALL");
  printf("%-*s", name_col_width, "ALL");
  if(pw_opts.debug) {
    printf(" %-*.*lf", col_width, 2, get_interval_failed_percent());
    printf(" %-*.*lf", col_width, 2, get_interval_ringbuf_used());
  } else {
    for(i = 0; i < pw_opts.cols_len; i++) {
      printf(" ");
#ifdef TMA
      printf("%-*.*lf",
              col_width, 2,
              get_interval_metric(pw_opts.cols[i]));
#else
      printf("%-*.*lf",
              col_width, 2, /* Two digits of precision */
              get_interval_percent(pw_opts.cols[i]));
#endif
    }
  }
  printf(" %-*.*lf", col_width, 2, 100.0);
  printf(" %-*.*" PRIu64, col_width, 2, get_interval_num_samples());
  printf("\n");

  /****************************************************************************
                                    PER-PID
  ****************************************************************************/
  for(i = 0; i < sortint->num_pids; i++) {
    printf("%-*d ", pid_col_width, sortint->pids[i]);
    printf("%-*.*s", name_col_width, name_col_width, sortint->proc_names[i]);
    if(pw_opts.debug) {
      printf(" %-*.*lf", col_width, 2, get_interval_proc_percent_failed(sortint->pid_indices[i]));
      printf(" %-*.*s", col_width, col_width, "N/A");
    } else {
      for(n = 0; n < pw_opts.cols_len; n++) {
        printf(" ");
#ifdef TMA
  /*       printf("%-*.*lf", */
  /*               col_width, 2, */
  /*               get_interval_proc_metric(sortint->pid_indices[i], sortint->indices[n])); */
#else
        printf("%-*.*lf",
                col_width, 2,
                get_interval_proc_percent(sortint->pid_indices[i], pw_opts.cols[n]));
#endif
      }
    }
    printf(" %-*.*lf", col_width, 2, get_interval_proc_percent_samples(sortint->pid_indices[i]));
    printf(" %-*.*" PRIu64, col_width, 2, get_interval_proc_num_samples(sortint->pid_indices[i]));
    printf("\n");
  }
}

void free_sorted_interval() {
  int i;
  
  free(sorted_interval->pids);
  for(i = 0; i < sorted_interval->num_pids; i++) {
    free(sorted_interval->proc_names[i]);
  }
  free(sorted_interval->proc_names);
  free(sorted_interval->pid_indices);
  free(sorted_interval);
  sorted_interval = NULL;
}

void deinit_screen() {
  int i;
  
  if(sorted_interval) {
    free(sorted_interval->pids);
    for(i = 0; i < sorted_interval->num_pids; i++) {
      free(sorted_interval->proc_names[i]);
    }
    free(sorted_interval->proc_names);
    free(sorted_interval->pid_indices);
    free(sorted_interval);
    sorted_interval = NULL;
  }
}
