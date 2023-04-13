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

void update_screen(struct sorted_interval **sortint_arg) {
  int i, n,
      cur_x, cur_y, index;
  process_t *process;
  
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
  
  /* Print the header */
  printf("\n");
  printf("%-*s %-*s", pid_col_width, "PID", name_col_width, "NAME");
  for(i = 0; i < pw_opts.cols_len; i++) {
    printf(" ");
    printf("%-*.*s", col_width, col_width, get_name(pw_opts.cols[i]));
  }
  printf("\n");
  
  printf("%-*s ", pid_col_width, "ALL");
  printf("%-*s", name_col_width, "ALL");
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
  printf("\n");

  /* Print one PID per line */
  for(i = 0; i < sortint->num_pids; i++) {
    printf("%-*d ", pid_col_width, sortint->pids[i]);
    printf("%-*.*s", name_col_width, name_col_width, sortint->proc_names[i]);
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
