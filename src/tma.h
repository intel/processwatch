/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#pragma once

#ifdef TMA

#include <sys/resource.h>
#include <dirent.h>
#include <stddef.h>
#include <sys/types.h>
#include <math.h>
#include <float.h>

#include <jevents.h>
#include <jsession.h>
#include <tinyexpr.h>
#include "tma_metrics.h"

int proc_name_buf_size = 32;
static char proc_filename[25];

int get_proc_name(uint32_t pid, char **proc_name_buf) {
  size_t size;
  int old_proc_name_buf_size, total_read;
  FILE *f;
  char *buf;
  
  if(!(*proc_name_buf)) {
    *proc_name_buf = malloc(proc_name_buf_size);
  }
  
  sprintf(proc_filename, "/proc/%d/cmdline", pid);
  f = fopen(proc_filename, "r");
  if(!f) {
    return -1;
  }
  
  /* Read the cmdline into the buffer */
  buf = *proc_name_buf;
  total_read = 0;
  old_proc_name_buf_size = 0;
  while((size = fread(buf, sizeof(char), proc_name_buf_size - old_proc_name_buf_size, f)) != 0) {
    if(size == proc_name_buf_size) {
      /* We've read the full buffer size, so grow it and keep reading.
         Here, we set 'buf' to the newly-grown memory area; we don't want
         to read over what we've already read. */
      old_proc_name_buf_size = proc_name_buf_size;
      proc_name_buf_size *= 2;
      *proc_name_buf = realloc(*proc_name_buf, proc_name_buf_size);
      buf = (*proc_name_buf) + old_proc_name_buf_size;
    }
    total_read += size;
  }
  
  /* Put a null terminator at the end */
  *(*proc_name_buf + total_read) = '\0';
  
  fclose(f);
  return 0;
}


int get_num_open_files() {
  DIR *dp;
  struct dirent *de;
  int count;
  
  count = -3;
  dp = opendir("/proc/self/fd");
  if(dp == NULL) {
    fprintf(stderr, "Failed to open /proc/self/fd. Aborting.\n");
    return -1;
  }

  while((de = readdir(dp)) != NULL) {
    count++;
  }

  closedir(dp);

  return count;
}

int set_maximum_open_files() {
  int needed_files, open_files, i;
  struct rlimit rlim;
  struct event *e;
  
  /* Calculate how many files we'll need */
  needed_files = MAX_PERF_EVENTS * 2 + 1; /* BPF itself */
  for(e = bpf_info->tma->el->eventlist; e; e = e->next) {
    if(e->uncore) {
      needed_files += (bpf_info->tma->el->num_sockets * 2);
    } else {
      needed_files += (bpf_info->tma->el->num_cpus * 2);
    }
  }
  
  /* Calculate how many files we already have open */
  open_files = get_num_open_files();
  if(open_files == -1) {
    return -1;
  }
  needed_files += open_files;
  
  /* Give ourselves some wiggle-room (for example, ncurses needs some file descriptors */
  needed_files += 10;
  
  /* Round up to the nearest power of two */
  needed_files = pow(2, ceil(log(needed_files)/log(2)));
  
  /* Figure out how many open files we're allowed */
  if(getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
    fprintf(stderr, "Failed to call getrlimit. Aborting.\n");
    return -1;
  }
  if(needed_files > rlim.rlim_cur) {
    printf("WARNING: Need to open %d files, but the soft limit is %ju.\n", needed_files,
                                                                           (uintmax_t) rlim.rlim_cur);
    printf("I'll simply try to raise the soft limit.\n");
  }
  if(needed_files > rlim.rlim_max) {
    fprintf(stderr, "Unable to open the required number of files.\n");
    fprintf(stderr, "Try increasing your hard limit with the ulimit command.\n");
    return -1;
  }
  
  rlim.rlim_cur = needed_files;
  if(setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
    fprintf(stderr, "Failed to set the soft limit for the number of open files. Aborting.\n");
    return -1;
  }
  
  return 0;
}
  

static int update_tma_metric(struct tma_metric_bpf_info_t *metric) {
  int i, n, retval, map_fd, index, num_elems;
  struct tma_event_bpf_info_t *event;
  uint64_t lookup_key, next_key, val;
  uint32_t pid, hash, cpu;
  double scale;
  char *proc_name_buf;
  
  proc_name_buf = NULL;
  
  for(i = 0; i < metric->num_events; i++) {
    event = metric->events[i];
    
    for(n = 0; n < event->num_map_fds; n++) {
      map_fd = event->map_fds[n];
      
      /* Get the values out of this map */
      lookup_key = -1;
      num_elems = 0;
      while(!bpf_map_get_next_key(map_fd, &lookup_key, &next_key)) {
        retval = bpf_map_lookup_elem(map_fd, &next_key, &val);
        if(retval < 0) {
          fprintf(stderr, "Failed to lookup elements in event %d in metric %s.\n",
                  i, metric->name);
          return -1;
        }
        pid = next_key >> 32;
        cpu = next_key;
        num_elems++;
        
        /* Get the number that we need to scale by */
        scale = (double) event->perf_ptrs[cpu]->time_enabled /
                         event->perf_ptrs[cpu]->time_running;
        
        /* Update the overall data and the per-PID */
        metric->vals[cpu][i] += (val * scale);

        /* Per process */
        retval = get_proc_name(pid, &proc_name_buf);
        if(retval == -1) {
          /* If the process no longer exists, we can just ignore it */
          lookup_key = next_key;
          continue;
        }
        hash = djb2(proc_name_buf);
        update_process_info(pid, proc_name_buf, hash);
        index = get_interval_proc_arr_index(pid);
        results->interval->proc_num_samples[index]++;
        results->interval->num_samples++;
        results->num_samples++;
        results->interval->pids[index] = pid;
        metric->proc_vals[cpu][i][index] += (val * scale);
        
        lookup_key = next_key;
      }
      
      /* Clear the map */
      lookup_key = -1;
      while (!bpf_map_get_next_key(map_fd, &lookup_key, &next_key)) {
        retval = bpf_map_delete_elem(map_fd, &next_key);
        if (retval < 0) {
          fprintf(stderr, "failed to cleanup infos: %d\n", retval);
          return -1;
        }
        lookup_key = next_key;
      }
    }
  }
  
  return 0;
}

static int update_tma_metrics() {
  int retval, i, n, x, y, nr_cpus_with_samples;
  struct tma_metric_bpf_info_t *metric;
  double val;
  
  /* For programming tinyexpr */
  te_variable *vars;
  char *name, c;
  
  /* Update all per-event and per-PID values for each metric */
  for(i = 0; i < bpf_info->tma->num_metrics; i++) {
    metric = &(bpf_info->tma->metrics[i]);
    retval = update_tma_metric(metric);
    if(retval != 0) {
      fprintf(stderr, "ERROR: Failed to update metric: '%s'.\n", metric->name);
      return retval;
    }
  }
  
  /* Iterate over the metrics */
  for(i = 0; i < bpf_info->tma->num_metrics; i++) {
    metric = &(bpf_info->tma->metrics[i]);
    
    /* We're going to reuse this te_variable array for all PIDs and CPUs */
    vars = calloc(metric->num_events, sizeof(te_variable));
    for(y = 0; y < metric->num_events; y++) {
      vars[y].name = malloc(sizeof(char) * 2);
    }
    
    /* Iterate over the PIDs that we've seen this interval */
    for(n = 0; n < results->interval->pid_ctr; n++) {
      
      /* For this PID, iterate over all the CPUs it could have been on */
      for(x = 0; x < bpf_info->nr_cpus; x++) {
        
        /* Construct a te_variable array with per-CPU values */
        c = 'a';
        for(y = 0; y < metric->num_events; y++) {
          name = (char *) vars[y].name;
          name[0] = c; name[1] = 0;
          vars[y].address = &(metric->proc_vals[x][y][n]);
          c++;
        }
        metric->proc_expr[x][n] = te_compile(metric->str_expr, vars, metric->num_events, &retval);
        if(!metric->proc_expr[x][n]) {
          fprintf(stderr, "Error with a per-process metric expression:\n");
          fprintf(stderr, "  %s\n", metric->str_expr);
          fprintf(stderr, "  %*s^\n", retval - 1, "");
        }
      }
    }
    for(y = 0; y < metric->num_events; y++) {
      free((void *) vars[y].name);
    }
    free(vars);
  }
  
  for(i = 0; i < bpf_info->tma->num_metrics; i++) {
    metric = &(bpf_info->tma->metrics[i]);
    
    /* Per process */
    for(n = 0; n < results->interval->pid_ctr; n++) {
      results->interval->proc_tma_metric[i][n] = 0;
      nr_cpus_with_samples = 0;
      for(x = 0; x < bpf_info->nr_cpus; x++) {
        val = te_eval(metric->proc_expr[x][n]);
        if((val != val) || (val < -DBL_MAX || val > DBL_MAX)) {
          /* If it's not equal to itself, then it's -nan */
          continue;
        }
        nr_cpus_with_samples += 1;
        results->interval->proc_tma_metric[i][n] += val;
      }
      if(!(metric->flags & TMA_SUM_OVER_CORES) && nr_cpus_with_samples) {
        results->interval->proc_tma_metric[i][n] /= nr_cpus_with_samples;
      }
      if((metric->flags & TMA_PER_SECOND)) {
        results->interval->proc_tma_metric[i][n] /= (pw_opts.interval_time / 1000);
      }
    }
    
    /* Overall */
    results->interval->tma_metric[i] = 0;
    nr_cpus_with_samples = 0;
    for(x = 0; x < bpf_info->nr_cpus; x++) {
      val = te_eval(metric->expr[x]);
      if((val != val) || (val < -DBL_MAX || val > DBL_MAX)) {
        /* If it's not equal to itself, then it's -nan */
        continue;
      }
      nr_cpus_with_samples += 1;
      results->interval->tma_metric[i] += val;
    }
    if(!(metric->flags & TMA_SUM_OVER_CORES) && nr_cpus_with_samples) {
      results->interval->tma_metric[i] /= nr_cpus_with_samples;
    }
    if((metric->flags & TMA_PER_SECOND)) {
      results->interval->tma_metric[i] /= (pw_opts.interval_time / 1000);
    }
  }
  
  /* We're going to keep track of instructions and cycles */
  for(n = 0; n < results->interval->pid_ctr; n++) {
    results->interval->proc_tma_instructions[n] = 0;
    results->interval->proc_tma_cycles[n] = 0;
    for(x = 0; x < bpf_info->nr_cpus; x++) {
      results->interval->proc_tma_instructions[n] += bpf_info->tma->metrics[0].proc_vals[x][0][n];
      results->interval->proc_tma_cycles[n] += bpf_info->tma->metrics[0].proc_vals[x][1][n];
    }
  }
  
  return 0;
}

int init_tma() {
  int i, x, y, retval;
  struct tma_metric_bpf_info_t *metric;
  char *jevent_str;
  struct event *e;
  
  /* For programming tinyexpr */
  te_variable *vars;
  char *name, c;
  
  bpf_info->tma = calloc(1, sizeof(struct tma_bpf_info_t));
  
  /* First, select which tma_metric_bpf_info_t array we're using based on the microarch */
  if(strncmp(bpf_info->pmu_name, "skylake", 7) == 0) {
    jevent_str = skx_tma_event_str;
    bpf_info->tma->metrics = skx_tma_metrics;
    bpf_info->tma->num_metrics = sizeof(skx_tma_metrics) / sizeof(struct tma_metric_bpf_info_t);
  } else if(strncmp(bpf_info->pmu_name, "icelake", 7) == 0) {
    jevent_str = icx_tma_event_str;
    bpf_info->tma->metrics = icx_tma_metrics;
    bpf_info->tma->num_metrics = sizeof(icx_tma_metrics) / sizeof(struct tma_metric_bpf_info_t);
  } else {
    jevent_str = skx_tma_event_str;
    bpf_info->tma->metrics = skx_tma_metrics;
    bpf_info->tma->num_metrics = sizeof(skx_tma_metrics) / sizeof(struct tma_metric_bpf_info_t);
  }
  
  read_events(NULL);
  bpf_info->tma->el = alloc_eventlist();
  retval = parse_events(bpf_info->tma->el,
                        jevent_str);
  if(retval < 0) {
    fprintf(stderr, "jevents failed to parse the event string '%s': %d. Aborting.\n",
            jevent_str,
            retval);
    free_eventlist(bpf_info->tma->el);
    return -1;
  }
  
  /* Count the number of unique events in the eventlist */
  bpf_info->tma->num_events = 0;
  for(e = bpf_info->tma->el->eventlist; e; e = e->next) {
    bpf_info->tma->num_events++;
  }
  bpf_info->tma->events = calloc(bpf_info->tma->num_events, sizeof(struct tma_event_bpf_info_t));
  
  for(i = 0; i < bpf_info->tma->num_metrics; i++) {
    metric = &(bpf_info->tma->metrics[i]);
    
    vars = calloc(metric->num_events, sizeof(te_variable));
    metric->expr = malloc(sizeof(te_expr *) * bpf_info->nr_cpus);
    metric->vals = calloc(bpf_info->nr_cpus, sizeof(double *));
    metric->proc_vals = calloc(bpf_info->nr_cpus, sizeof(double **));
    metric->proc_expr = calloc(bpf_info->nr_cpus, sizeof(te_expr **));
    for(x = 0; x < bpf_info->nr_cpus; x++) {
      metric->vals[x] = calloc(metric->num_events, sizeof(double));
      metric->proc_vals[x] = calloc(metric->num_events, sizeof(double *));
    }
    
    /* Initialize each metric's tinyexpr structures */
    for(x = 0; x < bpf_info->nr_cpus; x++) {
      c = 'a';
      for(y = 0; y < metric->num_events; y++) {
        name = malloc(sizeof(char) * 2);
        name[0] = c; name[1] = 0;
        vars[y].name = name;
        vars[y].address = &(metric->vals[x][y]);
        c++;
      }
      metric->expr[x] = te_compile(metric->str_expr, vars, metric->num_events, &retval);
      if(!metric->expr[x]) {
        fprintf(stderr, "Error with a metric expression:\n");
        fprintf(stderr, "  %s\n", metric->str_expr);
        fprintf(stderr, "  %*s^\n", retval - 1, "");
      }
      for(y = 0; y < metric->num_events; y++) {
        free((void *) vars[y].name);
      }
    }
    free(vars);
    
    /* Initialize the array of events. */
    metric->events =
      calloc(metric->num_events, sizeof(struct tma_event_bpf_info_t *));
    for(x = 0; x < metric->num_events; x++) {
      metric->events[x] = &(bpf_info->tma->events[metric->event_indices[x]]);
    }
  }
  
  /* Make sure we're not going to hit any file-open limits */
  if(set_maximum_open_files() < 0) {
    return -1;
  }
  
  return 0;
}

#endif
