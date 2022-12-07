/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>

#include "processwatch.h"

/* This is where results are stored */
results_t *results = NULL;
bpf_info_t *bpf_info = NULL;
pthread_rwlock_t results_lock = PTHREAD_RWLOCK_INITIALIZER;

/*******************************************************************************
*                                    OPTIONS
*******************************************************************************/

static struct option long_options[] = {
  {"interval",      required_argument, 0, 'i'},
  {"csv",           required_argument, 0, 'c'},
  {"pid",           required_argument, 0, 'p'},
  {"mnemonics",     no_argument,       0, 'm'},
  {"sample-period", required_argument, 0, 's'},
  {"filter",        required_argument, 0, 'f'},
  {"time",          required_argument, 0, 't'},
  {"help",          no_argument,       0, 'h'},
  {0,               0,                 0, 0}
};

struct pw_opts_t pw_opts;

void free_opts() {
  if(pw_opts.csv_filename) {
    free(pw_opts.csv_filename);
  }
  if(pw_opts.filter_string) {
    free(pw_opts.filter_string);
  }
}

int read_opts(int argc, char **argv) {
  int option_index, i;
  char c;

  pw_opts.interval_time = 2000;
  pw_opts.csv_filename = NULL;
  pw_opts.csv_file = NULL;
  pw_opts.pid = -1;
  pw_opts.show_mnemonics = 0;
  
#ifdef TMA
  pw_opts.sample_period = 10000;
#else
  pw_opts.sample_period = 10000;
#endif
  pw_opts.filter_string = NULL;
  pw_opts.filter_string_len = 0;
  pw_opts.runtime = -1;

  while(1) {
    option_index = 0;
    c = getopt_long(argc, argv, "i:c:p:ms:f:t:h",
                    long_options, &option_index);
    if(c == -1) {
      break;
    }

    switch(c) {
      case 0:
        printf("option %s\n", long_options[option_index].name);
        break;
      case 'h':
        printf("usage: insnprof [options]\n");
        printf("\n");
        printf("options:\n");
        printf("  -h          Displays this help message.\n");
        printf("  -i <len>    Prints results every <len> milliseconds.\n");
        printf("  -c <csv>    Prints all results in CSV format to the file <csv>.\n");
        printf("  -p <pid>    Only profiles <pid>.\n");
        printf("  -m          Displays instruction mnemonics, instead of categories.\n");
        printf("  -s <samp>   Profiles instructions with a sampling period of <samp>.\n");
        printf("  -f <insn>   Only shows the (case insensitive) mnemonic or category <insn>.\n");
        printf("  -t <time>   When used in CSV mode, limits execution time to <time> seconds.\n");
        return -1;
        break;
      case 'i':
        /* Length in milliseconds of an interval */
        pw_opts.interval_time = strtoul(optarg, NULL, 10);
        break;
      case 'c':
        /* The filename of the CSV you want to print */
        if(pw_opts.csv_filename) {
          free(pw_opts.csv_filename);
        }
        pw_opts.csv_filename = strdup(optarg);
        if(!pw_opts.csv_filename) {
          fprintf(stderr, "Failed to allocate memory! Aborting.\n");
          exit(1);
        }
        break;
      case 'p':
        pw_opts.pid = (int) strtoul(optarg, NULL, 10);
        break;
      case 'm':
        pw_opts.show_mnemonics = 1;
        break;
      case 's':
        pw_opts.sample_period = strtoul(optarg, NULL, 10);
        break;
      case 'f':
        if(pw_opts.filter_string) {
          free(pw_opts.filter_string);
        }
        pw_opts.filter_string = strdup(optarg);
        if(!pw_opts.filter_string) {
          fprintf(stderr, "Failed to allocate memory! Aborting.\n");
          exit(1);
        }
        pw_opts.filter_string_len = strlen(pw_opts.filter_string);
        break;
      case 't':
        pw_opts.runtime = strtoul(optarg, NULL, 10);
        break;
      case '?':
        return -1;
      default:
        return -1;
    }
  }
  
  /*
     In order to speed up string comparison later, we want to:
       1. Convert the filter string to lowercase if mnemonics are being used.
       2. Convert the filter string to uppercase if categories are being used.
  */
  if(pw_opts.show_mnemonics) {
    for(i = 0; i < pw_opts.filter_string_len; i++) {
      pw_opts.filter_string[i] = tolower(pw_opts.filter_string[i]);
    }
  } else {
    for(i = 0; i < pw_opts.filter_string_len; i++) {
      pw_opts.filter_string[i] = toupper(pw_opts.filter_string[i]);
    }
  }

  return 0;
}

/*******************************************************************************
*                              THREAD AND SIGNALS
*******************************************************************************/

pthread_t ui_thread_id;

int interval_signal;
static int stopping = 0;
timer_t interval_timer, runtime_timer;
double interval_target_time;
struct timespec interval_start,
                interval_end;
                
void ui_thread_interval(int s) {
  if(pthread_rwlock_wrlock(&results_lock) != 0) {
    fprintf(stderr, "Failed to grab the write lock! Aborting.\n");
    exit(1);
  }
  
  if(!screen_paused) {
    
#ifdef TMA
    update_tma_metrics();
#else
    calculate_interval_percentages();
#endif

    if(sorted_interval) {
      free_sorted_interval();
    }
  }
  
  /* Display the results */
  if(pw_opts.csv_file) {
    print_csv_interval(pw_opts.csv_file);
  } else {
    update_screen(&sorted_interval);
  }
  
  /* Clear out the events to start another interval */
  clear_interval_results();
  
  if(pthread_rwlock_unlock(&results_lock) != 0) {
    fprintf(stderr, "Failed to release the lock! Aborting.\n");
    exit(1);
  }
}

void ui_thread_stop(int s) {
  timer_delete(interval_timer);
  if(pw_opts.csv_file && (pw_opts.runtime > 0)) {
    timer_delete(runtime_timer);
  }
  stopping = 1;
}

/**
  init_interval_signal: Sets up the signal handler to trigger an interval.
*/
int init_interval_signal() {
  struct sigevent sev, runtime_sev;
  struct itimerspec its, runtime_its;
  struct sigaction sa;
  sigset_t interval_mask, runtime_mask;
  pid_t tid;
  
  interval_signal = SIGRTMIN;
  
  /* Set up a signal handler for the master.
     The call to sigaddset here blocks the stop signal until an interval is completed. */
  sa.sa_flags = 0;
  sa.sa_handler = ui_thread_interval;
  sigemptyset(&sa.sa_mask);
  if(sigaction(interval_signal, &sa, NULL) == -1) {
    fprintf(stderr, "Error creating interval signal handler. Aborting.\n");
    exit(1);
  }

  /* Block the interval signal */
  sigemptyset(&interval_mask);
  sigaddset(&interval_mask, interval_signal);
  if(sigprocmask(SIG_SETMASK, &interval_mask, NULL) == -1) {
    fprintf(stderr, "Error blocking signal. Aborting.\n");
    exit(1);
  }

  /* Create the interval timer */
  tid = syscall(SYS_gettid);
  sev.sigev_notify = SIGEV_THREAD_ID;
  sev.sigev_signo = interval_signal;
  sev.sigev_value.sival_ptr = &interval_timer;
  sev._sigev_un._tid = tid;
  if(timer_create(CLOCK_REALTIME, &sev, &interval_timer) == -1) {
    fprintf(stderr, "Error creating timer. Aborting.\n");
    exit(1);
  }

  /* Set the interval timer */
  its.it_value.tv_sec     = pw_opts.interval_time / 1000;
  its.it_value.tv_nsec    = (pw_opts.interval_time % 1000) * 1000000;
  its.it_interval.tv_sec  = its.it_value.tv_sec;
  its.it_interval.tv_nsec = its.it_value.tv_nsec;
  if(timer_settime(interval_timer, 0, &its, NULL) == -1) {
    fprintf(stderr, "Error setting the timer. Aborting.\n");
    exit(1);
  }
  
  /* The user specified to run for a certain amount of time.
     Only do this if we're in CSV mode. */
  if(pw_opts.csv_file && (pw_opts.runtime > 0)) {
    /* Block the runtime signal */
    sigemptyset(&runtime_mask);
    sigaddset(&runtime_mask, SIGTERM);
    if(sigprocmask(SIG_SETMASK, &runtime_mask, NULL) == -1) {
      fprintf(stderr, "Error blocking signal. Aborting.\n");
      exit(1);
    }
    
    /* Create the runtime timer */
    runtime_sev.sigev_notify = SIGEV_THREAD_ID;
    runtime_sev.sigev_signo = SIGTERM;
    runtime_sev.sigev_value.sival_ptr = &runtime_timer;
    runtime_sev._sigev_un._tid = tid;
    if(timer_create(CLOCK_REALTIME, &runtime_sev, &runtime_timer) == -1) {
      fprintf(stderr, "Error creating timer. Aborting.\n");
      exit(1);
    }
    
    runtime_its.it_value.tv_sec     = pw_opts.runtime;
    runtime_its.it_value.tv_nsec    = 0;
    runtime_its.it_interval.tv_sec  = runtime_its.it_value.tv_sec;
    runtime_its.it_interval.tv_nsec = runtime_its.it_value.tv_nsec;
    if(timer_settime(runtime_timer, 0, &runtime_its, NULL) == -1) {
      fprintf(stderr, "Error setting the timer. Aborting.\n");
      exit(1);
    }
    
    /* Unblock the runtime signal */
    if(sigprocmask(SIG_UNBLOCK, &runtime_mask, NULL) == -1) {
      fprintf(stderr, "Error unblocking signal. Aborting.\n");
      exit(1);
    }
  }

  /* Initialize the current time so that our first interval
     knows how long it took */
  clock_gettime(CLOCK_MONOTONIC, &(interval_end));
  
  /* Unblock the interval signal */
  if(sigprocmask(SIG_UNBLOCK, &interval_mask, NULL) == -1) {
    fprintf(stderr, "Error unblocking signal. Aborting.\n");
    exit(1);
  }

  return 0;
}

/**
  ui_thread_main: This is the function for the profiling thread.
    It does some setup, then triggers a profiling interval at a given
    rate.
*/
void *ui_thread_main(void *a) {
  int ch, sig;
  sigset_t mask;
  
  init_interval_signal();
  
  /* Wait for the user to exit */
  if(pw_opts.csv_file) {
    /* If we're in CSV mode, wait on SIGTERM */
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    if(sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
      fprintf(stderr, "Error blocking SIGTERM. Aborting.\n");
      exit(1);
    }
    while(sigwait(&mask, &sig) == 0) {
      if(sig == SIGTERM) {
        break;
      }
    }
    /* Make sure we get at least one interval; if
       not intervals have run yet, send the interval signal
       manually */
    if(results->interval_num == 0) {
      pthread_kill(ui_thread_id, interval_signal);
    }
  } else {
    while((ch = getch()) != 'q') {
      switch(ch) {
        case KEY_LEFT:
          left_scroll_screen();
          break;
        case KEY_RIGHT:
          right_scroll_screen();
          break;
        case 'r':
          resume_screen();
          break;
        case KEY_UP:
          up_scroll_screen();
          break;
        case KEY_DOWN:
          down_scroll_screen();
          break;
      }
    }
  }
  ui_thread_stop(SIGTERM);
  
  return NULL;
}

/**
  start_ui_thread: Sets up the stop signal and creates the profiling thread.
*/
int start_ui_thread() {
  int retval;
  sigset_t mask;
  
  /* The main thread should block SIGTERM, so that all
     SIGTERMs go to the UI thread. */
  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);
  if(sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
    fprintf(stderr, "Error blocking signal. Aborting.\n");
    exit(1);
  }
  
  retval = pthread_create(&ui_thread_id, NULL, &ui_thread_main, NULL);
  if(retval != 0) {
    fprintf(stderr, "Failed to call pthread_create. Something is very wrong. Aborting.\n");
    return -1;
  }

  return 0;
}

/*******************************************************************************
*                                  MAIN
*******************************************************************************/

int main(int argc, char **argv) {
  int retval;

  /* Read options */
  retval = read_opts(argc, argv);
  if(retval != 0) {
    return 1;
  }
  
  pw_opts.csv_file = init_csv(pw_opts.csv_filename);
  
  /* Open perf events and start gathering */
  bpf_info = calloc(1, sizeof(bpf_info_t));
  if(!bpf_info) {
    fprintf(stderr, "Failed to allocate memory! Aborting.\n");
    exit(1);
  }
  if(program_events(pw_opts.pid) == -1) {
    retval = 1;
    goto cleanup;
  }
  
  /* Initialize the results struct. */
  init_results();
  
  /* Initialize the UI */
  if(pw_opts.csv_file) {
    print_csv_header(pw_opts.csv_file);
  } else {
    init_screen();
  }
  
  /* Start the ui thread, which will collect results
     and, for each interval, render/print the UI. */
  retval = start_ui_thread();
  if(retval != 0) {
    retval = 1;
    goto cleanup;
  }
  
  /* Poll for some new samples */
#ifndef TMA
  struct timespec time;
#ifdef INSNPROF_LEGACY_PERF_BUFFER
  int err;
  while(stopping == 0) {
    err = perf_buffer__poll(bpf_info->pb, 100);
    if(err < 0) {
      fprintf(stderr, "Failed to poll perf buffer: %d\n", err);
      break;
    }
  }
#else
  time.tv_sec = 0;
  time.tv_nsec = 100000000;
  while(stopping == 0) {
    ring_buffer__consume(bpf_info->rb);
    nanosleep(&time, NULL);
  }
#endif
#endif

  /* Send the stop signal to the profiling thread,
     then wait for it to close successfully. */
  pthread_join(ui_thread_id, NULL);
  if(pw_opts.csv_file) {
    deinit_csv(pw_opts.csv_file);
  } else {
    deinit_screen();
  }
  
#ifndef TMA
  print_results_summary();
#endif

cleanup:
  deinit_bpf_info();
  deinit_results();
  free_opts();
  return retval;
}
