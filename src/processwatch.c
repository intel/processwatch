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
#ifdef __aarch64__
#include <capstone/capstone.h>
#elif __x86_64__
#include <Zydis/Zydis.h>
#endif

#include "processwatch.h"

/* This is where results are stored */
results_t *results = NULL;
bpf_info_t *bpf_info = NULL;
pthread_rwlock_t results_lock = PTHREAD_RWLOCK_INITIALIZER;

#ifndef GIT_COMMIT_HASH
#define GIT_COMMIT_HASH "?"
#endif

/*******************************************************************************
*                                    OPTIONS
*******************************************************************************/

static struct option long_options[] = {
  {"help",          no_argument,       0, 'h'},
  {"version",       no_argument,       0, 'v'},
  {"debug",         no_argument,       0, 'd'},
  {"interval",      required_argument, 0, 'i'},
  {"num-intervals", required_argument, 0, 'n'},
  {"csv",           no_argument,       0, 'c'},
  {"pid",           required_argument, 0, 'p'},
  {"mnemonics",     no_argument,       0, 'm'},
  {"extensions",    no_argument,       0, 'e'},
  {"sample-period", required_argument, 0, 's'},
  {"filter",        required_argument, 0, 'f'},
  {"list",          no_argument,       0, 'l'},
  {"btf",           required_argument, 0, 'b'},
  {"all",           no_argument,       0, 'a'},
  {0,               0,                 0, 0}
};

struct pw_opts_t pw_opts;

#ifdef __aarch64__

#define NUM_DEFAULT_COL_STRS 4
#define NUM_DEFAULT_MNEM_COL_STRS 0
static int num_default_col_strs = NUM_DEFAULT_COL_STRS;
static int num_default_mnem_col_strs = NUM_DEFAULT_MNEM_COL_STRS;
static char *default_col_strs[NUM_DEFAULT_COL_STRS] = {
  "HasFPARMv8",
  "HasNEON",
  "HasSVE",
  "HasSVE2"
};
static char *default_mnem_col_strs[NUM_DEFAULT_MNEM_COL_STRS] = {
};
static char *default_ext_col_strs[1];

#elif __x86_64__
  
#define NUM_DEFAULT_COL_STRS 5
#define NUM_DEFAULT_MNEM_COL_STRS 0
#define NUM_DEFAULT_EXT_COL_STRS 6
static int num_default_col_strs = NUM_DEFAULT_COL_STRS;
static int num_default_mnem_col_strs = NUM_DEFAULT_MNEM_COL_STRS;
static int num_default_ext_col_strs = NUM_DEFAULT_EXT_COL_STRS;
static char *default_col_strs[NUM_DEFAULT_COL_STRS] = {
  "SSE",
  "AVX",
  "AVX2",
  "AVX512",
  "AMX_TILE"
};
static char *default_mnem_col_strs[NUM_DEFAULT_MNEM_COL_STRS] = {
};
static char *default_ext_col_strs[NUM_DEFAULT_EXT_COL_STRS] = {
  "BASE",
  "AVX512EVEX",
  "AVX512VEX",
  "AMX_BF16",
  "AMX_INT8",
  "AMX_TILE"
};

#endif

void list_opt() {
  int i;
  
  if(pw_opts.show_mnemonics) {
    printf("Listing all available mnemonics:\n");
    for(i = 0; i <= MNEMONIC_MAX_VALUE; i++) {
#ifdef __aarch64__
      printf("%s\n", cs_insn_name(handle, i));
#elif __x86_64__
      printf("%s\n", ZydisMnemonicGetString(i));
#endif
    }
#ifdef __x86_64__
  } else if(pw_opts.show_extensions) {
    printf("Listing all available extensions:\n");
    for(i = 0; i <= EXTENSION_MAX_VALUE; i++) {
      printf("%s\n", ZydisISAExtGetString(i));
    }
#endif
  } else {
    printf("Listing all available categories:\n");
    for(i = 0; i <= CATEGORY_MAX_VALUE; i++) {
#ifdef __aarch64__
      /* Capstone aarch64 groups aren't consecutive :( */
      if (cs_group_name(handle, i) != NULL) printf("%s\n", cs_group_name(handle, i));
#elif __x86_64__
      printf("%s\n", ZydisCategoryGetString(i));
#endif
    }
  }
}

void convert_col_strs() {
  int i, n, found, max_value;
  const char *name;
  
  /* Convert col_strs to an array of the ZydisInstructionCategory or ZydisMnemonic enum. */
  if(pw_opts.show_mnemonics) {
    max_value = MNEMONIC_MAX_VALUE;
#ifdef __x86_64__
  } else if(pw_opts.show_extensions) {
    max_value = EXTENSION_MAX_VALUE;
#endif
  } else {
    max_value = CATEGORY_MAX_VALUE;
  }
  
  for(i = 0; i < pw_opts.col_strs_len; i++) {
    for(n = 0; n <= max_value; n++) {
      found = 0;
      if(pw_opts.show_mnemonics) {

#ifdef __aarch64__
        name = cs_insn_name(handle, n);
#elif __x86_64__
        name = ZydisMnemonicGetString(n);
      } else if(pw_opts.show_extensions) {
        name = ZydisISAExtGetString(n);
#endif
      } else {
#ifdef __aarch64__
        name = cs_group_name(handle, n);
#elif __x86_64__
        name = ZydisCategoryGetString(n);
#endif
      }
      if(name && strncasecmp(pw_opts.col_strs[i], name, strlen(pw_opts.col_strs[i])) == 0) {
        found = 1;
        pw_opts.cols_len++;
        pw_opts.cols = realloc(pw_opts.cols, sizeof(int) * pw_opts.cols_len);
        pw_opts.cols[pw_opts.cols_len - 1] = n;
        break;
      }
    }
    if(!found) {
      fprintf(stderr, "WARNING: Didn't recognize instruction mnemonic/category/extension: %s\n", pw_opts.col_strs[i]);
    }
  }
}

#ifdef __aarch64__
int aarch_get_num_cols() {
  int i, retval;
  
  /* Needed because Capstone's enums aren't consecutive, and their
     final value also isn't the final value (it's the final value + 1). */
  retval = 0;
  if(pw_opts.show_mnemonics) {
    for(i = 0; i <= MNEMONIC_MAX_VALUE; i++) {
      if(cs_insn_name(handle, i) == NULL) continue;
      retval++;
    }
  } else {
    for(i = 0; i <= CATEGORY_MAX_VALUE; i++) {
      if(cs_group_name(handle, i) == NULL) continue;
      retval++;
    }
  }
  
  return retval;
}
#endif

#ifdef __x86_64__
int x86_get_num_cols() {
  int retval;
  
  if(pw_opts.show_mnemonics) {
    retval = MNEMONIC_MAX_VALUE + 1;
  } else if(pw_opts.show_extensions) {
    retval = EXTENSION_MAX_VALUE + 1;
  } else {
    retval = CATEGORY_MAX_VALUE + 1;
  }
  
  return retval;
}
#endif

void free_opts() {
  int i;
  
  if((pw_opts.col_strs != default_col_strs) &&
     (pw_opts.col_strs != default_mnem_col_strs) &&
     (pw_opts.col_strs != default_ext_col_strs)) {
    for(i = 0; i < pw_opts.col_strs_len; i++) {
      free(pw_opts.col_strs[i]);
    }
    free(pw_opts.col_strs);
  }
}

int read_opts(int argc, char **argv) {
  int option_index, index, elem;
  size_t size;
  int c;

  pw_opts.interval_time = 2;
  pw_opts.num_intervals = 0;
  pw_opts.pid = -1;
  pw_opts.show_mnemonics = 0;
  pw_opts.show_extensions = 0;
  pw_opts.csv = 0;
  pw_opts.btf_custom_path = NULL;
  pw_opts.debug = 0;
  pw_opts.sample_period = 100000;

  /* Column filters */
  pw_opts.col_strs = NULL;
  pw_opts.col_strs_len = 0;
  pw_opts.cols = NULL;
  pw_opts.cols_len = 0;
  pw_opts.list = 0;
  
  while(1) {
    option_index = 0;
    c = getopt_long(argc, argv, "hvdi:cp:ms:f:ln:b:ea",
                    long_options, &option_index);
    if(c == -1) {
      break;
    }

    switch(c) {
      case 0:
        printf("option %s\n", long_options[option_index].name);
        break;
      case 'v':
        printf("Version: %s\n", GIT_COMMIT_HASH);
        return -1;
        break;
      case 'h':
        printf("usage: processwatch [options]\n");
        printf("\n");
        printf("options:\n");
        printf("  -h          Displays this help message.\n");
        printf("  -v          Displays the version.\n");
        printf("  -i <int>    Prints results every <int> seconds.\n");
        printf("  -n <num>    Prints results for <num> intervals.\n");
        printf("  -c          Prints all results in CSV format to stdout.\n");
        printf("  -p <pid>    Only profiles <pid>.\n");
        printf("  -m          Displays instruction mnemonics, instead of categories.\n");
#ifdef __x86_64__
        printf("  -e          Displays instruction extensions, instead of categories. Only for x86.\n");
#endif
        printf("  -s <samp>   Profiles instructions with a sampling period of <samp>. Defaults to 100000 instructions (1 in 100000 instructions).\n");
#ifdef __aarch64__
        printf("  -f <filter> Can be used multiple times. Defines filters for columns. Defaults to 'FPARMv8', 'NEON', 'SVE' and 'SVE2'.\n");
#elif __x86_64__
        printf("  -f <filter> Can be used multiple times. Defines filters for columns. Defaults to 'AVX', 'AVX2', and 'AVX512'.\n");
#endif
        printf("  -a          Displays a column for each category, mnemonic, or extension. This is a lot of output!\n");
        printf("  -l          Prints a list of all available categories, mnemonics, or extensions.\n");
        printf("  -d          Prints only debug information.\n");
        return -1;
        break;
      case 'b':
        if(pw_opts.btf_custom_path) {
          fprintf(stderr, "Multiple custom BTF files specified! Aborting.\n");
          exit(1);
        }
        size = strlen(optarg);
        pw_opts.btf_custom_path = calloc(size + 1, sizeof(char));
        strncpy(pw_opts.btf_custom_path, optarg, size);
        break;
      case 'i':
        /* Length in seconds of an interval */
        pw_opts.interval_time = strtoul(optarg, NULL, 10);
        break;
      case 'n':
        /* Number of intervals */
        pw_opts.num_intervals = strtoul(optarg, NULL, 10);
        break;
      case 'c':
        pw_opts.csv = 1;
        break;
      case 'p':
        pw_opts.pid = (int) strtoul(optarg, NULL, 10);
        break;
      case 'm':
        pw_opts.show_mnemonics = 1;
        break;
#ifdef __x86_64__
      case 'e':
        pw_opts.show_extensions = 1;
        break;
#endif
      case 's':
        pw_opts.sample_period = strtoul(optarg, NULL, 10);
        break;
      case 'f':
        pw_opts.col_strs_len++;
        pw_opts.col_strs = (char **) realloc(pw_opts.col_strs, sizeof(char *) *
                                             pw_opts.col_strs_len);
        pw_opts.col_strs[pw_opts.col_strs_len - 1] = strdup(optarg);
        break;
      case 'a':
        pw_opts.all = 1;
        break;
      case 'l':
        pw_opts.list = 1;
        break;
      case 'd':
        pw_opts.debug = 1;
        break;
      case '?':
        return -1;
      default:
        return -1;
    }
  }
  
  if(pw_opts.list) {
    list_opt();
    exit(0);
  }
  
  if(pw_opts.all) {
    
    /* Set the number of columns */
    #ifdef __x86_64__
    pw_opts.cols_len = x86_get_num_cols();
    #elif __aarch64__
    pw_opts.cols_len = aarch_get_num_cols();
    #else
    fprintf(stderr, "Invalid architecture! Aborting.\n");
    exit(1);
    #endif
    
    /* Allocate room for the columns */
    pw_opts.cols = realloc(pw_opts.cols, sizeof(int) * pw_opts.cols_len);
    
    /* Loop over all categories/mnemonics/extensions and add them to
       the columns array */
    index = 0;
    elem = 0;
    while(index < pw_opts.cols_len) {
#ifdef __aarch64__
      /* Capstone aarch64 groups aren't consecutive :( */
      if (cs_group_name(handle, elem) == NULL) {
        elem++;
        continue;
      }
#endif
      pw_opts.cols[index] = elem;
      index++;
      elem++;
    }
    
  } else if(pw_opts.col_strs == NULL) {
    /* User didn't specify -f or -a */
    if(pw_opts.show_mnemonics) {
      pw_opts.col_strs = default_mnem_col_strs;
      pw_opts.col_strs_len = num_default_mnem_col_strs;
#ifdef __x86_64__
    } else if(pw_opts.show_extensions) {
      pw_opts.col_strs = default_ext_col_strs;
      pw_opts.col_strs_len = num_default_ext_col_strs;
#endif
    } else {
      pw_opts.col_strs = default_col_strs;
      pw_opts.col_strs_len = num_default_col_strs;
    }
    convert_col_strs();
  } else {
    convert_col_strs();
  }
  
 
  return 0;
}

/*******************************************************************************
*                              THREAD AND SIGNALS
*******************************************************************************/

pthread_t ui_thread_id;

int interval_signal;
static int stopping = 0;
timer_t interval_timer;
double interval_target_time;
struct timespec interval_start,
                interval_end;
                
void ui_thread_stop(int s) {
  timer_delete(interval_timer);
  stopping = 1;
}
                
void ui_thread_interval(int s) {
  if(pthread_rwlock_wrlock(&results_lock) != 0) {
    fprintf(stderr, "Failed to grab the write lock! Aborting.\n");
    exit(1);
  }
  
  calculate_interval_percentages();

  if(pw_opts.debug) {
    results->interval->ringbuf_used = get_ringbuf_used();
  }

  if(sorted_interval) {
    free_sorted_interval();
  }
  
  /* Display the results */
  if(pw_opts.csv) {
    print_csv_interval(stdout);
  } else {
    update_screen(&sorted_interval);
  }
  
  /* Clear out the events to start another interval */
  clear_interval_results();
  
  if(pthread_rwlock_unlock(&results_lock) != 0) {
    fprintf(stderr, "Failed to release the lock! Aborting.\n");
    exit(1);
  }
  
  /* If the user specified a number of intervals to run */
  if(results->interval_num == pw_opts.num_intervals) {
    ui_thread_stop(SIGTERM);
  }
}

/**
  init_interval_signal: Sets up the signal handler to trigger an interval.
*/
int init_interval_signal() {
  struct sigevent sev;
  struct itimerspec its;
  struct sigaction sa;
  sigset_t interval_mask;
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
  its.it_value.tv_sec     = pw_opts.interval_time;
  its.it_value.tv_nsec    = 0;
  its.it_interval.tv_sec  = its.it_value.tv_sec;
  its.it_interval.tv_nsec = its.it_value.tv_nsec;
  if(timer_settime(interval_timer, 0, &its, NULL) == -1) {
    fprintf(stderr, "Error setting the timer. Aborting.\n");
    exit(1);
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
  int sig;
  sigset_t mask;
  
  init_interval_signal();
  
  /* Wait for the user to exit */
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

#ifdef __aarch64__
  enum cs_err cap_err;
  /* Initialise Capstone, which we use to disassemble the instruction */
  cap_err = cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle);
  if (cap_err != CS_ERR_OK) {
    fprintf(stderr, "Failed to initialise Capstone! Aborting.\n");
    exit(1);
  }
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
#endif

  /* Read options */
  retval = read_opts(argc, argv);
  if(retval != 0) {
    return 1;
  }
  
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
  if(pw_opts.csv) {
    print_csv_header(stdout);
  }
  
  /* Start the ui thread, which will collect results
     and, for each interval, render/print the UI. */
  retval = start_ui_thread();
  if(retval != 0) {
    retval = 1;
    goto cleanup;
  }
  
  /* Poll for some new samples */
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
  struct timespec time;
  time.tv_sec = 0;
  time.tv_nsec = 100000000;
  while(stopping == 0) {
    ring_buffer__consume(bpf_info->rb);
    nanosleep(&time, NULL);
  }
#endif

  /* Send the stop signal to the profiling thread,
     then wait for it to close successfully. */
  pthread_kill(ui_thread_id, SIGTERM);
  pthread_join(ui_thread_id, NULL);
  
cleanup:
  deinit_bpf_info();
  deinit_results();
  free_opts();
  return retval;
}
