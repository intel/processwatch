/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#pragma once
#include <tinyexpr.h>

#define TMA_SUM_OVER_CORES 0x1
#define TMA_PER_SECOND 0x2
#define TMA_LOW_PRECISION 0x4

struct tma_event_bpf_info_t {
  /* Stores the map fds to read values from BPF */
  int *map_fds, num_map_fds;
  
  /* Metadata pages, which we can use to get the ratio
     of time that this event spent programmed on the PMU.
     We'll scale by this value. */
  struct perf_event_mmap_page **perf_ptrs;
  int num_perf_ptrs;
};

struct tma_metric_bpf_info_t {
  char *name,
       *shortname,
       *str_expr;
  unsigned int flags;
  
  /* This stores a value per event, so that tinyexpr
     can refer to these values to calculate the final metric value */
  te_expr **expr;
  double **vals;
  
  /* Per-PID. First dimension is per-event, second is per-PID */
  te_expr ***proc_expr;
  double ***proc_vals;
  
  /* Each metric includes multiple events */
  struct tma_event_bpf_info_t **events;
  int num_events;
  int event_indices[2];
};

#define NUM_TMA_METRICS 8

static char *icx_tma_event_str =
  "cpu-cycles,"
  "instructions,"
  "cpu/event=0x51,umask=0x01/,"
  "cpu/event=0x24,umask=0xe4/,"
  "cpu/event=0xf1,umask=0x1f/,"
  "cpu/event=0xd1,umask=0x20/,"
  "cpu/event=0xc5,umask=0x00/,"
  "cpu/event=0xc4,umask=0x00/,"
  "cpu/event=0xb7,umask=0x01,config1=0x104000477/,"
  "cpu/event=0xb7,umask=0x01,config1=0x84002380/,"
  "cpu/event=0xb7,umask=0x01,config1=0x730000477/,"
  "cpu/event=0xb7,umask=0x01,config1=0x90002380/";

static struct tma_metric_bpf_info_t icx_tma_metrics[] = {
  {
    "Cycles Per Instruction",
    "CPI",
    "a / b",
    0,
    NULL, NULL,
    NULL, NULL,
    NULL, 2,
    {0, 1},
  },
  {
    "L1D kMPI",
    "L1D kMPI",
    "1000 * a / b",
    0,
    NULL, NULL,
    NULL, NULL,
    NULL, 2,
    {2, 1},
  },
  {
    "L1I kMPI",
    "L1I kMPI",
    "1000 * a / b",
    0,
    NULL, NULL,
    NULL, NULL,
    NULL, 2,
    {3, 1},
  },
  {
    "L2 kMPI",
    "L2 kMPI",
    "1000 * a / b",
    0,
    NULL, NULL,
    NULL, NULL,
    NULL, 2,
    {4, 1},
  },
  {
    "L3 kMPI",
    "L3 kMPI",
    "1000 * a / b",
    0,
    NULL, NULL,
    NULL, NULL,
    NULL, 2,
    {5, 1},
  },
  {
    "RD BW LOCAL",
    "RD BW LOCAL",
    "(a + b) * 64 / 1000000",
    TMA_SUM_OVER_CORES | TMA_PER_SECOND | TMA_LOW_PRECISION,
    NULL, NULL,
    NULL, NULL,
    NULL, 2,
    {8, 9},
  },
  {
    "RD BW REMOTE",
    "RD BW REMOTE",
    "(a + b) * 64 / 1000000",
    TMA_SUM_OVER_CORES | TMA_PER_SECOND | TMA_LOW_PRECISION,
    NULL, NULL,
    NULL, NULL,
    NULL, 2,
    {10, 11},
  },
  {
    "BR MISS",
    "BR MISS",
    "a / b",
    0,
    NULL, NULL,
    NULL, NULL,
    NULL, 2,
    {6, 7},
  },
};

static char *skx_tma_event_str =
  "cpu-cycles,"
  "instructions,"
  "cpu/event=0x51,umask=0x01/,"
  "cpu/event=0x24,umask=0xe4/,"
  "cpu/event=0xf1,umask=0x1f/,"
  "cpu/event=0xd1,umask=0x20/,"
  "cpu/event=0xc5,umask=0x00/,"
  "cpu/event=0xc4,umask=0x00/,";

static struct tma_metric_bpf_info_t skx_tma_metrics[] = {
  {
    "Cycles Per Instruction",
    "CPI",
    "a / b",
    0,
    NULL, NULL,
    NULL, NULL,
    NULL, 2,
    {0, 1},
  },
  {
    "L1D kMPI",
    "L1D kMPI",
    "1000 * a / b",
    0,
    NULL, NULL,
    NULL, NULL,
    NULL, 2,
    {2, 1},
  },
  {
    "L1I kMPI",
    "L1I kMPI",
    "1000 * a / b",
    0,
    NULL, NULL,
    NULL, NULL,
    NULL, 2,
    {3, 1},
  },
  {
    "L2 kMPI",
    "L2 kMPI",
    "1000 * a / b",
    0,
    NULL, NULL,
    NULL, NULL,
    NULL, 2,
    {4, 1},
  },
  {
    "L3 kMPI",
    "L3 kMPI",
    "1000 * a / b",
    0,
    NULL, NULL,
    NULL, NULL,
    NULL, 2,
    {5, 1},
  },
  {
    "BR MISS",
    "BR MISS",
    "a / b",
    0,
    NULL, NULL,
    NULL, NULL,
    NULL, 2,
    {6, 7},
  },
};

struct tma_bpf_info_t {
  /* An eventlist for all metrics' events */
  struct eventlist *el;
  
  /* An array of metrics */
  struct tma_metric_bpf_info_t *metrics;
  int num_metrics;
  
  /* We have a flat array of events, which the metrics
     have pointers into. */
  struct tma_event_bpf_info_t *events;
  int num_events;
};
