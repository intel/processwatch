/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef INSNPROF_DETECT_PMU
#define INSNPROF_DETECT_PMU

#include <stdio.h>

void get_pmu_string(char *pmu_name) {
  FILE *f;
  
  f = fopen("/sys/devices/cpu/caps/pmu_name", "r");
  if(!f) {
    fprintf(stderr, "WARNING: Unable to properly detect PMU name. Using software events.\n");
    strcpy(pmu_name, "invalid");
    return;
  }
  fread(pmu_name, sizeof(char), 32, f);
  fclose(f);
}

#endif
