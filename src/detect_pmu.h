/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef INSNPROF_DETECT_PMU
#define INSNPROF_DETECT_PMU

#include <stdio.h>

void get_pmu_string(char *pmu_name) {
  FILE *f;
  size_t retval;
  
  f = fopen("/sys/devices/cpu/caps/pmu_name", "r");
  if(!f) {
    fprintf(stderr, "WARNING: Unable to open '/sys/devices/cpu/caps/pmu_name'. Using software events.\n");
    strcpy(pmu_name, "invalid");
    return;
  }
  retval = fread(pmu_name, sizeof(char), 31, f);
  if(retval == 0) {
    fprintf(stderr, "WARNING: Unable to read '/sys/devices/cpu/caps/pmu_name'. Using software events.\n");
    strcpy(pmu_name, "invalid");
    return;
  }
  fclose(f);
}

#endif
