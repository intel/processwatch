/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef INSNPROF_KERNINFO
#define INSNPROF_KERNINFO

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

#define MINIMUM_ISA_SUPPORT \
    fprintf(stderr, "Failed to parse '/proc/cpuinfo'! Assuming minimum ISA support.\n"); \
    return 0;

/* It's either this, or I call `lscpu` and parse its output. */
char supports_amx_tile() {
  FILE *cpu_info = fopen("/proc/cpuinfo", "r");
  char *buff, *buff2, *buff_orig, found;
  int chars_read;
  size_t n;
  ssize_t nread;
  
  if(cpu_info == NULL) {
    MINIMUM_ISA_SUPPORT;
  }

  buff = NULL;
  found = 0;
  while(!found && !feof(cpu_info)) {
    if(fscanf(cpu_info, "%*[^f]") == EOF) {
      MINIMUM_ISA_SUPPORT;
    }
    found = fscanf(cpu_info, "flags%m[^:]", &buff) == 1;
  }
  fseek(cpu_info, 1, SEEK_CUR);
  free(buff);

  buff = NULL;
  nread = getline(&buff, &n, cpu_info);
  fclose(cpu_info);
  if(nread <= 0) {
    MINIMUM_ISA_SUPPORT;
  }
  buff_orig = buff;

  found = 0;
  while(!found) {
    nread = sscanf(buff, "%ms%n", &buff2, &chars_read);
    if((nread == EOF) || (nread == 0)) {
      break;
    }
    buff += chars_read;
    if(!strcmp(buff2, "amx_tile")) {
      found = 1;
    }
    free(buff2);
  }
  free(buff_orig);
  
  if(found) {
    return 1;
  }
  return 0;
}

#endif
