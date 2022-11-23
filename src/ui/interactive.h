#pragma once

#include <ncurses.h>
#include "utils.h"

static WINDOW *res;
static WINDOW *head;
static WINDOW *scr;

static char screen_paused = 0;
static int  pid_col_width = 8;
static int  name_col_width = 16;
static int  col_width = 8;
static int  cols_fit = 0;
static int  rows_fit = 0;
static int  tot_screen_width = 0;
static int  tot_screen_height = 0;
static int  num_cols = -1;
static int  first_col = -1;
static int  last_col = -1;
static int  first_row = -1;
static int  last_row = -1;

#define HEADER_FORMAT "Sample Rate: %u | Interval Time: %u | "

/* The sorted_interval struct stores the sorted
   indices, PIDs, and process names of all
   processes that we're displaying this interval.
   We store this information so that, on successive
   intervals, we can recall the exact order in which
   we displayed the processes (in the case of the user
   pausing the interface). We regenerate this struct when
   we want to display a regular (non-paused) interval. */
struct sorted_interval {
  int *indices, *pid_indices,
      *pids, num_pids;
  char **proc_names;
};
static struct sorted_interval *sorted_interval = NULL;

void print_header() {
  attron(A_REVERSE);
  move(0, 0);
  printw("%-*s", tot_screen_width, " ");
  move(0, 0);
  printw(HEADER_FORMAT, pw_opts.sample_period, pw_opts.interval_time);
  if(screen_paused) {
    printw("Press 'r' to resume");
  } else {
    printw("Press an arrow key to pause");
  }
}

int check_screen(int row, int col) {
  if(row <= 2) {
    return -1;
  }
  return 0;
}

int init_screen() {
  
  /* Initializing the screen here, per ncurses documentation,
     will cause a "still reachable" memory leak. This is
     unavoidable as a user of the ncurses library. */
  scr = initscr();
  raw();
  keypad(stdscr, TRUE);
  noecho();
  
  /* This display optimizes for 80-column screens,
     but can use less with sub-optimal results */
  getmaxyx(stdscr, tot_screen_height, tot_screen_width);
  if(check_screen(tot_screen_height, tot_screen_width) != 0) {
    return -1;
  }
  
  head = newwin(1, tot_screen_width, 1, 0);
  res = newwin(tot_screen_height - 2, tot_screen_width, 2, 0);
  
  /* Print the program name and version at the top */
  print_header();
  
  wattron(head, A_REVERSE);
  wprintw(head, "%-6s  %-16s", "PID", "NAME");
  wprintw(head, "  ");
  wprintw(res, "Waiting one interval length...");
  
  first_col = 0;
  first_row = 0;
  
  refresh();
  wrefresh(head);
  wrefresh(res);
  
  return 0;
}

void update_screen(struct sorted_interval **sortint_arg) {
  int i, n,
      cur_x, cur_y, index;
  process_t *process;
  
  struct sorted_interval *sortint = *sortint_arg;
  
  /* Clear the results on screen */
  werase(head);
  werase(res);
  
  print_header();
  
  /* If the user passes in NULL, initialize and sort.
     If it's a valid pointer instead, leave it alone */
  if(!sortint) {
    sortint = malloc(sizeof(struct sorted_interval));
    if(!sortint) {
      fprintf(stderr, "Failed to allocate memory! Aborting.\n");
      exit(1);
    }
    
#ifdef TMA

    num_cols = bpf_info->tma->num_metrics;
    sortint->indices = malloc(sizeof(int) * num_cols);
    if(!(sortint->indices)) {
      fprintf(stderr, "Failed to allocate memory! Aborting.\n");
      exit(1);
    }
    for(i = 0; i < num_cols; i++) {
      sortint->indices[i] = i;
    }
    
#else

    /* Get a sorted array of mnemonics or categories */
    if(pw_opts.show_mnemonics) {
      sortint->indices = sort_interval_insns(&num_cols);
    } else {
      sortint->indices = sort_interval_cats(&num_cols);
    }
    if(!sortint->indices) {
      /* If wee haven't got anything to print, do nothing */
      free(sortint->indices);
      free(sortint);
      return;
    }
    
#endif
    
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
  
  /* Calculate the number of columns that we can fit */
  getmaxyx(stdscr, tot_screen_height, tot_screen_width);
  cols_fit = tot_screen_width - pid_col_width - name_col_width - 1;
  cols_fit /= (col_width + 1);
  
  /* Make sure last_col is initialized and reasonable */
  last_col = first_col + cols_fit - 1;
  if(last_col > (num_cols - 1)) {
    last_col = num_cols - 1;
  }
  
  /* Figure out how many rows of PIDs we can print */
  rows_fit = tot_screen_height - 3;
  last_row = first_row + rows_fit - 1;
  if(last_row > sortint->num_pids - 1) {
    last_row = sortint->num_pids - 1;
  }
  
  /* Print the header */
  wprintw(head, "%-*s %-*s", pid_col_width, "PID", name_col_width, "NAME");
  for(i = first_col; i <= last_col; i++) {
    wprintw(head, " ");
    wprintw(head, "%-*.*s", col_width, col_width, get_name(sortint->indices[i]));
  }
  
  /* Print empty characters to the end of the line if
     there are more columns to the right */
  if(last_col != (num_cols - 1)) {
    getyx(head, cur_y, cur_x);
    wprintw(head, "%-*s", tot_screen_width - cur_y, " ");
  }
  
  wprintw(res, "%-*s ", pid_col_width, "ALL");
  wprintw(res, "%-*s", name_col_width, "ALL");
  for(i = first_col; i <= last_col; i++) {
    wprintw(res, " ");
#ifdef TMA
    wprintw(res, "%-*.*lf",
            col_width, 2,
            get_interval_metric(sortint->indices[i]));
#else
    wprintw(res, "%-*.*lf",
            col_width, 2, /* Two digits of precision */
            get_interval_percent(sortint->indices[i]));
#endif
  }
  wprintw(res, "\n");
  
  /* Print one PID per line */
  for(i = first_row; i <= last_row; i++) {
    wprintw(res, "%-*d ", pid_col_width, sortint->pids[i]);
    wprintw(res, "%-*.*s", name_col_width, name_col_width, sortint->proc_names[i]);
    for(n = first_col; n <= last_col; n++) {
      wprintw(res, " ");
#ifdef TMA
      wprintw(res, "%-*.*lf",
              col_width, 2,
              get_interval_proc_metric(sortint->pid_indices[i], sortint->indices[n]));
#else
      wprintw(res, "%-*.*lf",
              col_width, 2,
              get_interval_proc_percent(sortint->pid_indices[i], sortint->indices[n]));
#endif
    }
    wprintw(res, "\n");
  }
  
  refresh();
  wrefresh(res);
  wrefresh(head);
}

void pause_screen() {
  screen_paused = 1;
  print_header();
}

void left_scroll_screen() {
  pause_screen();
  first_col--;
  if(first_col < 0) {
    first_col = 0;
    return;
  }
  update_screen(&sorted_interval);
}

void right_scroll_screen() {
  pause_screen();
  if((num_cols == -1) || (first_col == -1) || (last_col == -1)) {
    return;
  }
  if((first_col + cols_fit) >= num_cols) {
    return;
  }
  first_col++;
  update_screen(&sorted_interval);
}

void down_scroll_screen() {
  pause_screen();
  if((sorted_interval->num_pids == -1) || (first_row == -1) || (last_row == -1)) {
    return;
  }
  if((first_row + rows_fit) >= sorted_interval->num_pids) {
    return;
  }
  first_row++;
  update_screen(&sorted_interval);
}

void up_scroll_screen() {
  pause_screen();
  first_row--;
  if(first_row < 0) {
    first_row = 0;
    return;
  }
  update_screen(&sorted_interval);
}

void free_sorted_interval() {
  int i;
  
  free(sorted_interval->pids);
  free(sorted_interval->indices);
  for(i = 0; i < sorted_interval->num_pids; i++) {
    free(sorted_interval->proc_names[i]);
  }
  free(sorted_interval->proc_names);
  free(sorted_interval->pid_indices);
  free(sorted_interval);
  sorted_interval = NULL;
}

void resume_screen() {
  screen_paused = 0;
  first_col = 0;
  first_row = 0;
  free_sorted_interval();
  update_screen(&sorted_interval);
}

void deinit_screen() {
  int i;
  
  delwin(head);
  delwin(res);
  delwin(scr);
  endwin();
  
  if(sorted_interval) {
    free(sorted_interval->pids);
    free(sorted_interval->indices);
    for(i = 0; i < sorted_interval->num_pids; i++) {
      free(sorted_interval->proc_names[i]);
    }
    free(sorted_interval->proc_names);
    free(sorted_interval->pid_indices);
    free(sorted_interval);
    sorted_interval = NULL;
  }
}
