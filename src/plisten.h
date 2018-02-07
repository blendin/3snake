#ifndef SNAKE_PLISTEN
#define SNAKE_PLISTEN

#include <stdbool.h>

int nl_connect(void);
int set_proc_ev_listen(int, bool);
void handle_proc_ev(int);
void plisten(void);

#endif
