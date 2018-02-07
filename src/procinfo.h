#ifndef SNAKE_PROCINFO
#define SNAKE_PROCINFO

#include <sys/types.h>

// Using as opposed to <limits.h> just in case the target system is
// different than the compiled system. Wouldn't lead to vulnerabilities
// but would cut off very long paths or usernames that probably wouldn't
// happen in the first place
#define UID_PATH_BUF (2<<15)

char *get_proc_name(pid_t);
int get_proc_euid(pid_t);
char *get_proc_username(pid_t);
char *get_proc_path(pid_t);

#endif
