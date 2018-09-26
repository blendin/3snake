#ifndef SNAKE_HELPERS
#define SNAKE_HELPERS
#include <time.h>

#define debug(x...) fprintf(stderr,x)

#define fatal(x...) { \
fprintf(stderr, "[-] ERROR: " x); \
exit(1); \
}\

#define output(x...) { \
fprintf(stderr, "[%s] %d %d %s\t", process_username, (int)time(0), process_pid, process_name);\
fprintf(stderr, x);\
}\

#endif
