#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "ssh_tracer.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  char *x = (char *) malloc(sizeof(uint8_t) * Size);
  memcpy(x, (char *)Data, Size);

  char *r = find_password_write(x, Size);
  free(r);
  free(x);
  return 0;
}
