/* hook puts() via PLT/IAT */
#define SNARE_IMPLEMENTATION
#include "../libsnare.h"
#include <stdio.h>

static int (*real_puts)(const char *);

int hooked_puts(const char *s) {
  real_puts("[snare] ");
  return real_puts(s);
}

int main(void) {
  snare_plt_t *plt;

  puts("before hook");

  if (snare_plt_open(&plt, NULL) != SNARE_PLT_SUCCESS) {
    fprintf(stderr, "snare_plt_open: %s\n", snare_plt_error());
    return 1;
  }

  snare_plt_replace(plt, "puts", (void *)hooked_puts, (void **)&real_puts);
  puts("after hook");

  /* restore original */
  snare_plt_replace(plt, "puts", (void *)real_puts, NULL);
  puts("restored");

  snare_plt_close(plt);
  return 0;
}
