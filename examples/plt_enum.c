/* dump all PLT/IAT entries for the current process */
#define SNARE_IMPLEMENTATION
#include "../libsnare.h"
#include <stdio.h>

int main(void) {
  snare_plt_t *plt;
  unsigned int pos = 0;
  const char *name;
  void **addr;

  if (snare_plt_open(&plt, NULL) != SNARE_PLT_SUCCESS) {
    fprintf(stderr, "snare_plt_open: %s\n", snare_plt_error());
    return 1;
  }

  while (snare_plt_enum(plt, &pos, &name, &addr) == 0) {
    printf("  %-30s %p -> %p\n", name, (void *)addr, *addr);
  }

  snare_plt_close(plt);
  return 0;
}
