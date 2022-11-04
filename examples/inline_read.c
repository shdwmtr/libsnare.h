/* check if function is already hooked and read destination */
#define SNARE_IMPLEMENTATION
#include "../libsnare.h"
#include <stdio.h>

int target(int x) { return x * 2; }
int hook_func(int x) { return x * 3; }

int main(void) {
  void *existing = snare_inline_read_dst((void *)target);
  if (existing) {
    printf("target already hooked to %p\n", existing);
  } else {
    printf("target not hooked\n");
  }

  snare_inline_t hook = snare_inline_new((void *)target, (void *)hook_func);
  snare_inline_install(hook);

  void *dst = snare_inline_read_dst((void *)target);
  printf("target now hooked to %p (expected %p)\n", dst, (void *)hook_func);

  snare_inline_remove(hook);
  snare_inline_free(hook);

  existing = snare_inline_read_dst((void *)target);
  printf("after removal: %s\n", existing ? "still hooked" : "unhooked");

  return 0;
}
