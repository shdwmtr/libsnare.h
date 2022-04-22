/* check if function is already hooked and read destination */
#define SNARE_IMPLEMENTATION
#include "../snare.h"
#include <stdio.h>

int target(int x) { return x * 2; }
int hook_func(int x) { return x * 3; }

int main(void) {
  /* check if target is already hooked */
  void *existing = snare_read_dst((void *)target);
  if (existing) {
    printf("target already hooked to %p\n", existing);
  } else {
    printf("target not hooked\n");
  }

  /* install our hook */
  snare_t hook = snare_new((void *)target, (void *)hook_func);
  snare_install(hook);

  /* now read_dst should return our hook address */
  void *dst = snare_read_dst((void *)target);
  printf("target now hooked to %p (expected %p)\n", dst, (void *)hook_func);

  snare_remove(hook);
  snare_free(hook);

  /* verify it's unhooked */
  existing = snare_read_dst((void *)target);
  printf("after removal: %s\n", existing ? "still hooked" : "unhooked");

  return 0;
}
