/* basic hooking example */
#define SNARE_IMPLEMENTATION
#include "../snare.h"
#include <stdio.h>

int add(int a, int b) { return a + b; }

/* trampoline stored globally for hook access */
snare_t hook = NULL;

int add_hook(int a, int b) {
  printf("add_hook: %d + %d\n", a, b);

  /* cast trampoline back to original signature */
  typedef int (*add_func)(int, int);
  add_func original = (add_func)snare_get_trampoline(hook);

  /* double the result because we can */
  return original(a, b) * 2;
}

int main(void) {
  printf("original: %d\n", add(5, 3));

  printf("creating hook...\n");
  hook = snare_new((void *)add, (void *)add_hook);
  if (!hook) {
    printf("hook creation failed\n");
    return 1;
  }
  printf("hook created, trampoline=%p\n", snare_get_trampoline(hook));

  printf("installing hook...\n");
  snare_install(hook);
  printf("hook installed\n");

  printf("calling hooked function...\n");
  printf("hooked: %d\n", add(5, 3));

  snare_remove(hook);
  printf("unhooked: %d\n", add(5, 3));

  snare_free(hook);
  return 0;
}
