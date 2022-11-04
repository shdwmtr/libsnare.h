/* C++ RAII wrapper example */
#define SNARE_IMPLEMENTATION
#include "../libsnare.h"
#include <iostream>

extern "C" int multiply(int a, int b) { return a * b; }
snare_inline *hook = nullptr;

extern "C" int multiply_hook(int a, int b)
{
  std::cout << "multiply_hook: " << a << " * " << b << std::endl;
  typedef int (*multiply_func)(int, int);
  multiply_func original = (multiply_func)hook->get_trampoline();

  return original(a, b) + 100;
}

int main()
{
  std::cout << "original: " << multiply(5, 3) << std::endl;

  hook = new snare_inline((void *)multiply, (void *)multiply_hook);
  hook->install();

  std::cout << "hooked: " << multiply(5, 3) << std::endl;

  {
    snare_inline::scoped_remove scoped(hook);
    std::cout << "scoped remove: " << multiply(5, 3) << std::endl;
  }

  std::cout << "re-hooked: " << multiply(5, 3) << std::endl;
  delete hook;

  std::cout << "final: " << multiply(5, 3) << std::endl;
  return 0;
}
