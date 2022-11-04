# libsnare.h

A c/cxx/asm compatible single-header hooking library for x86/x64/arm64. inline hooks and PLT/IAT hooks. linux/windows/macos.

## usage

define `SNARE_IMPLEMENTATION` in exactly one translation unit:

```c
#define SNARE_IMPLEMENTATION
#include "libsnare.h"
```

everywhere else just include it normally.

### cmake

```cmake
include(FetchContent)
FetchContent_Declare(snare GIT_REPOSITORY https://github.com/shdwmtr/libsnare.h GIT_TAG main)
FetchContent_MakeAvailable(snare)

target_link_libraries(your_target PRIVATE snare::snare)
```

## inline hooks

patches the first few bytes of a function with a jmp to your detour. trampoline lets you call the original.

```c
snare_inline_t snare_inline_new(void *src, void *dst);
void snare_inline_free(snare_inline_t hook);
int snare_inline_install(snare_inline_t hook);
int snare_inline_remove(snare_inline_t hook);
int snare_inline_is_installed(snare_inline_t hook);
void *snare_inline_get_trampoline(snare_inline_t hook);
void *snare_inline_read_dst(void *src);
```

```cpp
class snare_inline {
    bool install();
    bool install(void *src, void *dst);
    bool remove();
    void *get_trampoline();
    // scoped_remove / scoped_install RAII helpers
};
```

## PLT/IAT hooks

hooks imports via the GOT/PLT (ELF), IAT (PE), or lazy bind table (Mach-O). no code patching, just pointer swaps.

```c
int snare_plt_open(snare_plt_t **out, const char *filename);
int snare_plt_open_by_handle(snare_plt_t **out, void *handle);
int snare_plt_open_by_address(snare_plt_t **out, void *address);
int snare_plt_enum(snare_plt_t *plt, unsigned int *pos, const char **name, void ***addr);
int snare_plt_replace(snare_plt_t *plt, const char *funcname, void *funcaddr, void **oldfunc);
void snare_plt_close(snare_plt_t *plt);
const char *snare_plt_error(void);
```

```cpp
class snare_plt {
    bool open(const char *filename);
    bool open_by_handle(void *handle);
    bool open_by_address(void *address);
    int enum_next(unsigned int *pos, const char **name, void ***addr);
    bool replace(const char *funcname, void *funcaddr, void **oldfunc);
    void close();
    static const char *error();
};
```

note:
win32 PLT hooks require linking `dbghelp` (`#pragma comment(lib, "dbghelp.lib")` is emitted for MSVC, if you use MSYS2/MinGW, you'll need to link manually. )

## build examples

```bash
cd examples && make
```
