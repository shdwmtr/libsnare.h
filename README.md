# snare.h

single-header x86/x64/arm64 inline function hooking library

## features

- header-only, drop it in and go
- x86, x86-64, arm64 support
- linux/windows/macos
- trampoline generation for calling original functions
- c and c++ apis

## Usage

define `SNARE_IMPLEMENTATION` in exactly one translation unit:

```c
#define SNARE_IMPLEMENTATION
#include "snare.h"
```

everywhere else just include it normally.

## API

### C

```c
snare_t snare_new(void* src, void* dst);
void snare_free(snare_t hook);
int snare_install(snare_t hook);
int snare_remove(snare_t hook);
int snare_is_installed(snare_t hook);
void* snare_get_trampoline(snare_t hook);
void* snare_read_dst(void* src);
```

### C++

```cpp
class snare {
    bool install();
    bool remove();
    void* get_trampoline();
    // ... + scoped_remove/scoped_install RAII helpers
};
```

## Build Examples

```bash
cd examples && make
./basic
./raii
./inline_check
```

## How It Works

- allocates executable trampoline page
- disassembles first N bytes of target (>= 5 bytes for jmp on x86)
- copies instructions to trampoline with relocation fixups
- patches target with jmp to hook function
- trampoline jumps back to target+N

## License

BSD 2-Clause
