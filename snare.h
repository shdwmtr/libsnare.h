/* Copyright (c) 2026 Ethan Alexander
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SNARE_H
#define SNARE_H
#include <stddef.h>

/* arch detection */
#if defined _M_IX86 || defined __i386__
#define SNARE_X86
#define SNARE_BITS 32
#elif defined _M_AMD64 || __amd64__
#define SNARE_X86_64
#define SNARE_BITS 64
#elif defined __aarch64__ || defined _M_ARM64
#define SNARE_ARM64
#define SNARE_BITS 64
#else
#error Unsupported architecture
#endif
/* os detection */
#if defined __linux__
#define SNARE_LINUX
#elif defined _WIN32
#define SNARE_WINDOWS
#elif defined __APPLE__
#define SNARE_MACOS
#else
#error Unsupported operating system
#endif
#if !defined SNARE_EXTERN
#if defined __cplusplus
#define SNARE_EXTERN extern "C"
#else
#define SNARE_EXTERN extern
#endif
#endif
#if defined SNARE_STATIC
#define SNARE_API
#define SNARE_EXPORT SNARE_EXTERN
#endif
#if !defined SNARE_API
#if defined SNARE_X86
#if defined SNARE_WINDOWS
#define SNARE_API __cdecl
#elif defined SNARE_LINUX
#define SNARE_API __attribute__((cdecl))
#endif
#else
#define SNARE_API
#endif
#endif
#if !defined SNARE_EXPORT
#if defined SNARE_WINDOWS
#if defined SNARE_IMPLEMENTATION
#define SNARE_EXPORT SNARE_EXTERN __declspec(dllexport)
#else
#define SNARE_EXPORT SNARE_EXTERN __declspec(dllimport)
#endif
#elif defined SNARE_LINUX
#if defined SNARE_IMPLEMENTATION
#define SNARE_EXPORT SNARE_EXTERN __attribute__((visibility("default")))
#else
#define SNARE_EXPORT SNARE_EXTERN
#endif
#else
#define SNARE_EXPORT SNARE_EXTERN
#endif
#endif
struct snare_s;
typedef struct snare_s *snare_t;
SNARE_EXPORT snare_t SNARE_API snare_new(void *src, void *dst);
SNARE_EXPORT void SNARE_API snare_free(snare_t hook);
SNARE_EXPORT void *SNARE_API snare_get_src(snare_t hook);
SNARE_EXPORT void *SNARE_API snare_get_dst(snare_t hook);
SNARE_EXPORT void *SNARE_API snare_get_trampoline(snare_t hook);
SNARE_EXPORT int SNARE_API snare_install(snare_t hook);
SNARE_EXPORT int SNARE_API snare_is_installed(snare_t hook);
SNARE_EXPORT int SNARE_API snare_remove(snare_t hook);
/* read jmp target from existing hook */
SNARE_EXPORT void *SNARE_API snare_read_dst(void *src);
#ifdef __cplusplus
class snare {
public:
  snare() : hook_(0) {}
  snare(void *src, void *dst) : hook_(snare_new(src, dst)) {}
  ~snare() {
    snare_remove(hook_);
    snare_free(hook_);
  }
  void *get_src() { return snare_get_src(hook_); }
  void *get_dst() { return snare_get_dst(hook_); }
  void *get_trampoline() { return snare_get_trampoline(hook_); }
  bool install() { return snare_install(hook_) >= 0; }
  bool install(void *src, void *dst) {
    if (hook_ == 0) {
      hook_ = snare_new(src, dst);
    }
    return install();
  }
  bool remove() { return snare_remove(hook_) >= 0; }
  bool is_installed() const { return !!snare_is_installed(hook_); }
  class scoped_remove {
  public:
    scoped_remove(snare *hook) : hook_(hook), removed_(hook_->remove()) {}
    ~scoped_remove() {
      if (removed_) {
        hook_->install();
      }
    }

  private:
    scoped_remove(const scoped_remove &);
    void operator=(const scoped_remove &);

  private:
    snare *hook_;
    bool removed_;
  };
  class scoped_install {
  public:
    scoped_install(snare *hook) : hook_(hook), installed_(hook_->install()) {}
    ~scoped_install() {
      if (installed_) {
        hook_->remove();
      }
    }

  private:
    scoped_install(const scoped_install &);
    void operator=(const scoped_install &);

  private:
    snare *hook_;
    bool installed_;
  };
  static void *read_dst(void *src) { return snare_read_dst(src); }

private:
  snare(const snare &);
  void operator=(const snare &);

private:
  snare_t hook_;
};
#endif /* __cplusplus */
#ifdef SNARE_IMPLEMENTATION
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifdef SNARE_WINDOWS
typedef unsigned __int8 uint8_t;
typedef __int32 int32_t;
#if SNARE_BITS == 64
typedef __int64 intptr_t;
#elif SNARE_BITS == 32
typedef __int32 intptr_t;
#endif
#else
#include <stdint.h>
#endif
#if defined SNARE_LINUX || defined SNARE_MACOS
#include <sys/mman.h>
#include <unistd.h>
#if defined SNARE_ARM64 && defined SNARE_MACOS
#include <libkern/OSCacheControl.h>
#endif
#endif
#ifdef SNARE_WINDOWS
#include <windows.h>
#endif
struct snare_s {
  int installed;
  void *src;
  void *dst;
  void *code;
  void *trampoline;
};
/* x86/x64: 5 byte jmp (e9 + rel32) */
#if defined SNARE_X86 || defined SNARE_X86_64
#define JMP_INSN_OPCODE 0xE9
#define JMP_INSN_LEN sizeof(struct snare_jmp)
#define MAX_INSN_LEN 15
#define MAX_TRAMPOLINE_LEN (JMP_INSN_LEN + MAX_INSN_LEN - 1)
#pragma pack(push, 1)
struct snare_jmp {
  uint8_t opcode;
  int32_t offset;
};
#pragma pack(pop)
#elif defined SNARE_ARM64
/* arm64: 16 byte ldr+br stub */
#define JMP_INSN_LEN 16
#define MAX_INSN_LEN 4
#define MAX_TRAMPOLINE_LEN (JMP_INSN_LEN + (MAX_INSN_LEN * 4))
#pragma pack(push, 1)
struct snare_jmp {
  uint32_t ldr;
  uint32_t br;
  uint64_t addr;
};
#pragma pack(pop)
#endif
static void *snare_unprotect(void *address, size_t size) {
#if defined SNARE_LINUX || defined SNARE_MACOS
  long pagesize;
  pagesize = sysconf(_SC_PAGESIZE);
  address = (void *)((long)address & ~(pagesize - 1));
  if (mprotect(address, size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    return NULL;
  return address;
#elif defined SNARE_WINDOWS
  DWORD old_protect;
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0)
    return NULL;
  if (VirtualProtect(mbi.BaseAddress, size, PAGE_EXECUTE_READWRITE,
                     &old_protect) == 0)
    return NULL;
  return address;
#endif
}
#if defined SNARE_X86 || defined SNARE_X86_64
/* length disassembler for x86/x64 */
static size_t snare_disasm(uint8_t *code, int *reloc) {
  enum flags {
    MODRM = 1,
    PLUS_R = 1 << 1,
    REG_OPCODE = 1 << 2,
    IMM8 = 1 << 3,
    IMM16 = 1 << 4,
    IMM32 = 1 << 5,
    RELOC = 1 << 6
  };
  static int prefixes[] = {
      0xF0, 0xF2, 0xF3, 0x2E, 0x36,
      0x3E, 0x26, 0x64, 0x65, 0x66, /* operand size override */
      0x67                          /* address size override */
  };
  struct opcode_info {
    int opcode;
    int reg_opcode;
    int flags;
  };
  static struct opcode_info opcodes[] = {
      /* CALL rel32       */ {0xE8, 0, IMM32 | RELOC},
      /* CALL r/m32       */
      {0xFF, 2, MODRM | REG_OPCODE},
      /* JMP rel32        */
      {0xE9, 0, IMM32 | RELOC},
      /* JMP r/m32        */
      {0xFF, 4, MODRM | REG_OPCODE},
      /* LEA r16,m        */
      {0x8D, 0, MODRM},
      /* MOV r/m8,r8      */
      {0x88, 0, MODRM},
      /* MOV r/m32,r32    */
      {0x89, 0, MODRM},
      /* MOV r8,r/m8      */
      {0x8A, 0, MODRM},
      /* MOV r32,r/m32    */
      {0x8B, 0, MODRM},
      /* MOV r/m16,Sreg   */
      {0x8C, 0, MODRM},
      /* MOV Sreg,r/m16   */
      {0x8E, 0, MODRM},
      /* MOV AL,moffs8    */
      {0xA0, 0, IMM8},
      /* MOV EAX,moffs32  */
      {0xA1, 0, IMM32},
      /* MOV moffs8,AL    */
      {0xA2, 0, IMM8},
      /* MOV moffs32,EAX  */
      {0xA3, 0, IMM32},
      /* MOV r8, imm8     */
      {0xB0, 0, PLUS_R | IMM8},
      /* MOV r32, imm32   */
      {0xB8, 0, PLUS_R | IMM32},
      /* MOV r/m8, imm8   */
      {0xC6, 0, MODRM | REG_OPCODE | IMM8},
      /* MOV r/m32, imm32 */
      {0xC7, 0, MODRM | REG_OPCODE | IMM32},
      /* POP r/m32        */
      {0x8F, 0, MODRM | REG_OPCODE},
      /* POP r32          */
      {0x58, 0, PLUS_R},
      /* PUSH r/m32       */
      {0xFF, 6, MODRM | REG_OPCODE},
      /* PUSH r32         */
      {0x50, 0, PLUS_R},
      /* PUSH imm8        */
      {0x6A, 0, IMM8},
      /* PUSH imm32       */
      {0x68, 0, IMM32},
      /* RET              */
      {0xC3, 0, 0},
      /* RET imm16        */
      {0xC2, 0, IMM16},
      /* SUB r/m32, imm8  */
      {0x83, 5, MODRM | REG_OPCODE | IMM8},
      /* SUB r/m32, r32   */
      {0x29, 0, MODRM},
      /* SUB r32, r/m32   */
      {0x2B, 0, MODRM}};
  int i;
  int len = 0;
  int operand_size = 4;
  int address_size = 4;
  (void)address_size;
  int opcode = 0;
  for (i = 0; i < (int)(sizeof(prefixes) / sizeof(*prefixes)); i++) {
    if (code[len] == prefixes[i]) {
      len++;
      if (prefixes[i] == 0x66)
        operand_size = 2;
      if (prefixes[i] == 0x67)
        address_size = SNARE_BITS / 8 / 2;
    }
  }
  for (i = 0; i < (int)(sizeof(opcodes) / sizeof(*opcodes)); i++) {
    int found = 0;
    if (code[len] == opcodes[i].opcode)
      found = !(opcodes[i].flags & REG_OPCODE) ||
              ((code[len + 1] >> 3) & 7) == opcodes[i].reg_opcode;
    if ((opcodes[i].flags & PLUS_R) && (code[len] & 0xF8) == opcodes[i].opcode)
      found = 1;
    if (found) {
      opcode = code[len++];
      break;
    }
  }
  if (opcode == 0)
    return 0;
  if (reloc != NULL && opcodes[i].flags & RELOC)
    *reloc = len;
  if (opcodes[i].flags & MODRM) {
    int modrm = code[len++];
    int mod = modrm >> 6;
    int rm = modrm & 7;
    if (mod != 3 && rm == 4)
      len++;
#ifdef SNARE_X86_64
    if (reloc != NULL && rm == 5)
      *reloc = len;
#endif
    if (mod == 1)
      len += 1;
    if (mod == 2 || (mod == 0 && rm == 5))
      len += 4;
  }
  if (opcodes[i].flags & IMM8)
    len += 1;
  if (opcodes[i].flags & IMM16)
    len += 2;
  if (opcodes[i].flags & IMM32)
    len += operand_size;
  return len;
}
#endif /* SNARE_X86 || SNARE_X86_64 */
static size_t snare_make_jmp(uint8_t *src, uint8_t *dst, int32_t offset) {
  struct snare_jmp *jmp = (struct snare_jmp *)(src + offset);
#if defined SNARE_X86 || defined SNARE_X86_64
  jmp->opcode = JMP_INSN_OPCODE;
  jmp->offset = dst - (src + JMP_INSN_LEN);
#elif defined SNARE_ARM64
  jmp->ldr = 0x58000050; /* ldr x16, #8 */
  jmp->br = 0xD61F0200;  /* br x16 */
  jmp->addr = (uint64_t)dst;
#endif
  return sizeof(*jmp);
}

static size_t snare_make_trampoline(uint8_t *trampoline, uint8_t *src) {
  size_t orig_size = 0;
#if defined SNARE_X86 || defined SNARE_X86_64
  size_t insn_len;
  while (orig_size < JMP_INSN_LEN) {
    int reloc = 0;
    insn_len = snare_disasm(src + orig_size, &reloc);
    if (insn_len == 0)
      return 0;
    memcpy(trampoline + orig_size, src + orig_size, insn_len);
    if (reloc > 0)
      *(int32_t *)(trampoline + orig_size + reloc) -=
          (intptr_t)trampoline - (intptr_t)src;
    orig_size += insn_len;
  }
  return orig_size + snare_make_jmp(trampoline, src, orig_size);
#elif defined SNARE_ARM64
  /* just copy 16 bytes, no relocation */
  memcpy(trampoline, src, JMP_INSN_LEN);
  orig_size = JMP_INSN_LEN;
  return orig_size + snare_make_jmp(trampoline, src + JMP_INSN_LEN, orig_size);
#endif
}

SNARE_EXPORT snare_t SNARE_API snare_new(void *src, void *dst) {
  snare_t hook;
  if ((hook = (snare_t)malloc(sizeof(*hook))) == NULL)
    return NULL;
  hook->installed = 0;
  hook->src = src;
  hook->dst = dst;
  if ((hook->code = malloc(JMP_INSN_LEN)) == NULL) {
    free(hook);
    return NULL;
  }
  memcpy(hook->code, hook->src, JMP_INSN_LEN);
  if ((hook->trampoline = calloc(1, MAX_TRAMPOLINE_LEN)) == NULL) {
    free(hook->code);
    free(hook);
    return NULL;
  }
  if (snare_unprotect(hook->src, JMP_INSN_LEN) == NULL ||
      snare_unprotect(hook->trampoline, MAX_TRAMPOLINE_LEN) == NULL) {
    free(hook->trampoline);
    free(hook->code);
    free(hook);
    return NULL;
  }
  if (snare_make_trampoline((uint8_t *)hook->trampoline,
                            (uint8_t *)hook->src) == 0) {
    free(hook->trampoline);
    hook->trampoline = NULL;
  }
#if defined SNARE_ARM64 && defined SNARE_MACOS
  if (hook->trampoline) {
    sys_icache_invalidate(hook->trampoline, MAX_TRAMPOLINE_LEN);
  }
#endif
  return hook;
}

SNARE_EXPORT void SNARE_API snare_free(snare_t hook) {
  if (hook == NULL)
    return;
  free(hook->trampoline);
  free(hook->code);
  free(hook);
}
SNARE_EXPORT void *SNARE_API snare_get_trampoline(snare_t hook) {
  return hook->trampoline;
}
SNARE_EXPORT void *SNARE_API snare_get_src(snare_t hook) { return hook->src; }
SNARE_EXPORT void *SNARE_API snare_get_dst(snare_t hook) { return hook->dst; }

SNARE_EXPORT int SNARE_API snare_is_installed(snare_t hook) {
  return hook->installed;
}
SNARE_EXPORT int SNARE_API snare_install(snare_t hook) {
  if (hook->installed)
    return -EINVAL;
  snare_make_jmp((uint8_t *)hook->src, (uint8_t *)hook->dst, 0);
  hook->installed = 1;
#if defined SNARE_ARM64 && defined SNARE_MACOS
  sys_icache_invalidate(hook->src, JMP_INSN_LEN);
#endif
  return 0;
}

SNARE_EXPORT int SNARE_API snare_remove(snare_t hook) {
  if (!hook->installed)
    return -EINVAL;
  memcpy(hook->src, hook->code, JMP_INSN_LEN);
  hook->installed = 0;
  return 0;
}

SNARE_EXPORT void *SNARE_API snare_read_dst(void *src) {
  struct snare_jmp *maybe_jmp = (struct snare_jmp *)src;
#if defined SNARE_X86 || defined SNARE_X86_64
  if (maybe_jmp->opcode != JMP_INSN_OPCODE)
    return NULL;
  return (void *)(maybe_jmp->offset + (uint8_t *)src + JMP_INSN_LEN);
#elif defined SNARE_ARM64
  if (maybe_jmp->ldr != 0x58000050 || maybe_jmp->br != 0xD61F0200)
    return NULL;
  return (void *)maybe_jmp->addr;
#endif
}
#endif /* SNARE_IMPLEMENTATION */
#endif /* SNARE_H */
