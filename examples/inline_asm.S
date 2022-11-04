# inline hook from pure x86_64 asm
# link with inline_asm_impl.c for snare symbols
# x86_64 sysv abi, linux only

.data
hook:       .quad 0
fmt_before: .asciz "before: %d\n"
fmt_detour: .asciz "detour: %d\n"
fmt_after:  .asciz "after:  %d\n"

.text

# target function: identity(x) = x
# only uses opcodes in snare's length disassembler
#   53       push %rbx
#   89 fb    mov %edi, %ebx
#   89 d8    mov %ebx, %eax
#   5b       pop %rbx
#   c3       ret
.globl target
.type target, @function
target:
    push %rbx
    movl %edi, %ebx
    movl %ebx, %eax
    pop %rbx
    ret

# detour: calls original via trampoline, negates result
.globl detour
.type detour, @function
detour:
    push %rbx
    push %r12
    sub $8, %rsp

    movl %edi, %ebx

    lea fmt_detour(%rip), %rdi
    movl %ebx, %esi
    xorl %eax, %eax
    call printf@PLT

    mov hook(%rip), %rdi
    call snare_inline_get_trampoline@PLT
    mov %rax, %r12

    movl %ebx, %edi
    call *%r12
    negl %eax

    add $8, %rsp
    pop %r12
    pop %rbx
    ret

.globl main
.type main, @function
main:
    push %rbx
    sub $8, %rsp

    # before hook
    movl $42, %edi
    call target
    movl %eax, %ebx
    lea fmt_before(%rip), %rdi
    movl %ebx, %esi
    xorl %eax, %eax
    call printf@PLT

    # snare_inline_new(target, detour)
    lea target(%rip), %rdi
    lea detour(%rip), %rsi
    call snare_inline_new@PLT
    mov %rax, hook(%rip)

    # snare_inline_install(hook)
    mov %rax, %rdi
    call snare_inline_install@PLT

    # call through hook
    movl $42, %edi
    call target
    movl %eax, %ebx
    lea fmt_detour(%rip), %rdi
    movl %ebx, %esi
    xorl %eax, %eax
    call printf@PLT

    # snare_inline_remove(hook)
    mov hook(%rip), %rdi
    call snare_inline_remove@PLT

    # snare_inline_free(hook)
    mov hook(%rip), %rdi
    call snare_inline_free@PLT

    # after unhook
    movl $42, %edi
    call target
    movl %eax, %ebx
    lea fmt_after(%rip), %rdi
    movl %ebx, %esi
    xorl %eax, %eax
    call printf@PLT

    xorl %eax, %eax
    add $8, %rsp
    pop %rbx
    ret
