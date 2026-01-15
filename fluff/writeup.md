# ROP Emporium - fluff (x86_64)

## Challenge Overview

The goal is to call `print_file("flag.txt")` to read the flag. However, unlike simpler challenges, there are no direct memory write gadgets like `mov [reg], reg`. Instead, we must use "questionable gadgets" to write the string `"flag.txt"` byte-by-byte to the `.data` section.

## Binary Analysis

### Key Sections

| Section | Address | Purpose |
|---------|---------|---------|
| `.data` | `0x601028` | Writable memory (our target) |
| `.dynstr` | `0x4003c0` | Contains function names (character source) |
| `.rodata` | `0x4006c0` | Read-only data (character source) |

### Questionable Gadgets

```asm
0x400628: xlatb; ret
0x40062a: pop rdx; pop rcx; add rcx,0x3ef2; bextr rbx,rcx,rdx; ret
0x400639: stosb; ret
```

### Other Required Gadgets

```asm
0x4006a3: pop rdi; ret
```

## Gadget Explanation

### 1. `xlatb` (0x400628)

```asm
xlatb    ; AL = [RBX + AL]
ret
```

- Reads a single byte from memory at address `RBX + AL`
- Stores result in `AL`
- Used to **read characters** from the binary

### 2. `bextr` gadget (0x40062a)

```asm
pop rdx              ; RDX = value from stack
pop rcx              ; RCX = value from stack
add rcx, 0x3ef2      ; RCX += 0x3ef2
bextr rbx, rcx, rdx  ; RBX = extract bits from RCX
ret
```

- `bextr` with `RDX = 0x4000` copies all 64 bits from RCX to RBX
- Used to **control RBX** (indirectly, accounting for the add)
- Formula: `RCX = (target_address - AL - 0x3ef2)`

### 3. `stosb` (0x400639)

```asm
stosb    ; [RDI] = AL, RDI++
ret
```

- Writes the byte in `AL` to address in `RDI`
- Auto-increments RDI
- Used to **write characters** to `.data`

## Character Source Locations

Characters for `"flag.txt"` found in the binary:

| Char | Hex  | Address    | Found in |
|------|------|------------|----------|
| `f`  | 0x66 | 0x4003c4   | "lib**f**luff.so" |
| `l`  | 0x6c | 0x4003c1   | "**l**ibfluff.so" |
| `a`  | 0x61 | 0x4003d6   | "st**a**rt" |
| `g`  | 0x67 | 0x4003cf   | "__**g**mon" |
| `.`  | 0x2e | 0x4003c9   | "libfluff**.**so" |
| `t`  | 0x74 | 0x4003d8   | "star**t**" |
| `x`  | 0x78 | 0x4006c8   | "none**x**istent" |

## Exploit Strategy

### The Problem

We need to write `"flag.txt"` to memory, but there's no simple write gadget.

### The Solution

Write one byte at a time using:
1. `bextr` gadget to set RBX = (char_address - AL)
2. `xlatb` to read character into AL
3. `stosb` to write AL to destination

### ROP Chain Structure

```
[padding - 40 bytes]

[pop rdi; ret]
[0x601028]              <- Set destination to .data

For each character:
  [pop rdx; pop rcx; add rcx,0x3ef2; bextr; ret]
  [0x4000]              <- RDX: extract all 64 bits
  [char_addr - AL - 0x3ef2]  <- RCX value
  [xlatb; ret]          <- AL = character
  [stosb; ret]          <- Write to .data, RDI++

[pop rdi; ret]
[0x601028]              <- Pointer to "flag.txt"
[print_file@plt]        <- Call the function
```

### The AL Tracking Problem

- `xlatb` uses current AL as offset: `AL = [RBX + AL]`
- After `stosb`, AL contains the character just written
- Initial AL = `0x0b` (return value of `puts("Thank you!")`)

For each character:
- Calculate: `RCX = (char_address - current_AL - 0x3ef2)`
- After write: `AL = ord(character)`


## Key Takeaways

1. **No direct write gadgets?** Look for indirect methods like `stosb`, `movsb`, etc.

2. **Understand obscure x86 instructions:**
   - `xlatb`: Table lookup using AL as index
   - `bextr`: Bit field extraction (can copy registers)
   - `stosb`: Store byte to [RDI] and increment

3. **Track register state:** AL changes after each operation - must account for this in calculations.

4. **Find characters in the binary:** Use `objdump -s` to dump sections and locate needed bytes.

5. **Initial register values matter:** The return value of the last function call (here `puts`) determines initial AL.

