# Types of attacks

In this file we will see how can we use the tools (seen in [TOOLKIT](./TOOLKIT.md)) to exploit some vulnerabilities of the program.

## Changing ASM instructions (or bytes)
It's possible to change an ASM instruction or bytes by patching the program (see [Ida patching](./TOOLKIT.md#Patching-with-Ida) or [Radare2 patching](./TOOLKIT.md#Patching-with-Radare2)). This type of attack is especially used to reverse a jmp instruction *(e.g. from JNZ to JZ)* or to avoid an istruction to be executed by replacing it with NOPs.



## Buffer overflows to redirect execution
### Our goal
When a function calls another function, it:
- pushes a return pointer (EIP) to the stack so the called function knows where to return
- when the called function finishes execution, it pops it off the stack again

Because this value is saved on the stack, just like our local variables, if we write more characters than the program expects, we can overwrite the value and redirect code execution to wherever we wish.

### What we need to do
To redirect the execution (i.e. changing where we return):
- first we need to find the padding until we begin to overwrite the return pointer (EIP)  -> use [cyclic patterns](./TOOLKIT.md#Cyclic-patterns)
- then we need to find what value we want to overwrite EIP to (i.e. the address of the function we want to execute) -> use [ELF .symbols function](./TOOLKIT.md#ELF) or use [afl command in Radare2](./TOOLKIT.md#Radare2-basics)
 
Basically the code in python will loke like this:
```python
from pwn import *            # import pwntools

p = process('./name_of_the_process')        # to interact with the process

payload = b'A' * n       # n is the number of bytes for the padding
payload += p32(address_to_go)   # pack the address of the function to execute

p.sendline(payload)
# if the function to execute is the opening of a shell then you need to add also:
# p.interactive()
```
 
> ***PLEASE NOTE:*** In real exploits, it's not particularly likely that you will have a suitable function lying around, so the shellcode is a way to run your own instructions, giving you the ability to run arbitrary commands on the system. So instead of jumping to a funtion we can for example jump to the address of the start of the buffer, so if we input some code in the buffer it will be executed. Here we can put some code that opens a shell (see below how to do find it).

### FOCUS: HOW TO FIND A SHELLCODE
If you'd like to do a shellcode attack you need to input in the buffer some code that opens a shell *(i.e. usually the vulnerability is a gets(buffer) where you can overflow the buffer and put as return address the start of the buffer where you have the code of the shell, see [how to redirect execution](./TOOLKIT.md#Redirect-execution)).* 
  - This shellcode can be find at https://shell-storm.org/shellcode/index.html where there are different shellcodes based on architecture and features. You can search manually or do a simple python program to search it for you. The code of this program can be e.g.:
      ```python
      import requests

      keyword1 = "bash"       #we want a bash shell
      keyword2 = "execve"     #we want a shell that is able to execute a program referred to by pathname
      shellcodes = "http://shell-storm.org/api/?s=" + keyword1 + "*" + keyword2           #filter the shellcodes based on the keywords

      response = requests.get(shellcodes)
      possible_shellcodes = response.content      #get the possible shellcodes (filtered before)
      print(possible_shellcodes)      #prints the name and the link where to find the suitable shellcodes
      ```
      Then you can search for the most suitable between the choices in the print (please make sure to look at the correct architecture and at the bytes needed for the shellcode).

  - Alternatively, you can create a shell using [pwntools shellcraft command](./TOOLKIT.md#Interactive-sessions)



## Exploiting GOT vulnerabilties to redirect execution
### How dynamic linking works and why we need to exploit GOT to redirect execution
There’s two types of binaries on any system: statically linked and dynamically linked. Statically linked binaries are self-contained, containing all of the code necessary for them to run within the single file, and do not depend on any external libraries. Dynamically linked binaries (which are the default when you run gcc and most other compilers) do not include a lot of functions, but rely on system libraries to provide a portion of the functionality (to reduce substancially the size of the program). 

*For example, when your binary uses puts, the actual implementation of puts is part of the system C library. This means each ELF file will not carry their own version of puts compiled within it - it will instead dynamically link to the puts of the system it is on.*

> ***PLEASE NOTE:*** You may think that when libraries are on a new system, then it's just encessary to replace function calls (to these libraries) with hardcoded addresses; but the problem with this is that it would require the libraries to have a constant base address, i.e. be loaded in the same area of memory every time it's run. However, this is most of the time not true since modern systems use ASLR *(Address Space Layout Randomization )* which means libraries are loaded at different locations on each program invocation, which is possible only thanks to dynamic linking (these addresses need to be resolved every time the binary is run and to do so is rather impossible with hardcoding addresses).

Consequently, a strategy called *"Relocation"* was developed to allow looking up all of these addresses when the program was run and providing a mechanism to call these functions from libraries. The hard work of doing this is done by the PLT and the GOT which are sections within an ELF file that deal with the dynamic linking and specifically they take care of locating these *(dynamically-linked)* functions (since the program need to know the address of the functions to call them).

### The relocation: PLT and GOT
PLT *(Procedure Linkage Table)* and GOT *(Global Offset Table)* work together to perform linking.
Basically what happens is that when the program calls one of the (library's) functon it's actually calling the address of the PLT corresponding to that function which they actually make another indirect call to the correspondent address of the GOT.

*For example: When you call puts() in C and compile it as an ELF executable, it is not actually puts() - instead, it gets compiled as puts@plt (you can check it out in GDB). This happens because it doesn't know where puts actually is, so it jumps to the PLT entry of puts instead. From here, puts@plt does some very specific things:*
- *If there is a GOT entry for puts, it jumps to the address stored there. *
- *If there isn't a GOT entry, it will resolve it and jump there*

> ***PLEASE NOTE:*** Since calling the PLT address of a function is equivalent to calling the function itself if we have a PLT entry for a desirable library function we can just redirect execution (normally) to its PLT entry and it will be the equivalent of calling the function directly

The GOT is basically a massive table of addresses (every library function used by the program has an entry there). These addresses are the actual (real, absolute) locations in memory of the library functions. 

So, when the PLT gets called, it reads the GOT address and redirects execution there. If the address is empty, it coordinates with the ld.so (also called the dynamic linker/loader) to get the function address and stores it in the GOT.

### Finding the addresses

> ***PLEASE NOTE:***  GOT thing that allows a c program to call libc libraries and serve as a jumping point for the program. Therefore, we can try to hijack it, especially if ASLR is enabled, because it stays constant (the address of a GOT entry is only fixed per binary, so if two systems have the same binary running, then the GOT entry is always at the same address). This means if we modify the jumping point we can make the program execute code at a different address than intended.

The GOT address contains addresses of functions in libraries, and the GOT is within the binary, so it will always be a constant offset away from the base. Therefore, if PIE is disabled or you somehow leak the binary base (see [bypassing PIE](#Bypassing-PIE)), you know the exact address (of the GOT and so the address...) that contains a library's function's address.
You can retrieve this real/absolute address 3 different methods:
- using Radare2:
    - by doing ```pdf @ name_of_the_function``` or equivalently ```pd n @ name_of_the_function``` *(n is the number of asm instructions to display)* which will print the function disassembled and with it also the relocated address (just look at the end after the jump to the ...word of the reloc)
- using the objdump command
    - in particular by doing ```objdump --dynamic-reloc ./name_of_the_file``` which will show the real address of all the functions
- using pwntools
    - in particular by doing ```function_gotAdd = elf.got["name_of_the_function"]``` *(where elf is the object created with the context.binary setted)*, and in this case function_gotAdd* will store the real GOT address
    
You can retrieve the address where to jump instead of the GOT address found above:
- using ```afl``` command in Radare2 which will show the address of the function
- using pwntools:
    - we can use the ```functionAdd = elf.symbols["name_of_the_function"]```, and in this case *functionAdd* will store the address of the function


### Bypassing PIE
PIE (*Position Independent Executable*) if enabled (you can check it using [checksec](./TOOLKIT.md#Some-useful-commands)) means that every time you run the file it (meaning the binary) gets loaded into a different memory address. This means you cannot hardcode values such as function addressess without finding out where they are, i.e. if PIE is active it means the .symbols[] won't recover the correct address (it will recover the address offsetted which means every time you run it will be different).

However, since PIE executables are based around relative rather than absolute addresses, meaning that while the locations in memory are random, the offsets between different parts of the binary remain constant. 

*For example, if you know that the function main is located 0x128 bytes in memory after the base address of the binary, and you somehow find the location of main, you can simply subtract 0x128 from this to get the base address (and the same from the addresses of everything else ro retrieve the original one).*

> ***PLEASE NOTE:***  Due to the way PIE randomisation works, the base address of a PIE executable (i.e. elf.address) will always end in the hexadecimal characters 000. This is because pages are the things being randomised in memory, which have a standard size of 0x1000. So you can look at this when double-checking the base address.

So, all we need to do is find a single (original) address and PIE is bypassed, e.g. we can find the address of the main. 
We already know the original address of the main because it's the start of the process, so we can retrieve it simply by doing ```main = p.unpack()```. We also know the address of the main function that has been modified with the PIE offset thanks to ```elf.symbols["main"]```.
So we can know the PIE offset simply by doing ```main - elf.symbols["main"]```. We then have to update the addresses of all symbols (to the address without the offset caused by PIE), this can be done simply by doing:
```python  
elf.address = main - elf.symbols["main"]
```
> ***PLEASE NOTE:*** Before this remember to set the context.binary and create the elf object (that we've called *elf* here) with the context.binary.path.

Now that we know this we can redirect the execution by exploiting the vulnerability of the GOT as usual (see [exploiting GOT](Exploiting-GOT-vulnerabilties-to-redirect-execution)).