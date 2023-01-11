# Types of attacks

In this file we will see how can we use the tools (seen in [TOOLKIT](./TOOLKIT.md)) to exploit some vulnerabilities of the program.

## Changing ASM instructions (or bytes)
It's possible to change an ASM instruction or bytes by patching the program (see [Ida patching](./TOOLKIT.md#Patching-with-Ida) or [Radare2 patching](./TOOLKIT.md#Patching-with-Radare2)). This type of attack is especially used to reverse a jmp instruction *(e.g. from JNZ to JZ)* or to avoid an istruction to be executed by replacing it with NOPs.

> ***PLEASE NOTE:*** If the exercise require you not to patch the binary, sometimes it might be useful enough to put a breakpoint using gdb in the correct place (e.g. just after the function you would like to modify but can't so you can read the register eax (with the returned value) by doing ```print $eax``` and then with ```c``` you continue the debug and input the value discovered at the breakpoint (converted to decimal obviously)) .



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
payload += p32(address_to_go)   # pack the address of the function to execute (p64 if arch is 64-bit, you can check with checksec)

p.sendline(payload)
msgout = p.recvall()
print(msgout)       #remember to print the result!!!!!
# if the function to execute is the opening of a shell then you need to add also:
# p.interactive()
```
 
> ***PLEASE NOTE:*** In real exploits, it's not particularly likely that you will have a suitable function lying around, so the shellcode is a way to run your own instructions, giving you the ability to run arbitrary commands on the system. So instead of jumping to a funtion we can for example jump to the address of the start of the buffer, so if we input some code in the buffer it will be executed. Here we can put some code that opens a shell (see below how to do find it).

### Focus: How to find a shellcode
If you'd like to do a shellcode attack you need to input in the buffer some code that opens a shell *(i.e. usually the vulnerability is a gets(buffer) where you can overflow the buffer and put as return address the start of the buffer where you have the code of the shell, see [how to redirect execution](#Buffer-overflows-to-redirect-execution)).* 
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



## Exploiting GOT vulnerabilities to redirect execution
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

> ***PLEASE NOTE:*** A great idea is for example to retrieve the absolute address of the *exit()* function and change it to the address of the function you want to call. Please remember that if it is the program itself changing the value of the address you have to pay attention at the type of variables they're asking for *(e.g if the variable where the program is storing the addresses is an integer, you have to convert the hex address to an int number and then into a string in order to send it, sometimes even encode it in ascii to obtain a byte like object).*

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

Now that we know this we can redirect the execution by exploiting the vulnerability of the GOT as usual (see [exploiting GOT](#Exploiting-GOT-vulnerabilities-to-redirect-execution)).


## Bypassing NX (using ROP)
### What is NX?
The NX bit, which stands for *No eXecute*, defines areas of memory as either instructions or data. This means that your input will be stored as data, and any attempt to run it as instructions will crash the program, effectively neutralising shellcode.

To check if it's enabled simply you can use [checksec](./TOOLKIT.md#Some-useful-commands)).

### What is ROP
To get around NX, exploit developers have to leverage a technique called ROP, Return-Oriented Programming. ROP is basically a computer security exploit technique in which the attacker uses control of the call stack *(by doing a stack overflow)* to indirectly execute cherry-picked machine instructions or groups of machine instructions within the existing program code. In ROP, these code chunks, *necessarily have to end with a* **ret** *instruction*, are called **gadgets**. Moreover, these gadgets can be chained together to make them work as a simple unit to perform arbitray computations.

In other words, we found a vulnerability in the stack, usually a buffer that we can overflow. Overflowing the buffer means overwriting the return address to the gadget we want to execute and after that in the stack we can also insert some values (taken from other parts of the code) useful for the gadget. In the end, since most of the time our goal is to call a function in the program with different parameters, after all of this we can also put the address of the function (so that it will be called once the gadget is done and so removed from the stack).

> ***PLEASE NOTE:*** For a more in-depth explanation you can check [here](https://resources.infosecinstitute.com/topic/return-oriented-programming-rop-attacks/)

### How can we use ROP to execute a function with different parameters (if NX enabled)
In order to change the execution of the program using ROP we will need to:
- ***STEP 1:*** inspect the binary and look for a function with a vulnerability of buffer overflow *(in challenges it's usually called pwnme)*
- ***STEP 2:*** once we have identified the vulnerability, we have to get the offset between the start of the buffer and the return address so that we can overwrite the latter and make it the address of the gadget we want. 
     - In order to do so, we use [cyclic pattern](./TOOLKIT.md#Cyclic-patterns) (specifically doing the *please note* stuff)
- ***STEP 3:*** now we need to find the address of the gadget we want to execute. We can do it using [ROPgadget](./TOOLKIT.md#Some-useful-commands)
     - usually the gadget we need is something that puts a value into a register, that can be done by ```pop register, ret```, so we can put as parameter of *grep* in ROPgadget either the register or the pop instruction and loook for it
     - in this case, the ```pop``` instruction will take the last item in the stack and store it in the *register* (the argument of the pop). Therefore, after the address of the gadget we will also need to put in the stack the address of the values we want to put in the *register*
     - to check for the address of values, usually strings, we need to use radare2. In particular, we use ```iz``` which will find all the strings in data section
- ***STEP 4:*** if we have successfully changed the registers we want, we can now put on the stack the function we want to execute with different parameters
     - usually, if it's for example a ```system()``` instruction we want to execute with different parameters, we will need in *step 3* for example a gadget as ```pop rdi, ret```
     - to check the address of system we can use in GDB the instruction ```p system```

So the payload used as input will be formed by: ```padding + addr_gadget + addr_arguments + ... + addr_function_to_call  ```

> ***PLEASE NOTE:*** If we want to add more gadgets we can just add to the payload the address of the other gadget and the arguments after that (just remember not to add the padding again).

We are now ready to make our python script using pwntools:
```python
from pwn import *

padding = b'A' * offset    #offset found in step 2 with gdb's cyclic pattern
gadget = p64(addr_of_the_gadget)    #addr_of_the_gadget found with ROPgadget in step 3, and it's in the form 0x... (without " ")   (p32 if arch is 32-bit, check with checksec)
argument = p64(addr_of_argument)    #addr_of_argument found with radare2 in step 3, and it's theaddress of the parameter (usually of a register) we need in the gadget above
function_to_call = p64(addr_of_function)       #addr_of_function found with radare2 in step 4, and it's the address of the function we want to call

payload = padding + gadget + argument

########IMPORTANT#########
#If the stack is not 16-bytes aligned (i.e. the RSP address not end with 0 before e.g. calling system() which require the stack to be aligned) we'll have a SIGSEV error.
#To align it we need to move it by 8 bytes by adding a gadget which will only contain a ret (we can search it with ROPgadget) and insert it in the payload
payload += p64(gadget_only_ret)
##########################

payload += function_to_call

#connect the script with the process and send the payload
p = process("./name_of_the_file")
p.sendline(payload)

#print the result (alternatively might be needed to do a p.interactive() 
print(p.recvall())
```

### How can we use ROP to write something in memory (if NX enabled)
In order to write something in memory using ROP we will need to:
- ***STEP 1*** and ***STEP 2*** are the same as above
- ***STEP 3***: we need to find the are of the memory where to write what we want. In order to do we need to look at the ELF file's structure:
     - we use radare2, and in paricular, the command ```iS``` to display all the sections of the ELF file with their permissions *(an alternative (più brutta) could be the use in the terminal of ```readelf name_of_the_file -S```)*
     - we now have to look at the sections which are also marked as writable (w) and find a suitable one. For example, if present, we can write in *.data* which is used to store variables. 
          - To see if it's suitable we have to check first if it's big enough: we check if the *vsize* (in readelf is displayed just below the name of the section simply ) can contain the thing we want to write in it
          - If it's big enough we go to the address of the section using in radare2 and by doing ```s vaddr```. Then we have to check if there is something stored in the section: we check it using radare2 following command: ```px vsize```. If the section is empty, it's better because in that way we're sure that there is very little risk to overwrite important things for the program and make it crash.
- ***STEP 4:*** If we're satisfied with this, we can write in *vaddr*. In order to do so we need a gadget that can do it, for example ```mov [x], y``` (where x e y are registers). We also need a gadget to initialize x e y to the value we want, this could be achieved with a pop gadget i.e. ```pop x, y, ret```. To find tese gadgets we can use To find it we can use [ROPgadget](./TOOLKIT.md#Some-useful-commands)

The payload will be formed by: ```padding + gadget_pop + x (where we want to write which is vaddr) + y (what we want to write (in format b'...') e.g. if we want to write the value inside flag.txt we can write b'flag.txt') + gadget_mov_y_to_x```. The process and how to make/send the payload, instead, are the same as seen above.

> ***PLEASE NOTE:*** This thing won't print/receive anything so you need, for example, to chain after this in the payload also a function which print a specific register, i.e. you can use a *pop* gadget to put the *vaddr* in the specfific register of the print function found so that it will print the area that was overwritten. Basically you're doing ```payload += gadget_pop_z + x (i.e. the vaddr) + function_print_z```

