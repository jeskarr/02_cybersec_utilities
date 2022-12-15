# Toolkit

Some useful tools for the second part of the Cybersecurity course @UniPd


## Requirements
- Disassembler -> we use ***Ida***
    - *to download Ida (free version):* https://www.hex-rays.com/ida-free/
- Hexadecimal editor -> we use ***Radare2*** (alternative: *Hex Editor*)
    - *to download Radare:* https://github.com/radareorg/radare2
- Debugger -> we use ***GDB***
    - it should already been installed if you have Linux *(on Windows you will need to install it, please note that in this case MinGW distributes a Windows version of it)*
- Other tools useful for pwning:
    - ***PEDA*** *(i.e. Python Exploit Development Assistance for GDB)* available to download at: https://github.com/longld/peda
    - ***pwntool*** *(python library)*, available to download at: http://docs.pwntools.com/en/stable/ or simply by doing ```pip install pwntools```

> ***PLEASE NOTE:***  Before doing anything it's necessary to change the permissions of the directory we want to work on. We can achieve this with:   ``` chmod -R +x ./ ```


## Some useful commands
Let's see some commands (available to use on terminal) that might be useful for Reverse Engineering and Pwning:
- ***./name_of_the_program***
    - to simply run a program in the terminal
- ***cat ./text_file***
    - to read the files specified as parameters and display the concatenation of their content
- ***strings ./name_of_the_program***
    - to display all the strings used inside the program (e.g. if there is a psw or a flag stored it should appear)
- ***objdump -option ./name_of_the_program***
    - to display information about one or more object files. The options control what particular information to display, we can for example choose the option -d (--disassemble) which display the ASM code of the input files.
- ***checksec ./name_of_the_program***
    - to display details (+ security properties) regarding the executable file *(e.g. architecture 32bit/64bit so we know the size of the registers)*. In particular, it outputs:
        1. the architecture (32-64bit + little/big endian)
        2. RELRO, which stands for *Relocation Read-Only*, and if enabled it makes the GOT *(i.e. the "Global Offset Table" of ELF executable files used to resolve functions dynamically)* read-only, which prevents some form of relocation attacks.
        3. CANARY, they are special known values placed  between a buffer and control data on the stack to monitor buffer overflows. In this way, they can control that the function return to the real previous function
        4. NX, which stands for *Non-Executable*, it's often enabled by default and in that case the stack is non-executable (basically NX enabled can mark certain areas of memory as non-executable). This is done because often buffer-overflow exploits put code on the stack and then try to execute it. However, making this writable area non-executable can prevent such attacks.
        5. PIE, which stands for *Position Independent Executable*,  it's code that is placed somewhere in memory for execution regardless of its absolute address (basically the addresses are shifted of a (common) offset. 


## Ida
### Basics 
To open Ida from terminal:
```
cd idafree-8.1/
./ida64
```
To disassemble a file click on *New* and then *Ok* on the *Quick Start* window that opens up. You should now see all the ASM code of the program on the right side 
(included the branches generated by the jump instructions) and the various functions on the left side.
You can also change the view from "graph view" to "text view" by simply pressing the space bar on the keyboard.

From "text view" we are now able to patch the instructions by doing: ``` Edit -> Patch program -> Assemble ``` . Once we have changed/patched the instruction (and clicked on OK), then we need to actually apply the patch to the original program by doing: ``` Edit -> Patch program -> Apply patches to input file -> OK ```.

> ***PLEASE NOTE:*** When changing the type of view in Ida, if we have highlighted/selected some instruction, we will be able to see that instruction highlighted/selected in the other type of view as well.

### Patching with Ida
We can also patch instructions on Ida by changing the actual hexadecimal values. We pass to "Hex View" so we can see the hex of the instruction we want to patch. Then as before we can patch it by doing: ``` Edit -> Patch program -> Patch byte ``` and then apply the patch to the original program as before.

> ***PLEASE NOTE:*** The instructions are identified in hex with their opcode. So if you want to change an instruction you need to change the hex/opcode with the one you want. You can find all the opcodes with the corresponding instruction at: http://ref.x86asm.net/coder64.html 
In particular, please note that the opcode for the NOP instruction is 90.


## Radare2
### Basics
Radare2 is very useful for patching *(e.g. we can fill with NOP, invert or remove them and also paste new functions)*. In particular, we can use it for change some constant (since the free version of Ida doesn't really allow us to do so).

Let's see some Radare commands (that we use on the terminal) that help us doing it:
- To open the file using Radare2 *(-w to enable writing on it)* and launch tha analysis:
    ```
    r2 -w name_of_the_file
    aaaa
    ```
    > ***PLEASE NOTE:*** it's recommended doing a copy of the file and working with radare on it, rather than the original one
- To move to the start of a function or a specific address:
    ```C
    s name_of_the_function
    //or similarly
    s address
    ```
- To print the the decompiled function (once you've moved to the corresponding memory address) simply use:
    ```
    pdf
    ```
    In this way you will be able to see on your left the memory addresses, on the center the bytes that make up the instructions and on the right the instructions themselves.
- To disply all the functions and their memory address where they're store we simply use:
    ```C
    afl     //which stands for Analyse Function List
    ```


### Patching with Radare2
To patch the instruction (once you've moved to the corresponding memory address) you can use:
```C
//to patch the assembly instructions
wa new_instruction_in_ASM
//to patch the bytes
wx new_bytes
```
> ***PLEASE NOTE:*** you can double check the correctness of the patch with ```pdf```


## GDB (included PEDA)
### Basics
To run a file using GDB, i.e. debugging it:
```C
gdb name_of_the_file
//to initially run the program and make it stop at the most convenient spot:
start
```
or also
```C
gdb name_of_the_file
//add breakpoints
run
```
In this last way, the program will stop at the first breakpoint *(please note that if there are no breakpoints, it will run your program to completion without debugging it at all, unless of course the program crashes. In that case, gdb will stop and allow you to debug it)*. 

> ***PLEASE NOTE:*** If you don't add breakpoints, you can still stop the program while it's running by typing ```(ctrl) + c```. Gdb will stop your program at whatever line it has just executed. From here you can examine variables and move through your program.

### About breakpoints (and how to resume the program)
To add a breakpoint:
```C
b*memory_address
//or similarly
break name_of_the_function
```

> ***PLEASE NOTE:*** Breakpoints stay set when your program ends, so you do not have to reset them unless you quit gdb and restart it. 

Other useful commands regarding breakpoints:
- To list current breakpoints: ```info break```
- To delete a breakpoint: ```del breakpoint_number```
- To delete all breakpoints from a specific function: ```clear name_of_the_function```
- To temporarily disable a breakpoint: ```dis breakpoint_number```
- To enable a breakpoint: ```en breakpoint_number```
- To ignore a breakpoint until it has been crossed x times: ```ignore breakpoint_number x```

On the other hand you might want:
- To execute one line of code:
    - just type ```step``` or ```s```. If the line to be executed is a function call, gdb will step into that function and start executing its code one line at a time. If you want to execute the entire function with one keypress, type ```next``` or ```n```.
- To resume normal execution:
    - just type ```continue``` or ```c```. In this way, gdb will run until your program ends, your program crashes, or gdb encounters a breakpoint. 
    > ***PLEASE NOTE:***  In this way you can also loop the program n times just by typing: ```c n_times```
- To resume execution at another function of the program:
    - just type ```jump name_of_the_function ```

### Examining data with gdb
To show information about the current state of the program you can use the keyword info, for example:
- to show the current conent of the registers type ``` info registers ```
- to show the current variables type ``` info variables ```

> ***PLEASE NOTE:*** If you just type info, it will show you all the possible subcommands.

Sometimes, the content of register or variables might be an hexadecimal (in the form 0x...), so it might be useful to print the variable as a string. This is (of course) only possible when the program has been runned and it's stopped at a breakpoint and can simply be achieved by typing:
```C
printf "%s", (char *) var_address       // (char*) is in brackets because is optional
//or similarly
x/s var_address        // in general  is i
```
> ***PLEASE NOTE:*** We use in general ```x / Format Address_expression``` to show in a specific format *(i.e. s for strings, b for bytes...)* a piece of memory, which could be an address in hexadecimal or a register (in this case remember to use $ before the name of the register). *Example: we use ```x/200bx $esp``` to display the stack in bytes (x for hexadecimal which is optional since is the default). Alternatively, we could use rsp instead of esp but the syntax is the same*.

Other commands used to examine data when your program is stopped:
   - To check the assembly code of the program:
        - type ```disassemble name_of_the_function``` or ```disas name_of_the_function```
   - To show all the calls done until that moment:
        - type ```bt```, which stands for *backtrace*

### Cyclic patterns
When trying to pwn and, in particular, trying to do a stack overflow, it might be tricky to find the return address from the start of the buffer (that we want to overflow). To help us find it we can create a pattern (cyclic) and insert it into the buffer in order to see what part of the pattern overwrites the return address.
In this way, we can understand the difference in bytes, i.e. the offset (ret_addr - buff_addr), which is the "garbage"/"padding" we need to put in the buffer to overflow it and reach the start of the return address (where we will put our new address). Basically our input will then be ```garbage_of_length_offset + address_we_want_to_reach```.
- To create the pattern we can use the command: 
    ```
    pattern_create n name_of_the_pattern_file
    ``` 
    where:
    - *n* reppresent the length of the pattern which must be way bigger than the size of the buffer *(e.g. if the buffer size is 128, we can create a pattern long 300)
    - *name_of_the_pattern_file* rappresent the new file which will be created in the current directoy to save the pattern
- To run the program using a pattern as input:
    ```C
    r < name_of_the_pattern_file  
    // or similarly 
    run < name_of_the_pattern_file
    ```
    This should cause a segmentation fault and create an errore in the PC address (i.e. the IP, instruction Pointer) which will result invalid and which correspond to a piece of our pattern. 
- To finally see the offset we can type on the terminal:
    ```
    pattern_search
    ```
    We look at the registers that contain our pattern, and in particular to the IP/PC one (which name is EIP). It will show the offset we were looking for.


## Pwntools
### Basics: Processes and Communication
In this course, we aim to corrupt the memory of programs mainly by overflowing buffers. However, since sometimes it's time-consuming to do this by hand we can use a python script to do this for us. This is possible thanks to a python library called pwntools.

Firstly, we need to include the library pwntools in our python script:
```python
from pwn import *
```

Generally, then you will have to create a *"tube"* to talk to a process (i.e. connecting the script with the process you want to pwn). This can be achieved by creating a process object just like this:
```python
new_obj_name = process(path/name_of_the_process)
```
> ***PLEASE NOTE:*** from now on we will call *"new_obj_name"* just *"p"* (which stands for process) for convenience.

Once we have written our python script we can run it from terminal by doing:
```
python name_pf_the_script
```

### Sending and receiving data from processes
Now that we have a connection between the process and the python script we can use different (pwntool's) functions depending on our aim:
- To send data
    ```python
    p.send(data)              #sends data to the process (as if writing a string in terminal)    
    p.sendline(line)          #sends data plus a newline to the process (as if writing a string in terminal)  
    p.sendlineafter("_str_", line)      #sends data to the process (as if writing a string in terminal) only after reading a string specified by _str_
    ```
     > ***PLEASE NOTE:*** We can send the data to the process packed as bytes using the syntax ```b'string'``` (or with ```("string").encode('ascii')```) instead of strings, since sometimes there can be some problems with them. 
- To receive data
    ```python
    msg = p.recvall()           #msg will store all the prints from the execution in terminal of the process
    msg = p.recv(n)             #as above, but it will receive any number (n) of available bytes
    msg = p.recvline()          #receive data until a newline is encountered
    ```

### Packing
To pack data *(e.g. from the address in hex 0x... to bytes)* pwntools uses the context global variable (by default little endian) to automatically calculate how the packing should work. This is possible thanks to the function:
```python
//if we compile in a 64-bit architecture
packed_bytes = p64(data_to_pack)
//or if we compile in a 32-bit architecture
packed_bytes = p32(data_to_pack)
```
> ***PLEASE NOTE:*** p64() returns a bytes-like object *(e.g. b'some_bytes')*, so if you need to add padding to it remember to use b'A' instead of using just 'A'.

> ***PLEASE NOTE:*** It's also possible to unpack bytes by using ```u64(packed_bytes)```, which is the exact opposite of p64().

### Interactive sessions
We might also want to interact derectly with our process (on the terminal), i.e. we want to use the process in interactive mode to send commands and receive output from the process at runtime.
We do this using:
```python
# exploit goes here
p.interactive()
```
 > ***PLEASE NOTE:***  This is very common when the exercise involves the opening of a shell *(then you can use as a normal shell)*. So in this case remember to use this interactive mode rather than doing a recvall() which will not do anything good (the python script will continue to run and never stop).


```
GDB 
 r < $(python -c "print('A'*50)")   /da come input il risultato dello script
 
  +PWNTOOLS DI TRINCAW
 
 asm(shellcraft.sh())                                          /crea una shell 
 offset = cyclic_find("kaaa")                                  /ritorna la distanza della stringa kaaa sul cyclic
 c.binary.got["exit"]                                          /ottiene l'indirizzo della funzione exit in got
 c.binary.functions["win"].address                             /ottiene l'indirizzo di un metodo all'interno del
 -ROP 
 dst = context.binary.get_section_by_name(".data").header.     /ottiene l'indirizzo di un area di memoria
 r(r14=dst, r15=b"flag.txt")                                   /scrive su i registri dati
 r.call("system", [e.symbols["parameters"]])                   /richiama una funzione con parametri custom tramite ROP (aggiunge alla chain da richiamare)
 p.send(b"A" * 8 * 5 + r.chain())                              /invia la chain ROP creata
 
``` 

