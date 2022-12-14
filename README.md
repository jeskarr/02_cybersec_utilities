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
    - ***pwntool*** *(python library)*, available to download at: http://docs.pwntools.com/en/stable/


> ***PLEASE NOTE:***  Before doing anything it's necessary to change the permissions of the directory we want to work on. We can achieve this with:   ``` chmod -R +x ./ ```


## Reverse Engineering  (+ Patching)
### Some useful commands
Let's see some commands (available to use on terminal) that might be useful for Reverse Engineering:
- ***./name_of_the_program***
    - to simply run a program in the terminal
- ***strings ./name_of_the_program***
    - to display all the strings used inside the program (e.g. if there is a psw or a flag stored it should appear)
- ***objdump -option ./name_of_the_program***
    - to display information about one or more object files. The options control what particular information to display, we can for example choose the option -d (--disassemble) which display the ASM code of the input files.

### Ida
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

We can also patch instructions on Ida by changing the actual hexadecimal values. We pass to "Hex View" so we can see the hex of the instruction we want to patch. Then as before we can patch it by doing: ``` Edit -> Patch program -> Patch byte ``` and then apply the patch to the original program as before.

> ***PLEASE NOTE:*** The instructions are identified in hex with their opcode. So if you want to change an instruction you need to change the hex/opcode with the one you want. You can find all the opcodes with the corresponding instruction at: http://ref.x86asm.net/coder64.html 
In particular, please note that the opcode for the NOP instruction is 90.

### Radare2
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
- To patch the instruction (once you've moved to the corresponding memory address) you can use:
```C
//to patch the assembly instructions
wa new_instruction_in_ASM
//to patch the bytes
wx new_bytes
```
> ***PLEASE NOTE:*** you can double check the correctness of the patch with ```pdf```

### GDB
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


To show information about the current state of the program you can use the keyword info, for example:
- to show the current conent of the registers type ``` info registers ```
- to show the current variables type ``` info variables ```

> ***PLEASE NOTE:*** If you just type info, it will show you all the possible subcommands.

Sometimes, the content of register or variables might be an hexadecimal (in the form 0x...), so it might be useful to print the variable as a string. This can be done using:
```C
printf "%s", (char *) var_address       // (char*) is in brackets because is optional
//or similarly
x/s var_address        // in general x / [Format] [Address expression]
```

Other commands used to examine data when your program is stopped:
   - To check the assembly code of the program:
        - type ```disassemble name_of_the_function``` or ```disas name_of_the_function```
   - To show all the calls done until that moment:
        - type ```bt```, which stands for *backtrace*


## Pwning

```
 x/200bx $esp                       /mostra la stack, se non c'è esp usa rsp
 r < a                              /da come input il file a (da usare con cyclic)
 r < $(python -c "print('A'*50)")   /da come input il risultato dello script
``` 

