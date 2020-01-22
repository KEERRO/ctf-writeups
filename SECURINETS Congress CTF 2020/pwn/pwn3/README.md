# PWN3 (1000 pts)

That's the hardest challenge in the list.

We were given a 32bit binary after we execute it, it simply asks for a first name then prints ```Welcome,<first_name>``` then asks for a last name then prints a (kind of) biography of us containing the first name and the last name.

As usual there is user-input on the STDOUT the the first thing come to mind is a format string vulnerability .

So if we give it a "%x-%x" as input in the username prompt the output will be like "Welcome,a-32" so the first name prompt is vulnerable let's test the last name prompt the output:  "Here is ur biography!x-ffa25c69".

Both first name and last name are vulnerable to a format string.

After the analysis (using IDA or gdb) we can build our attack scenario, the ASLR is enabled on the server so we need a leak from the binary. 
We have 2 methods to exploit this scenario i'll describle them both.

Here is the 1st scenario:

1- use the first prompt to leak a stack address and a libc address

2- calculate the address of the saved return pointer of the main function and the address of the libc base and the libc system function and "/bin/sh" string.

3- Using the second prompt overwrite the saved return pointer of the main function with the address of "start" function or the entry point of the binary to have a chance to make more overwrites.

=> now the binary is in the main function again and we have 2 extra shots.

4- Overwrite the saved_return_pointer of the main function with the address of "system" in libc with the first prompt and the saved_return_pointer+8 address with "/bin/sh" string with the second one in order to perform a ```system("/bin/sh")``` after the main returns

Here is the 2nd scenario:


1- use the first prompt to leak a stack address and a libc address

2- calculate the address of the saved return pointer of the main function and the address of the libc base and the libc system function and "/bin/sh" string.

3- Using the second prompt overwrite the saved return pointer of the main function with the address of "start" function or the entry point of the binary to have a chance to make more overwrites.

PS: The RELRO is partial so the relocations are writable.

4- We will use the first prompt to overwrite the GOT entry of the "printf" function with "system"'s address in libc and the second to give the binary a "/bin/sh" input so when it performs a ```printf(input)``` call it really will perform a ```system(input)``` and if the input is "/bin/sh" it will perform a ```system("/bin/sh")``` call.

==> We have a shell :D

In the "solver.py" exploit thamer followed the 1st approach.

