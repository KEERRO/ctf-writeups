# Eggnog (PWN , 409pts)

We were given a 64bit  ELF file.

After analyzing, it's reading a 47 bytes from the user then calculates 14 random numbers between 0 and the length of the input. then it removes the bytes that come at one of the 14 numbers calculated before so these numbers are random indexes. Then it asks for the user permission to execute the rest of the bytes after the substraction. if the answer is "n" (no) it repeats all the process again.

We can notice that it's printing all the 14 numbers after doing the calculations so if we can predict the next 14 numbers we will be able to prevent the shellcode corruption with filling the 14 indexes calculated with junk bytes

Thanks to my teammate that recognized the PRNG and helped me to crack it.

It's the LCG algorithm ([Linear Congruential Generators](https://tailcall.net/blog/cracking-randomness-lcgs/))

So now the exploitation scenario is simple: Send random 46 bytes to the server to make it print the first 14 numbers calculated then answer with "n" to not execute them then calculate the missing parameters of the algorithm then calculate the next 14 indexes and put junk bytes at them, then send the new constructed shelcode to the server and answer with "y" to execute it.

=> We got a shell
