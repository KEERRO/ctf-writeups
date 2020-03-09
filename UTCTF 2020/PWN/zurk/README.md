# zurk (657 pts)

64bit ELF has a format string vulnerability with an infinite read/write loop.

All protections were disabled (except ASLR) so we can execute shellcode. My idea was to write the shellcode in the .bss section byte by byte and then leak a stack address and calculate the address of the return pointer and overwrite it with the shellcode address.

(solver attached)
