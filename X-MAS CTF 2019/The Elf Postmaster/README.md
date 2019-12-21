# The Elf Postmaster (PWN,378pts)

We are given a 64bit ELF file and a docker file for the environment.

After analyzing the binary we can figure out it's vulnerable to 2 format string bugs the 1st is a one-shot one and the second is in an infinite loop stops when we send "end of letter" string.

So we have an infinite arbitrary read/write.

The binary is almost full protected so we need to leak everything and the RELRO is full so no GOT overwriting.

It's seccomped too whitelisting only a few syscalls I focused on ```srop,open,read,write``` cuz the ```execve``` is blacklisted.

our idea is to transform the format string vulnerability to executing a rop chain ;

1st step is to leak binary base, libc address and the saved return pointer's stack address.

2nd step is to overwrite the seip (saved eip) with our rop chain byte by byte (because why not :D)

3rd step is to send "end of letter" string to exit the loop and step toward executing our ROP chain.

==> flag on STDOUT :D

This is the longest exploit you could will ever have xD

I could optimise it a bit by creating a function that does the same thing to a different addresses passed as arguments but too lazy for now :3
