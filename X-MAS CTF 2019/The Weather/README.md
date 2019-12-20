# The Weather (pwn , 127pts)

We were given a remote service and a docker file. the binary is recompiled every time we connect to the service then sent to us through it base64 encoded.

After analyzing 2 or 3 binaries, we can figure out that their behaviour is the same and they're vulnerable to a stack based buffer overflow. But the offset to the saved return pointer is changing some addresses too like the "pop rdi; ret" gadget..

So the idea is to build an exploit that dynamicly and automaticly extract the addresses and calculates the offset to the saved return pointer then build a system("/bin/sh") ROP chain using the ret2libc technique. 
