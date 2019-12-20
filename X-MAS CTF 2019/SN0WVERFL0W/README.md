# SN0WVERFL0W (PWN , 25pts)

Basic bufferoverflow vulnerability. We need to leak a libc address to bypass ASLR then build a system("/bin/sh") ROP chain using re2libc technique.
