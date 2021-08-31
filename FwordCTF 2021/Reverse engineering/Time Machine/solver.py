"""
ch = open("clean_diassembly.txt").read().split("\n")
ciphers = []
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

for i in range(0, len(ch), 7):
	to_process = ch[i:i+7]
	a1 = int(to_process[2].split("r11, ")[1].replace("h",""), 16)
	a1 ^= 0x1337
	res = ror(a1, 0xd, 64)
	ciphers.append(res)

print ciphers
"""
flag = ""
from pwn import *
from string import printable
ciphers = [1105125222L, 3597550946L, 84861922L, 867118355L, 2228983316L, 4106698431L, 1697040329L, 86081972L, 2137638942L, 3597550946L, 2634537178L, 2131826772L, 3418004561L, 1697040329L, 2131826772L, 1697040329L, 1213478405L, 2634537178L, 2131826772L, 1697040329L, 4064760690L, 2685652659L, 2131826772L, 3418004561L, 429896102L, 3418004561L, 3927678806L, 3465855092L, 2131826772L, 3465855092L, 4064760690L, 1420360541L, 2131826772L, 1420360541L, 1213478405L, 3418004561L, 1697040329L, 1786144152L, 2884595695L]
for c in ciphers:
	print "flag:" ,flag
	for i in printable[:-5]:
		#print i
		p = process("./a.out \\" + i, shell = True)
		data = int(p.recvline().strip())
		p.close()
		if data == c:
			flag += i
			break
