from pwn import *

## Get the right bytes of the key.

p = process("./generate_right_key")
data = p.recvall(timeout = 1)
p.close()


## Getting the flag

cipher = [179,163,240,179,233,10,240,20,33,135,3,177,220,172,86,154,103,62,178,229,222,17,226,74,128,50,233,211,232,171,48,25,238,210]
ci = ""
for i in cipher:
	ci += chr(i)
data = data[:-1]
data = data.split(",")
key = ""
for i in data:
	key += chr(int(i))
key = key[:len(ci)]
print "Flag: ",xor(key,ci)


## Flag: securinets{br34k1ng_prng_f0r_fun}