def ROR(x, n, bits = 8):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))
 
def ROL(x, n, bits = 8):
    return ROR(x, bits - n, bits)
cihper = "\xd0\x99\xe4\x99\xbe\xbc\x60\xba\xbe\xb3\x60"
flag = ""
for i in range(len(cihper)):
	if i%2 == 1:
		flag += chr(ROL(ord(cihper[i]),1))
	else:
		flag += chr(ROR(ord(cihper[i]),1))
print "securinets{%s}"%flag