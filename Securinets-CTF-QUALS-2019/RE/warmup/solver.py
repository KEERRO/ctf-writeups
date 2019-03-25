
#Author : kerro 
#warmup challenge(reverse engineering) for securinets Quals CTF.

import base64
#pos is a function that give the position same in the binary
def pos(x,y):
	for i in range(len(y)):
		if y[i] == x:
			return i
charset="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

flag_encoded = [0]*36
flag_encoded[0] = ord(charset[28])
flag_encoded[3] = ord('j')
flag_encoded[4] = flag_encoded[0]+1
flag_encoded[12] = flag_encoded[4]-1
flag_encoded[22] = flag_encoded[4]-1
flag_encoded[24] = flag_encoded[4]-1
flag_encoded[1] = ord(charset[54])
flag_encoded[2] = ord(charset[((28+pos(chr(flag_encoded[1]),charset))>>2)+1])
flag_encoded[10] = flag_encoded[2]
flag_encoded[6] = flag_encoded[3]-32
flag_encoded[7] = ord('p')
flag_encoded[11] = 48
flag_encoded[23] = 48
flag_encoded[35] = flag_encoded[11]+9
flag_encoded[8] = flag_encoded[0] - 1 
flag_encoded[27] = flag_encoded[4] + 2
flag_encoded[31] = flag_encoded[27]
flag_encoded[9] = flag_encoded[27] + 7
flag_encoded[25] = flag_encoded[27] + 7
flag_encoded[13] = flag_encoded[1] + 1 
flag_encoded[17] = flag_encoded[1] + 1 
flag_encoded[21] = flag_encoded[1] + 1 
flag_encoded[15] = flag_encoded[7] + 3
flag_encoded[14] = flag_encoded[15] + 1 
flag_encoded[19] = ord('z')
flag_encoded[34] = flag_encoded[0] - 33
flag_encoded[5] = 88
flag_encoded[20] = 88
flag_encoded[29] = 88
flag_encoded[33] = 88
flag_encoded[26] = 49
flag_encoded[16] = flag_encoded[9] - 32
flag_encoded[28] = flag_encoded[16]
flag_encoded[18] = flag_encoded[7]-30
flag_encoded[30] = flag_encoded[18]
flag_encoded[32] = flag_encoded[4]

flag_encoded_chars = "" #chars for the encoded flag
for i in flag_encoded:
	flag_encoded_chars += chr(i)
print "the encoded flag: ",f_e
print "the decoded flag: ",base64.b64decode(flag_encoded_chars)
