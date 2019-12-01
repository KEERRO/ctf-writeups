cipher = "d66t6u`y4ujbnwou3sm5bl5|tau1ent"
flag = ""
for i in range(len(cipher)):
	flag += chr(ord(cipher[i]) - ((i%3)+1))
print "securinets{%s}"%flag