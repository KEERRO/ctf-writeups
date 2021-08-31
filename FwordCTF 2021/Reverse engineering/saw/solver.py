ch = open("parsed_disassembly.txt").read().split('\n')
arr = [0]*400
for i in range(0, len(ch), 11):
	to_process = ch[i:i+11]
	idx = int(to_process[2][to_process[2].find("[edi+")+ 5:to_process[2].find("]")], 16)
	#print hex(idx)
	opr  = int(to_process[3][to_process[3].find("cx, ")+ 4:], 16)
	#print hex(opr)
	cmpp = int(to_process[5][to_process[5].find("cx, ")+ 4:], 16)
	if cmpp:
		arr[idx] |= 1 << opr
res = ""
for i in arr:
	res += chr(i)
print res