ch = open("parsed_assembly.txt").read().split("\n")
lista_s7i7a = []
res = ""
for i in range(0, len(ch), 7):
	to_process = ch[i:i+7]
	if " mov     r13, 1" in to_process[5]:
		for i in to_process:
			res += i + "\n"
print res
