ch=  open("parsed_inst.txt").read().split("\n")
res = ""
for i in ch:
	print "xxx ",i, " xxx"
	res += "s.add(" + i + ")\n"
print res