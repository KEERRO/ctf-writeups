from z3 import *

s = Solver()
a1 = Int("a1")
a2 = Int("a2")
a3 = Int("a3")
a4 = Int("a4")
a5 = Int("a5")
a6 = Int("a6")
a7 = Int("a7")
a8 = Int("a8")

for i in range(1,9):
	s.add(globals()['a%i'%i]<120,globals()['a%i'%i]>48)


s.add((a1*a2)*1003+(a3*13)+(a1*a3-100) == 11060103)
s.add(a4 == 103)
s.add((a4*a6)-1337 + a5*101 - (a4+a5+137) + (a4*a5 - 1337 * 13) == 12557)
s.add(a7*a8+a8%19 == 11520)

print s.check()
print s.model()
modl = s.model()
res=""
for i in range(1,9):
    obj = globals()['a%i' % i]
    c = modl[obj].as_long()
    res = res + chr(c)
print "flag: securinets{%s}"%res

## flag: securinets{flaghere}
