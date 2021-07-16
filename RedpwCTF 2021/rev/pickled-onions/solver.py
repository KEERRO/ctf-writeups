from z3 import *
s = Solver()

def jib_el_i(data):
    data = data[data.find("I")+1:]
    return int(data[:data.find("\\n")])


base = b"\x80\x04I102\nI108\nI97\nI103\nI123\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI65\nI125\n"
def get_arguments(data):
    data = data.replace(base, "")
    lines = data.split("\\n")
    if lines[0].endswith("p0"):
        lines[0] = lines[0].replace(b"p0",b"")
        lines[1] = lines[1].replace(b"p1",b"")
        p0 = lines[0].count(b"0")
        p1 = lines[1].count(b"0") + p0
    else:
        lines[0] = lines[0].replace(b"p1",b"")
        lines[1] = lines[1].replace(b"p0",b"")
        p1 = lines[0].count(b"0")
        p0 = lines[1].count(b"0") + p1
    return (p0, p1)

lines = open("final").read().strip().split("\n")
flag = []


for i in range(64):
    flag.append(BitVec("a%i"%i, 8))

flag[0] == ord('f')
flag[1] == ord('l')
flag[2] == ord('a')
flag[3] == ord('g')


for line in lines:
    p0, p1 = get_arguments(line)
    if "pickledhorseradish" in line: 
        i = jib_el_i(line)
        s.add( (flag[p0] + flag[p1]) == i)
    elif "pickledcoconut" in line:
        i = jib_el_i(line)
        s.add( (flag[p0] - flag[p1]) == i)
    elif "pickledlychee" in line:
        i = jib_el_i(line)
        s.add( (flag[p0] ^ flag[p1]) == i)
    elif "pickledcrabapple" in line:
        s.add(flag[p0] == flag[p1])
    elif "pickledportabella" in line:
        s.add(flag[p0] != flag[p1])
    elif "pickledquince" in line:
        s.add(flag[p0] <= flag[p1])
    elif "pickledeasternmayhawthorn" in line:
        s.add(flag[p0] >= flag[p1])


flg = ""


if s.check() == sat:
    modl = s.model()
    for i in range(64):
        flg += chr(modl[flag[i]].as_long())
    print "flag: ",flg[::-1]
else: 
    print "NOT SOLVABLE"

