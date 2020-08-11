from z3 import *

def calculate(cipher,keys):
    s = Solver()
    flag = []
    for i in range(10):
        flag.append(BitVec("a%i"%i,8))
        s.add(And(flag[i]<=126,flag[i]>=32))

    for i,j in enumerate(cipher):
        res = 0
        for k in range(10):
            res = (res + (flag[k] * keys[i][k])&0xff )&0xff
        s.add(res == ord(j))
    print s.check()
    modl = s.model()
    res = ""
    for i in range(len(flag)):
        res += chr(modl[flag[i]].as_long())
    return res

def main():
    keys = [
        [0xb9,0xfe,0x45,0x3b,0xd5,0x6e,0xd4,0x80,0xde,0x57],
        [0x55,0xc5,0x86,0xc5,0xe0,0x74,0x51,0x13,0x58,0x8e],
        [0xb2,0xb9,0x8d,0x88,0x59,0x76,0x69,0x49,0x01,0xb2],
        [0x27,0x6e,0xdd,0xa2,0x7f,0x1e,0x52,0xb9,0x7d,0x4d],
        [0x98,0xf0,0x7f,0x24,0x53,0x1d,0x28,0xe9,0xa4,0xa8],
        [0xc9,0x4b,0xd0,0xfa,0xa6,0xf0,0xb4,0x45,0xbe,0x29],
        [0x2e,0x3a,0x20,0x85,0xcf,0x5c,0xda,0xc3,0xb3,0x81],
        [0x67,0x69,0xda,0xa1,0x01,0x20,0x8f,0xe8,0x23,0x00],
        [0x1f,0x0e,0x68,0xc0,0x25,0xbc,0x73,0x67,0x12,0x5f],
        [0xce,0xd7,0x74,0x78,0x69,0x65,0x17,0x61,0xce,0xad]
    ]
    ciphers = []
    ciphers.append("\x4e\x5d\x59\x26\xfa\x8e\x54\x95\x2f\x3c")
    ciphers.append("\x90\xe6\xa1\xaf\xad\x45\x3a\x5a\x2e\xb3")
    ciphers.append("\xfb\xf0\xb4\xed\x80\x4d\xed\x01\x4e\x96")
    ciphers.append("\x52\xab\xba\xd5\x1f\xf1\xed\xe3\x1c\xe8")
    flag = ""
    for cipher in ciphers:
        flag += calculate(cipher,keys)
    print "Flag: ",flag

if __name__ == "__main__":
    main()

#Poseidon{M4tRix_G0T_Invers3ed_H3ll_Y3ah}