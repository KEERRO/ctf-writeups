from z3 import *
s = Solver()
a1 = [ ]
for i in range(96):
	a1.append(BitVec("x%i"%i, 32))
	s.add(a1[i] >= ord(' '))
	s.add(a1[i] <= ord('~'))

ct = [28, 247, 202, 49, 163, 94, 0, 207, 160, 199, 95, 99, 1, 13, 200, 32, 32, 57, 183, 174, 201, 93, 94, 244, 4, 254, 131, 245, 116, 76, 19, 192, 155, 46, 107, 105, 42, 142, 57, 12, 47, 146, 227, 33, 9, 127, 66, 252, 167, 246, 97, 67, 0, 31, 183, 94, 57, 255, 122, 108, 95, 66, 120, 11, 34, 181, 173, 127, 86, 179, 116, 154, 6, 200, 72, 160, 44, 101, 224, 4, 64, 119, 119, 2, 42, 20, 2, 125, 56, 115, 32, 78, 104, 4, 116, 160]
dd = [((a1[33] + (a1[3] ^ (a1[49] ^ a1[78] ^ a1[0])&0xff) - a1[49] - a1[26] ))&0xff,(((a1[44] | (a1[69] ^ (a1[43] + a1[21] + (a1[42] & a1[58] & a1[1])))&0xff) ))&0xff,(((a1[26] ^ (a1[45] + (a1[64] ^ a1[13] & a1[2]))&0xff) - a1[34] - a1[70] ))&0xff,(((a1[76] & (a1[71] + a1[80] + (a1[82] & (a1[40] | (a1[3] - a1[41]))))&0xff) ))&0xff,(((a1[30] ^ (a1[14] | ((a1[85] ^ a1[20] ^ a1[35] ^ a1[4]) - a1[64]))&0xff) ))&0xff,((a1[70] + a1[55] + (a1[60] ^ (a1[65] + (a1[32] ^ a1[22] ^ a1[5]))&0xff) )&0xff)&0xff,(((a1[18] ^ (a1[19] ^ a1[62] ^ a1[74])&0xff) ))&0xff,(((a1[3] ^ (a1[81] ^ a1[37] ^ a1[48] ^ (a1[38] + (a1[52] ^ a1[7])))&0xff) ))&0xff,(((a1[49] | ((a1[82] & a1[26] & (a1[78] ^ a1[8])) - a1[91])&0xff) - a1[53] ))&0xff,((a1[55] + (a1[90] ^ ((a1[63] & (a1[15] ^ a1[9])) - a1[3])&0xff) - a1[88] ))&0xff,(((a1[13] | (a1[78] + (a1[84] ^ (a1[72] + (a1[24] ^ (a1[33] | a1[10])))))&0xff) ))&0xff,(((a1[5] | (a1[4] & ((a1[78] ^ a1[11]) - a1[71] - a1[41]))&0xff) ))&0xff,(((a1[91] ^ (a1[89] & (a1[92] ^ (a1[1] + (a1[71] & a1[12]) - a1[66])))&0xff) ))&0xff,((a1[22] + (a1[32] ^ (a1[21] + a1[38] + (a1[16] ^ a1[13]))&0xff) - a1[59] ))&0xff,(((a1[90] | (a1[76] ^ (a1[20] + a1[14] - a1[0]))&0xff) - a1[40] - a1[72] ))&0xff,(((a1[76] ^ (a1[76] & (a1[60] + a1[8] + a1[15] - a1[84] - a1[23]))&0xff) ))&0xff,(((a1[12] & (a1[90] & (a1[39] ^ a1[82] ^ a1[8] & (a1[5] | a1[16])))&0xff) ))&0xff,(((a1[36] ^ (a1[79] | a1[63] | (a1[70] + a1[30] + (a1[43] | a1[17])))&0xff) ))&0xff,(((a1[2] ^ (a1[19] | a1[36] ^ (a1[83] | (a1[18] - a1[87])))&0xff) - a1[80] ))&0xff,(((a1[64] ^ (a1[6] ^ a1[20] ^ (a1[82] + (a1[10] ^ (a1[19] - a1[63]))))&0xff) ))&0xff,(((a1[91] ^ (a1[80] + (a1[13] | a1[39] | a1[71] ^ (a1[57] | a1[20])))&0xff) ))&0xff,(((a1[86] ^ (a1[85] ^ a1[86] & (a1[72] ^ (a1[71] + (a1[54] ^ a1[21]))))&0xff) ))&0xff,(((a1[57] ^ (a1[19] ^ a1[65] ^ a1[14] ^ (a1[22] - a1[58]))&0xff) - a1[38] ))&0xff,(((a1[21] ^ (a1[6] ^ ((a1[26] ^ a1[72] & (a1[73] ^ a1[23])) - a1[1]))&0xff) ))&0xff,(((a1[29] & (a1[69] & (a1[36] ^ (a1[52] + (a1[16] & (a1[24] - a1[76])))))&0xff) ))&0xff,(((a1[10] | (a1[12] | ((a1[55] & (a1[38] ^ (a1[42] + a1[25]))) - a1[80]))&0xff) ))&0xff,((a1[24] + (a1[47] & ((a1[16] & (a1[20] + (a1[71] & a1[26]))) - a1[47])&0xff) ))&0xff,(((a1[88] & (a1[20] | a1[91] ^ a1[76] & a1[80] & a1[27])&0xff) - a1[13] ))&0xff,((a1[12] + (a1[4] & (a1[7] ^ (a1[79] | a1[1] & (a1[89] ^ a1[28])))&0xff) ))&0xff,(((a1[95] ^ (a1[32] ^ a1[22] ^ (a1[68] + (a1[58] ^ a1[29]) - a1[54]))&0xff) ))&0xff,(((a1[69] ^ (a1[59] ^ a1[26] & (a1[40] | a1[44] ^ a1[41] ^ a1[30]))&0xff) ))&0xff,(((a1[50] ^ (a1[28] + (a1[16] & a1[24] & a1[31]) - a1[36] - a1[86])&0xff) ))&0xff,(((a1[50] ^ (a1[37] ^ a1[69] ^ a1[54] ^ a1[36] ^ (a1[32] - a1[33]))&0xff) ))&0xff,(((a1[56] ^ (a1[12] & (a1[52] ^ (a1[94] + a1[45] + a1[22] + a1[33])))&0xff) ))&0xff,(((a1[19] ^ (a1[89] + (a1[6] ^ a1[34]) - a1[23] - a1[20] - a1[42])&0xff) ))&0xff,(((a1[10] | (a1[60] + (a1[33] | a1[72] | (a1[27] + (a1[91] ^ a1[35]))))&0xff) ))&0xff,(((a1[94] ^ (a1[3] & (a1[24] ^ a1[24] & a1[19] & (a1[42] ^ a1[36])))&0xff) ))&0xff,(((a1[17] ^ (a1[57] | a1[71] | ((a1[7] ^ (a1[88] | a1[37])) - a1[19]))&0xff) ))&0xff,(((a1[56] ^ (a1[0] ^ a1[76] & (a1[71] ^ a1[76] ^ (a1[38] - a1[9])))&0xff) ))&0xff,(((a1[22] ^ (a1[8] ^ (a1[11] + a1[20] + (a1[4] ^ (a1[57] + a1[39]))))&0xff) ))&0xff,((a1[91] + (a1[77] | (a1[85] + (a1[38] ^ (a1[67] + a1[40])) - a1[78])&0xff) ))&0xff,((a1[84] + (a1[86] ^ (a1[85] ^ a1[51] & (a1[11] ^ (a1[78] | a1[41])))&0xff) ))&0xff,(((a1[12] ^ (a1[31] ^ (a1[90] + (a1[27] ^ a1[0] ^ a1[42]) - a1[65]))&0xff) ))&0xff,(((a1[75] ^ (a1[71] ^ (a1[64] + (a1[63] ^ a1[40] & (a1[2] ^ a1[43]))))&0xff) ))&0xff,(((a1[93] ^ (a1[27] ^ (a1[35] | a1[81] ^ (a1[44] - a1[9])))&0xff) - a1[76] ))&0xff,(((a1[88] | (a1[61] & a1[85] & (a1[78] ^ a1[71] & (a1[30] | a1[45])))&0xff) ))&0xff,(((a1[24] ^ (a1[41] ^ a1[21] ^ a1[76] ^ ((a1[89] & a1[46]) - a1[90]))&0xff) ))&0xff,(((a1[86] ^ (a1[28] + (a1[61] ^ a1[36] ^ a1[47]) - a1[18])&0xff) - a1[68] ))&0xff,(((a1[95] ^ (a1[24] + (a1[8] | a1[46] ^ a1[61] ^ (a1[23] | a1[48])))&0xff) ))&0xff,((a1[19] + (a1[25] | (a1[95] + (a1[32] ^ a1[67] ^ a1[49]))&0xff) - a1[42] ))&0xff,(((a1[67] ^ ((a1[90] ^ a1[85] ^ a1[19] ^ a1[50]) - a1[36] - a1[46])&0xff) ))&0xff,(((a1[29] ^ (a1[39] ^ a1[4] & ((a1[60] ^ (a1[59] + a1[51])) - a1[56]))&0xff) ))&0xff,(((a1[91] & (a1[36] & (a1[91] + (a1[10] ^ a1[69] ^ (a1[23] + a1[52]))))&0xff) ))&0xff,(((a1[88] ^ (a1[28] & (a1[19] ^ a1[45] & (a1[52] + (a1[81] ^ a1[53]))))&0xff) ))&0xff,(((a1[62] ^ (a1[57] ^ (a1[27] + (a1[44] | ((a1[82] & a1[54]) - a1[60]))))&0xff) ))&0xff,(((a1[69] & (a1[12] ^ (a1[10] + (a1[11] ^ a1[81] ^ a1[55]) - a1[17]))&0xff) ))&0xff,((a1[88] + (a1[51] ^ ((a1[53] ^ a1[19] ^ a1[93] ^ a1[56]) - a1[36])&0xff) ))&0xff,(((a1[61] | (a1[69] | a1[16] ^ (a1[13] + (a1[11] ^ a1[18] ^ a1[57])))&0xff) ))&0xff,(((a1[89] | (a1[60] ^ a1[39] ^ a1[67] ^ a1[58])&0xff) ))&0xff,((a1[10] + (a1[40] ^ (a1[69] ^ a1[4] & (a1[59] - a1[86] - a1[46]))&0xff) ))&0xff,(((a1[40] & (a1[68] | a1[18] ^ ((a1[76] ^ a1[84] ^ a1[60]) - a1[66]))&0xff) ))&0xff,(((a1[54] & (a1[53] ^ a1[82] ^ (a1[56] + (a1[81] ^ (a1[61] - a1[87]))))&0xff) ))&0xff,(((a1[56] ^ ((a1[67] ^ ((a1[41] ^ a1[62]) - a1[42])) - a1[3])&0xff) - a1[44] ))&0xff,(((a1[14] ^ (a1[55] | a1[30] ^ (a1[90] | a1[23] | a1[53] ^ a1[63]))&0xff) ))&0xff,(((a1[60] & (a1[59] ^ a1[44] ^ a1[46] ^ (a1[71] | a1[29] & a1[64]))&0xff) ))&0xff,(((a1[85] | ((a1[43] ^ a1[58] & a1[88] & a1[65]) - a1[49] - a1[73])&0xff) ))&0xff,((a1[12] + a1[88] + (a1[40] ^ (a1[18] ^ (a1[16] + a1[66] - a1[89]))&0xff) ))&0xff,(((a1[59] ^ (a1[90] & ((a1[30] ^ a1[9] ^ a1[3] ^ a1[67]) - a1[48]))&0xff) ))&0xff,(((a1[50] & (a1[0] | a1[51] ^ a1[11] ^ a1[36] ^ a1[4] ^ a1[68])&0xff) ))&0xff,(((a1[73] ^ (a1[0] ^ ((a1[4] ^ a1[81] ^ a1[55] ^ a1[69]) - a1[19]))&0xff) ))&0xff,(((a1[48] ^ (a1[81] ^ a1[12] ^ a1[63] & (a1[15] | a1[37] ^ a1[70]))&0xff) ))&0xff,(((a1[51] ^ (a1[57] ^ ((a1[6] ^ a1[77] ^ a1[87] ^ a1[71]) - a1[80]))&0xff) ))&0xff,(((a1[12] & (a1[76] ^ a1[57] ^ a1[93] ^ a1[89] & a1[72])&0xff) - a1[92] ))&0xff,(((a1[49] ^ (a1[87] + (a1[6] ^ a1[65] ^ a1[94] ^ a1[73]) - a1[56])&0xff) ))&0xff,(((a1[10] ^ (a1[35] + (a1[12] | a1[60] ^ a1[74]) - a1[58])&0xff) - a1[80] ))&0xff,(((a1[49] ^ (a1[68] ^ (a1[94] + (a1[71] ^ (a1[37] + a1[75] - a1[50]))))&0xff) ))&0xff,(((a1[66] ^ ((a1[53] | a1[65] ^ a1[15] & (a1[83] + a1[76])) - a1[15])&0xff) ))&0xff,(((a1[18] ^ (a1[91] & (a1[30] ^ a1[8] ^ a1[30] ^ (a1[56] + a1[77])))&0xff) ))&0xff,((a1[45] + (a1[55] ^ (a1[46] ^ ((a1[58] ^ (a1[79] | a1[78])) - a1[46]))&0xff) ))&0xff,(((a1[86] ^ (a1[31] ^ a1[94] ^ a1[24] & (a1[23] | a1[93] | a1[79]))&0xff) ))&0xff,(((a1[21] & (a1[7] ^ a1[46] ^ a1[63] & (a1[67] | (a1[80] - a1[55])))&0xff) ))&0xff,(((a1[1] | (a1[48] ^ a1[53] ^ a1[44] ^ a1[20] ^ a1[30] & a1[81])&0xff) ))&0xff,(((a1[25] | (a1[1] + (a1[23] ^ a1[70] ^ a1[82]) - a1[51] - a1[14])&0xff) ))&0xff,(((a1[37] ^ (a1[22] ^ (a1[58] | a1[5] | a1[60] ^ (a1[39] | a1[83])))&0xff) ))&0xff,(((a1[51] ^ (a1[51] & ((a1[91] | a1[74] ^ (a1[9] | a1[84])) - a1[6]))&0xff) ))&0xff,(((a1[81] ^ (a1[2] ^ a1[19] ^ a1[62] & (a1[47] + (a1[71] ^ a1[85])))&0xff) ))&0xff,(((a1[72] ^ (a1[33] & (a1[94] ^ a1[58] ^ a1[70] ^ (a1[84] + a1[86])))&0xff) ))&0xff,(((a1[44] | (a1[80] & (a1[88] ^ (a1[20] | a1[36] ^ a1[44] & a1[87])))&0xff) ))&0xff,(((a1[81] ^ (a1[38] ^ a1[94] ^ a1[25] & (a1[50] ^ (a1[88] - a1[0])))&0xff) ))&0xff,(((a1[3] | (a1[84] | a1[93] ^ (a1[11] | a1[66] & (a1[63] ^ a1[89])))&0xff) ))&0xff,(((a1[52] & (a1[13] ^ a1[85] & (a1[16] + (a1[95] ^ (a1[67] | a1[90]))))&0xff) ))&0xff,(((a1[44] ^ (a1[68] ^ a1[78] ^ (a1[74] + (a1[80] ^ (a1[51] + a1[91]))))&0xff) ))&0xff,(((a1[18] ^ (a1[15] ^ (a1[33] | a1[30] & (a1[87] ^ (a1[92] - a1[59]))))&0xff) ))&0xff,(((a1[67] & (a1[39] ^ (a1[76] + (a1[58] ^ a1[15] ^ a1[93]) - a1[6]))&0xff) ))&0xff,(((a1[65] & (a1[77] & (a1[66] ^ (a1[0] | a1[72] ^ a1[80] ^ a1[94])))&0xff) ))&0xff,(((a1[83] ^ (a1[55] | ((a1[7] ^ a1[70] & (a1[8] ^ a1[95])) - a1[28]))&0xff) ))&0xff]
kek = "FWORDctf"
for i, j in enumerate(kek):
	s.add(ord(j) == a1[i])
for i, j in enumerate(dd):
	s.add(j == ct[i])
flag = ""
while s.check() == sat:
	flag = ""
	modl = s.model()
	#print modl
	for i in a1:
		flag += chr(modl[i].as_long())
	print flag
	print "\n"
	block = [ ]
	for i in a1:
		block.append(i != modl[i])
	s.add(Or(block))
else:
	print "Bara nayek orgeeeed"