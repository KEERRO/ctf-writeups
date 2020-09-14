from z3 import *

board = [[0 for _ in range(12)] for _ in range(20)]

arr1 = [0x03,0x02,0x03,0x02,0x02,0x00,0x01,0x03,0x01,0x00,0x00,0x02,0x02,0x02,0x02,0x00,0x03,0x00,0x01,0x00,0x00,0x00,0x00,0x00]
arr2 = [0x02,0x02,0x02,0x02,0x02,0x03,0x01,0x02,0x01,0x03,0x03,0x01,0x01,0x01,0x01,0x03,0x01,0x03,0x01,0x03,0x00,0x00,0x00,0x00]
arr3 = [0x01,0x02,0x03,0x01,0x07,0x04,0x01,0x01,0x01,0x03,0x07,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]
arr4 = [0x05,0x02,0x03,0x05,0x03,0x02,0x01,0x05,0x01,0x04,0x03,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]

def first_check(a1,i,test):
	v4 = 0
	v3 = 0
	for j in range(3):
		if (test >> (2-j) )%2 :
			v4 ^= j + 1
			v3 += 1
	if (arr1[5 * a1 + i] == v4) and (arr2[5 * a1 + i] == v3):
		return 1
	else: 
		return 0

def real_first_check(a1):
	for i in range(5):
		v4 = 0
		v3 = 0
		for j in range(3):
			if (board[i + 15][3 * a1 + j]):
				v4 ^= j + 1
				v3 += 1
		if (arr1[5 * a1 + i] != v4) or (arr2[5 * a1 + i] != v3):
			return 0
	return 1

def second_check(a1):
	for i in range(3):
		v4 = 0
		v3 = 0
		for j in range(5):
			if (board[j + 15][3 * a1 + i]):
				v4 ^= j + 1
				v3 += 1
		if not (arr3[5 * a1 + i] == v4) and (arr4[5 * a1 + i] == v3):
			return 0
	return 1
def gen_second_check(a1,i,test):
		v4 = 0
		v3 = 0
		for j in range(5):
			if (test >> j)%2:
				v4 ^= j + 1
				v3 += 1
		if (arr3[5 * a1 + i] == v4) and (arr4[5 * a1 + i] == v3):
			return 1
		else: 
			return 0


def print_board():
	for i in range(20):
		for j in range(12):
			if board[i][j]:
				print("#", end="")
			else:
				print(".", end="")
		print("")

for i1 in range(4):
	for i2 in range(5):
		for test in range(8):
			if (first_check(i1,i2,test)):
				res=bin(test)[2:].rjust(3,"0")
				print (res)
				board[15+i2][0+(3*i1)]=int(res[0])
				board[15+i2][1+(3*i1)]=int(res[1])
				board[15+i2][2+(3*i1)]=int(res[2])

print_board()

for i in range(4):
	print(second_check(i),real_first_check(1))