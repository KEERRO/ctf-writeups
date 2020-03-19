rom pwn import *
import base64
import time
import string
def gen(arg):
	p = ''.join([string.ascii_letters[random.randint(0, len(string.ascii_letters)-1)] for _ in range(arg)])
	k = ''.join([string.ascii_letters[random.randint(0, len(string.ascii_letters)-1)] for _ in range(len(p))])
	return p,k
cnx = remote("misc.2020.chall.actf.co",20301)

x = int(time.time())

cnx.recvuntil("> ")
cnx.sendline("1")
data = cnx.recvline().strip()
data = str(data)
print (data)
data = data.split(" with key ")
ct = data[0]
key = data[1]
ct = base64.b64decode(ct)
key = base64.b64decode(key)
#print(key)
print(len(key))
random.seed(x)
ln = random.randint(1,30)
print(ln)
if ln == len(key):
	gen(ln)
	ln = random.randint(1,30)
	a,b = gen(ln)
	cnx.sendline("2")
	cnx.sendline(a)
	cnx.interactive()
