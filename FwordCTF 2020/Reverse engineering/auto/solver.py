from pwn import *
import string
import os 

a=[]
context.log_level="error"
printables=string.printable
print len(printables)**2
for b in range(0,400,1):
    print b
    done=False        
    for i in printables:
        for j in printables:
            p=process(["./out"+str(b).rjust(3,"0"),i+j])
            data=p.recvline().strip()
            if data== "NOOOOOOOOOOOOOOOOOOOO1":
                print "FOUND"
                a.append(i+j)
                done=True
                break
            p.close()
        if done:
            break
    print a
