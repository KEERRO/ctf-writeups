# Error program

I think we solved this problem using an unintended way.

- UAF in preview feature we can view the data of freed chunk => leak main arena of unsorted chunk => libc pointer \o/

- Leak pie using the format string bug by writing enough bytes in the tack until we reach pie address and since printf stops at null byte it'll continue printing buffer content until it reaches the first null terminator which is the MSB of pie address we want to leak. the real vunlerabity here is it performs memset after it reads buffer content not before, so we  can find useful addresses in the stack frame of the fuction we can leak.

- Now we got libc and pie leak so we can use the UAF bug in the Edit feature in order to build a fake chunk with fd and bk pointing to the address of the list of chunks in bss section in order to pull off a unsafe unlink attack => we can write any pointer we want in the list \o/ .

- Write the address of ```__free_hook``` in the array list in bss and use Edit feature to edit that fake chunk(pointing to free_hook) and write system in it.

- Build a new chunk with ```/bin/sh``` as data and free that chunk to execute ```free("/bin/sh")``` which is ```system("/bin/sh")``` => Got shell \o/.

Solved attached.
