# PWN1 (1000 pts)

We were given a 32 bit binary. After a simple static analysis we can figure out that it has a format string vulnerability.

The execution flow of the binary is simple, it just prints the string ```lemme check ur skills``` then asks for input and prints it back to the STDOUT.

After the analysis we know that after printing back the input it compares a global offset located in the ```data``` section initialized with ```0x12345678``` if it's equal to ```0xc0febabe``` it executes ```system("/bin/cat flag.txt")```.

The exploitation scenario is simple, we need to use the format string vulnerability to change the variable content to ```0xc0febabe``` since the ASLR doesn't affect the ELF sections addresses.

You can find the solver and the binary in the attached files.

