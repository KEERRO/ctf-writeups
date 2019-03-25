# Warmup challenge (RE)
Given a stripped 64 bit binary.
executing it, asking for a passcode then somehow it will get checked and a result message appears on the terminal.
![im1](executing.png)
After opening the binary in IDA and entering decompilation mode it does some encodings on the binary and it checks the result by doing some calculations on the characters.
![im2](checksb64.png)
so first of all we have to identify the encoding algorithm.
We can use 2 methods to do that ltrace or setting breakpoints on a debugger and check the output of the encoding function maybe we can identify it by format.
## ltrace:
![im3](checksb64.png)
