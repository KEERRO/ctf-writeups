# PWN2 (1000 pts)

We were given a 32bit binary. the execution flow is simple it prints the string ```Try to exploit me:``` then asks for input then it concatenates ```JUNKJUNK``` to it and prints the restult on the STDOUT.

For example if we provide "ABC" as input it prints "JUNKJUNKABC".

We can try a ```%x-%x``` as input the result printed is ```JUNKJUNKffd187e0-f7f1e5c0``` so the binary has a format string vulnerability.

After the static analysis (Using IDA or GDB) we can see that after the process described before it executes ```system("/bin/true")``` when the string "/bin/true" is located in the ```DATA``` section of the binary.


So the exploit scenario is simple, We will use the format string vulnerability to change the "/bin/true" string to "/bin/bash". "/bin/" is ready so we need to overwrite only the last 4 bytes. "true" ==> "bash". 
