# Time traveler (1000 pts)

We were given a 64bit binary.

After the static analysis it's an encryption program.
The encryption algorithm is just a XOR operation and the key is randomly generated.

The random function is seeded with the return value of ```time(0)``` call.

We were given the encrypted bytes of the flag.

So we need to know the seed in order to generate the same key used to encrypt the flag and reverse the xor operation to get to flag in plain.

The idea of the challenge is to use a linux linux command to know the "last access date and time" (i used ```stat``` command) that's the date when the author encrypted the flag, then transform it to a timestamp value then seed the random function with that value and perform the reverse xor operation.

The solver and the binary are attached in files.
