# Matrix of hell

Given a 64 bit stripped binary.

Executing, it's asking for a password then somehow checking it and printing a result message on the terminal.
<br>

![im1](executing.png)

<br>


Opening the binary on IDA, before asking for input it's initializing a matrix with some ordered chars and skipping "J" character.
first thoughts this may be "polyb cipher" with a standard matrix without a key.

<br>

![im3](matrix.png)

<br>

after that we can see it's asking for a 14 chars input.

<br>

![im4](input.png)


<br>

then it's creating a string with combination of line and column numbers of the cell of the matrix with each char in the input.
so that confirms it's a "Polybius cipher algorithm".

<br>


![im5](pol.png)


<br>

then it xors the ciphertext and compares it to another text located in the .DATA section in the binary.

the text: `B0C2A2C6A3A7C5@6B5F0A4G2B5A2`.

<br>

![im6](xor.png)

<br>

So all we have to do is xoring back the cipher text and decrypt it using and online decryptor so we get the right input.
I wrote a simple python script to xor back the cipher text.

```python
s = "B0C2A2C6A3A7C5@6B5F0A4G2B5A2"
result = ""
for i in range(len(s)):
  result += chr(ord(s[i]) ^ (i%4))
print result
```

it gives this cipher text back : `B1A1A3A5A2C4C4B5B4D3A5E1B4C1`

so we can change A with 1 and B with 2 and so on... and put it in an online decryptor in our case we're working with
[This decoding website](https://www.dcode.fr/chiffre-polybe) (remember to fill the matrix from "`A` to `Z` skipping `J).


<br>

![im7](res.png)

<br>

as we can see the plain text is `FACEBOOKISEVIL` passing it to the binary we get a greating message and the flag.

<br>

![im8](flag.png)


<br>

FLAG: `1337_FD_DDLLLKMO_KUWRRRVL_HAHAHA`
