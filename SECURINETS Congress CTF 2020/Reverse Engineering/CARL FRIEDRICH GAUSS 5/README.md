# CARL FRIEDRICH GAUSS 5 (1000 pts)

We were given a 64bit binary.

It takes the flag as argument.

After we open the binary in IDA and read the decompilation it verifies the flag through multiple equations.

The idea is simple create a solver using the [z3-solver](https://github.com/Z3Prover/z3) pyhon module. in order to calculate the equations for us and construct the right input.


Big thanks to [Anis_Boss](https://github.com/AnisBoss) the author of this challenge and its solver script.
