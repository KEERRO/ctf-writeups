# author : Anis_Bosss

with open("instructions.txt") as file :
        instructions = file.readlines()

result = ""

for i in range(len(instructions)-3):
        if "movzx" in instructions[i] and "cmp" in instructions[i+1]:
                new_char = chr( int(instructions[i+1].split(",")[1],16))
                result += new_char
        elif "movzx" in instructions[i] and "xor" in instructions[i+2]:
                new_char = chr( int(instructions[i+3].split(",")[1],16) ^ 0xeb )
                result+= new_char
print result