#include<stdio.h>

int main(int argc, char *argv[]){
	char Str = argv[1][0];
	unsigned int v4 = 1;
	unsigned int v9 = ((Str + v4) << 10) ^ (Str + v4);
	v4 = (v9 >> 1) + v9;
	unsigned int v10 = (((8 * v4) ^ (unsigned int)v4) >> 5) + ((8 * v4) ^ v4);
	unsigned int v11 = (((16 * v10) ^ v10) >> 17) + ((16 * v10) ^ v10);
	printf("%u\n",((((v11 << 25) ^ v11) >> 6) + ((v11 << 25) ^ v11)));
	return 0;
}
