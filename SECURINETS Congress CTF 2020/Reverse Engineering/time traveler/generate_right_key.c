#include <stdio.h>
#include <time.h>
int abss(long long k){
	if(k>=0)
		return k;
	return -(k);
}
int main(){
	long long s = 1579409148;
	srand(s);
	for(int i = 0 ; i<50 ; i++){
		printf("%d,",abss(rand())&255);
	}
	return 0;
}
