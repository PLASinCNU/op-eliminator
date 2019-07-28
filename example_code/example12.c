#include <stdio.h>
#include <stdlib.h>
unsigned char even(unsigned char x){
	unsigned char even = 170; //1010 1010
	return x & even;
}

unsigned char odd(unsigned char x){
	unsigned char odd = 85; // 0101 0101
	return x & odd;
}

int foo(unsigned char x,unsigned char y, unsigned char z){
	if ( x == y&z){
		return 1;
	}else
		return 0;
}

int main(void){

	unsigned char x,y,z;
	int rtn;
	
	scanf("%c",&x);
	
	y = even(x);
	z = odd(x);
	rtn = foo(x,y,z);

	printf("%d\n",rtn);
	
	return 0;
}
