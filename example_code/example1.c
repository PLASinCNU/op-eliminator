#include <stdio.h>

int foo( int x, int y ){

	int z = x*x;

	if((y+z) >= y){
		printf("y: %d\n", y);
		return y;
	}
	else{
		printf("x: %d\n", x);
		return x;
	}
}

int main(void){
	int x;
	int y = 10.0;
	int z;

	scanf("%d",&x);
	       
	z= foo(x,y);

	printf("z: %d\n",z);
	
	return 0;
}
