#include <stdio.h>

int foo( int x ){

	int x3 = x*x*x;

	if((x3-x)%3==0){
		return 1;
	}
	else{
		return 0;
	}
}

int main(void){
	int x;
	int y;
	scanf("%d",&x);
	       
	y= foo(x);

	printf("y: %d\n",y);
	
	return 0;
}
