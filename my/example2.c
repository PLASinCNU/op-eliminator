#include <stdio.h>

double foo( double x, double y ){

	double z = x*x*x;

	if((y+z) >= y){
		printf("y: %lf\n", y);
		return y;
	}
	else{
		printf("x: %lf\n", x);
		return x;
	}
}

int main(void){
	double x;
	double y = 10.0;
	double z;

	scanf("%lf",&x);
	z= foo(x,y);
	printf("z: %lf\n",z);
	
	return 0;
}
