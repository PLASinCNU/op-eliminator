#include <stdio.h>

int foo(double x){
	double y = x*x;
	if(y > x)
		return 1;
	else
		return 0;
}
int main(void){
	double x;
	scanf("%lf",&x);

	printf("%d\n",foo(x));
	return 0;
}
