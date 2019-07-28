#include <stdio.h>

int foo (int x){
	if ( x == NULL )
		return 0;
	else
		return 1;
}

int main (void) {
	int x;

	scanf("%d",&x);

	printf("%d\n",foo(x));
	return 0;
}


