#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

int foo(int x){
	char y[10];
	sprintf(y,"%d",x);
	if (isdigit(*y))
		return 1;
	else
		return 0;
}

int main(void){
	int x,y;

	scanf("%d",&x);
	y=foo(x);	
	printf("%d\n",y);
	return 0;
}
