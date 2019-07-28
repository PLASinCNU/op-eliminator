#include <stdio.h>

int foo(int x){
	if (1)
		return x;
	else
		return 0;
}

int main(void){
	int x,y;
	scanf("%d",&x);
	y=foo(x);
	printf("%d\n",y);

}
