#include <stdio.h>
#include <ctype.h>

int foo ( char x ){
	if(isupper(toupper(x))){
		return 1;		
	}
	else{
		return 0;
	}
}

int main(void){
	char x;
	int y;
	scanf("%c",&x);
	y = foo(x);

	printf("%d\n",y);

	return 0;
	
}
