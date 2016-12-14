#include <string.h>
#include <stdlib.h>

void overflow_function (char *str)
{
	char buffer[20];

	strcpy(buffer, str); // str을 buffer 로 복사하는 함수 
}

int main()
{
	char big_string[128];
	int i;

	for (i=0; i< 128; i++){
		big_string[i] = 'A';
	}

	overflow_function(big_string);

	exit(0);
}

		
