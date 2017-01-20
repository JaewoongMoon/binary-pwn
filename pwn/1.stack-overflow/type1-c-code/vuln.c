#include <string.h>

// 이 프로그램은 버퍼 오버플로 취약점을 갖고 있다.
// suid root 로 설정되어 있다.
// 버퍼를 셸코드로 덮어쓰면 루트 셸을 획득할 수 있다.

// <컴파일관련>
// 이 파일을 컴파일 할 때는 스택 프로텍터가 동작하지 않도록 -fno-stack-protector 옵션을 주어야 한다.
// 그리고 32비트 방식으로 컴파일 되도록 -m32 옵션도 주자.
int main(int argc, char *argv[])
{
	char buffer[500];
	strcpy(buffer, argv[1]); // 입력버퍼를 500 바이트의 로컬 변수에 복사한다.
	return 0;
}
