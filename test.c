
#include <stdio.h>

#include <unistd.h>
//#include <asm/atimic.h>

struct ONE {
	size_t		d_ino;
	size_t		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[0];
};


int main () {
	unsigned long a = 1;
	struct ONE one;

	
	printf ("Len: %d\n", sizeof one);
	//printf ("Str: %s\n", one.d_name);

	
	return 0;
}








