
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/unistd.h>



#define MSR_LSTAR 0xc0000082
typedef ssize_t (*READ_P)(int, void*, size_t);
typedef int (*MKDIR_P) (const char*, mode_t);



READ_P oldRead;
MKDIR_P oldMkdir;
void *sys_call_table;
const char *badDirName = "crazy";



ssize_t newRead (int fd, void *buf, size_t count) {
	printk ("Intercepted function sys_read\n");
	if (oldRead) return oldRead (fd, buf, count);
	else return EIO;
}


int newMkdir(const char *pathname, mode_t mode) {
	printk ("Intercepted function sys_mkdir\n");
	
	if (oldMkdir) {
		// это плохая проверка, адрес все равно может быть левым, нужно лучше разобраться.
		//if (pathname == NULL) return ENOENT;
		//if (!strcmp (pathname, badDirName)) {
		//	printk ("Attempt to creat bad directory\n");
		//	return EACCES;
		//}
		return oldMkdir (pathname, mode);
	}
	else return EIO;
}


int start (void) {
	int i, lo, hi;
	void *system_call;
	unsigned char *ptr;
	
	
	asm volatile("rdmsr" : "=a" (lo), "=d" (hi) : "c" (MSR_LSTAR));
	system_call = (void*)(((long)hi<<32) | lo);
	
	// 0xff14c5 - is opcode of relative call instraction at x64 (relative address is 4 byte value)
	// 500 in cycle is rather dangerous
	for (ptr = system_call, i = 0; i < 500; i++) {
		if (ptr[0] == 0xff && ptr[1] == 0x14 && ptr[2] == 0xc5) {
			sys_call_table = (void*)(0xffffffff00000000 | *((unsigned int*)(ptr+3)));
			break;
		}
		ptr++;
	}
	
	printk ("Have found sys_call_table address: %p\n", sys_call_table);
	
	if (!sys_call_table) return EPERM;
	
	// disable memory protection to writing
	asm("pushq %rax");
	asm("movq %cr0, %rax");
	asm("andq $0xfffffffffffeffff, %rax");
	asm("movq %rax, %cr0");
	asm("popq %rax");
	
	//oldMkdir = (MKDIR_P)(((void**)sys_call_table) [__NR_mkdir]);
	//((void**)sys_call_table) [__NR_mkdir] = &newMkdir;
	
	// enable memory protection to writing
	asm("pushq %rax");
	asm("movq %cr0, %rax");
	asm("xorq $0x0000000000001000, %rax");
	asm("movq %rax, %cr0");
	asm("popq %rax");
	
	
	return 0;
}

void stop (void) {
	// disable memory protection to writing
	asm("pushq %rax");
	asm("movq %cr0, %rax");
	asm("andq $0xfffffffffffeffff, %rax");
	asm("movq %rax, %cr0");
	asm("popq %rax");
	
	//((void**)sys_call_table) [__NR_mkdir] = oldMkdir;
	
	// enable memory protection to writing
	asm("pushq %rax");
	asm("movq %cr0, %rax");
	asm("xorq $0x0000000000001000, %rax");
	asm("movq %rax, %cr0");
	asm("popq %rax");
	
	printk ("Bye bye\n");
	
	return;
}



module_init(start);
module_exit(stop);
MODULE_LICENSE ("GPL");



/*
 * [  869.376793] supervise[5053] general protection ip:7f939d57e517 sp:7fff52f575a0 error:0 in libc-2.17.so[7f939d546000+1a4000]
[  870.963420] Intercepted function sys_mkdir
[  921.156604] supervise[5840] general protection ip:7f3bdd720517 sp:7fff87284a80 error:0 in libc-2.17.so[7f3bdd6e8000+1a4000]
 * */




