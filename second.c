
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/unistd.h>
#include <linux/stop_machine.h>
#include <linux/slab.h>
#include <linux/uaccess.h>


//
// types and defines
//
#define MSR_LSTAR_MY 0xC0000082

typedef long (*READ_P)(int, void*, size_t);
typedef int (*MKDIR_P) (const char*, mode_t);

typedef struct _DATA_FN {
	void *scltPtr;
	int sysNum;
	void *newPtr;
	void **oldPtr;
} DATA_FN, *PDATA_FN;



//
// globals
//
void* oldRead;
void* oldMkdir;
void *sys_call_table;
struct cpumask *cpus;
const char *badDirName = "crazy";



void changeSyscalltable (void *scltPtr, int sysNum, void *newPtr, void **oldPtr) {
	// disable memory protection to writing
	asm("pushq %rax");
	asm("movq %cr0, %rax");
	asm("andq $0xfffffffffffeffff, %rax");
	asm("movq %rax, %cr0");
	asm("popq %rax");
	
	*oldPtr = ((void**)scltPtr) [sysNum];
	((void**)sys_call_table) [sysNum] = newPtr;
	
	// enable memory protection to writing
	asm("pushq %rax");
	asm("movq %cr0, %rax");
	asm("xorq $0x0000000000010000, %rax");
	asm("movq %rax, %cr0");
	asm("popq %rax");
	
	return;
}


int setFunc (void *datPtr) {
	DATA_FN *dat = (DATA_FN*)datPtr;
	
	changeSyscalltable (dat->scltPtr, dat->sysNum, dat->newPtr, dat->oldPtr);
	
	return 0;
}


ssize_t newRead (int fd, void *buf, size_t count) {
	printk ("Intercepted function sys_read\n");
	if (oldRead) return ((READ_P)oldRead) (fd, buf, count);
	else return EIO;
}


int newMkdir(const char *pathname, mode_t mode) {
	int len = strlen_user (pathname);
	char *chPtr;
	
	
	printk ("Intercepted function sys_mkdir\n");
	
	if (oldMkdir) {
		if (len <= 0) return ENOENT;
		if ((chPtr = kmalloc (len + 1, GFP_KERNEL)) == NULL) {
			printk ("Insufficient of memory, error of kmalloc\n");
			return ENOMEM;
		}
		strncpy_from_user (chPtr, pathname, len);
		chPtr[len] = '\0';
		
		if (strstr (chPtr, badDirName)) {
			printk ("Attempt to creat bad directory\n");
			kfree (chPtr);
			return EACCES;
		}
		kfree (chPtr);
		return ((MKDIR_P)oldMkdir) (pathname, mode);
	}
	else return EIO;
}


int start (void) {
	int i, lo, hi;
	void *system_call;
	unsigned char *ptr;
	DATA_FN dat = {NULL, __NR_mkdir, &newMkdir, &oldMkdir};
	cpus = kmalloc (sizeof (struct cpumask), GFP_KERNEL);
	
	
	if (!cpus) {
		printk ("Insufficient of memory, error of kmalloc\n");
		return ENOMEM;
	}
	cpumask_clear (cpus);
	cpus->bits[0] = 1;
	
	asm volatile("rdmsr" : "=a" (lo), "=d" (hi) : "c" (MSR_LSTAR_MY));
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
	else dat.scltPtr = sys_call_table;
	
	
	stop_machine(&setFunc, &dat, cpus);
	
	
	return 0;
}

void stop (void) {	
	DATA_FN dat = {sys_call_table, __NR_mkdir, oldMkdir, &oldMkdir};
	
	printk ("Bye bye\n");
	stop_machine(&setFunc, &dat, cpus);
	kfree (cpus);
	
	return;
}



module_init(start);
module_exit(stop);
MODULE_LICENSE ("GPL");


//
// Errors due to disabled write protection bit at cr0
//
/*
 * [  869.376793] supervise[5053] general protection ip:7f939d57e517 sp:7fff52f575a0 error:0 in libc-2.17.so[7f939d546000+1a4000]
[  870.963420] Intercepted function sys_mkdir
[  921.156604] supervise[5840] general protection ip:7f3bdd720517 sp:7fff87284a80 error:0 in libc-2.17.so[7f3bdd6e8000+1a4000]
 * */




