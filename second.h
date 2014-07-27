
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/unistd.h>
#include <linux/stop_machine.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/dirent.h>
#include <asm/atomic.h>



typedef long (*READ_P)(int, void*, size_t);
typedef int (*MKDIR_P) (const char*, mode_t);
typedef int (*GETDENTS_P) (unsigned int, struct linux_dirent64*, unsigned int);

typedef struct _DATA_FN {
	void *scltPtr;
	int sysNum;
	void *newPtr;
	void **oldPtr;
} DATA_FN, *PDATA_FN;


typedef struct _SYSSERV_INFO {
	void *sysPtrNew;
	void *sysPtrOld;
	unsigned sysNum;
	atomic64_t numOfCalls;
} SYSSERV_INF, *PSYSSERV_INF;










