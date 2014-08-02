
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/unistd.h>
#include <linux/stop_machine.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/dirent.h>
#include <linux/atomic.h>
#include <asm/current.h> // current
#include <linux/fdtable.h> // struct files_struct
#include <linux/spinlock.h>
#include <linux/fs.h> // struct file at line 976
#include <linux/path.h> // struct path
#include <linux/dcache.h> // struct dentry
#include <linux/sched.h> // struct task_struct

#include <linux/file.h>
#include <linux/syscalls.h>
#include <linux/completion.h>
#include <linux/kernel.h> // simple_strtoul
#include <linux/cred.h> // for commit_creds
#include <asm/param.h> // HZ value



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










