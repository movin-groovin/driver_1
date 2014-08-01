
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


MODULE_LICENSE ("GPL");



static int __init hello (void)
{
    int retLen;
	char chBuf[16];
	struct file *filePtr;
	loff_t posFile = 0;
	mm_segment_t oldFs;
	
        
    printk (KERN_ALERT "Hello 123!\n");
        
    oldFs = get_fs();
	set_fs (KERNEL_DS);
	
	filePtr = filp_open ("/etc/passwd", O_RDONLY, 0);
	if (IS_ERR (filePtr)) {
		printk ("Can't open: %s - %d\n", chBuf, (int)filePtr);
		set_fs (oldFs);
		return 0;
	}
	printk ("File position: %d - %d\n", filePtr->f_pos, posFile);
	
	if ((retLen = vfs_read (filePtr, chBuf, 16 - 1, &posFile)) < 0) {
		printk ("Error at reading from: %s, ret: %d\n", chBuf, (int)retLen);
		filp_close (filePtr, NULL);
		set_fs (oldFs);
		return 0;
	}
	set_fs (oldFs);
	chBuf [15] = 0;
	printk ("A string: %s\n", chBuf);
	printk ("File position: %d - %d\n", filePtr->f_pos, posFile);
        
        
    return 0;
}

static void goodbye (void)
{
        printk (KERN_ALERT "Good 321!\n");
}

module_init(hello);
module_exit(goodbye);













