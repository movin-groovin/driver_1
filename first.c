
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <unistd.h>


MODULE_LICENSE ("GPL");



static int __init hello (void)
{
        int retVal, fd;
        
        
        printk (KERN_ALERT "Hello 123!\n");
        //fd = 
        
        
        return 0;
}

static void goodbye (void)
{
        printk (KERN_ALERT "Good 321!\n");
}

module_init(hello);
module_exit(goodbye);













