
#
# http://www.antiwomen.ru/ff/viewtopic.php?t=34785&highlight=%CF%EB%E0%E2%EB%E5%ED%E8%E5+%F2%E8%F2%E0%ED%E0
# http://www.linuxjournal.com/article/8110?page=0,1 - как читать - записывать файлы
# http://habrahabr.ru/post/110369/
# http://rus-linux.net/MyLDP/BOOKS/drivers/linux-device-drivers-00.html
# http://rus-linux.net/kos.php?name=/papers/boot/index.html#toc
# http://commons.oreilly.com/wiki/index.php/Network_Security_Tools/Modifying_and_Hacking_Security_Tools/Fun_with_Linux_Kernel_Modules#The_System_Call_Table
# http://www.opennet.ru/base/dev/intercept_lnx.txt.html
# http://www.cyberciti.biz/tips/build-linux-kernel-module-against-installed-kernel-source-tree.html
# http://wiki.opennet.ru/Linux_kernel_debug
# http://www.opennet.ru/docs/RUS/lki/
# http://www.infosecwriters.com/hhworld/hh9/lvtes.txt - hack
# http://stackoverflow.com/questions/1184274/how-to-read-write-files-within-a-linux-kernel-module - file operations
# 

obj-m := first.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
