
// gcc -std=gnu99 -o test test.c

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
//#include <asm/atimic.h>

struct ONE {
	size_t		d_ino;
	size_t		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[0];
};


int main (int argc, char **argv) {
	/*unsigned long a = 1;
	struct ONE one;
	char *chPtr;
	long val = strtoul ("qwert", &chPtr, 10);
	
	
	printf ("Value: %d\n", val);
	printf ("Len: %d\n", sizeof one);
	//printf ("Str: %s\n", one.d_name);
	
	for (a = 0; a < argc; ++a) printf ("Str: %s\n", argv[a]);
	pause ();*/
	
	char *chPtr = "/proc/modules";
	char buf1 [50], buf2[50];
	int fd = open (chPtr, O_RDONLY, 0);
	int ret = read (fd, buf1, 49);
	buf1 [49] = '\0';
	printf ("Pos: %d\n", lseek (fd, 0, SEEK_CUR));
	printf ("lseek ret: %d\n", lseek (fd, 0, SEEK_SET));
	ret = read (fd, buf2, 49);
	buf2[49] = '\0';
	printf ("1 - %s\n\n2 - %s\n", buf1, buf2);

	
	return 0;
}

/*
[ 1295.995226] BUG: unable to handle kernel NULL pointer dereference at 000000000000001e
[ 1295.995229] IP: [<ffffffffa0232172>] needHideProc+0xdf/0x1ff [second]
[ 1295.995235] PGD 5cfd2067 PUD 12492067 PMD 0 
[ 1295.995237] Oops: 0000 [#1] SMP 
[ 1295.995243] CPU 1 
[ 1295.995244] Modules linked in: second(O) binfmt_misc nfsd nfs nfs_acl auth_rpcgss fscache lockd sunrpc vfat fat loop fuse coretemp crc32c_intel snd_intel8x0 snd_ac97_codec snd_pcm snd_page_alloc snd_seq snd_seq_device evdev snd_timer processor psmouse thermal_sys snd button serio_raw soundcore ac97_bus pcspkr shpchp iTCO_wdt iTCO_vendor_support ext3 mbcache jbd sg sr_mod sd_mod cdrom crc_t10dif usbhid ata_generic hid uhci_hcd ata_piix ahci libahci libata floppy ehci_hcd scsi_mod e1000 usbcore usb_common [last unloaded: scsi_wait_scan]
[ 1295.995277] 
[ 1295.995279] Pid: 7607, comm: sudo Tainted: G           O 3.2.0-4-amd64 #1 Debian 3.2.57-3 Parallels Software International Inc. Parallels Virtual Platform/Parallels Virtual Platform
[ 1295.995284] RIP: 0010:[<ffffffffa0232172>]  [<ffffffffa0232172>] needHideProc+0xdf/0x1ff [second]
[ 1295.995288] RSP: 0018:ffff88005b2f5e38  EFLAGS: 00010282
[ 1295.995289] RAX: fffffffffffffffe RBX: ffff88001d631ec0 RCX: 0000000000000020
[ 1295.995291] RDX: 000000010003cf7e RSI: 0000000000000001 RDI: 0000000000000202
[ 1295.995292] RBP: ffff88005b2f5fd8 R08: 0000000000000001 R09: ffff88005b2f5c48
[ 1295.995294] R10: ffff88005b1144c0 R11: ffff88005b1144c0 R12: fffffffffffffffe
[ 1295.995297] R13: ffff88005bbf5222 R14: 00007ffffffff000 R15: 0000000000000001
[ 1295.995301] FS:  00007f0b299f47c0(0000) GS:ffff88005fc20000(0000) knlGS:0000000000000000
[ 1295.995303] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[ 1295.995305] CR2: 000000000000001e CR3: 000000001d699000 CR4: 00000000000006e0
[ 1295.995388] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[ 1295.995390] DR3: 0000000000000000 DR6: 00000000ffff0ff0 DR7: 0000000000000400
[ 1295.995392] Process sudo (pid: 7607, threadinfo ffff88005b2f4000, task ffff88005b004740)
[ 1295.995393] Stack:
[ 1295.995394]  0000000000000000 ffff88005bbf5223 ffff88005bbf5210 0000000000000030
[ 1295.995397]  ffff88005bbf5222 00000000000000d8 0000000000000018 ffffffffa02322f8
[ 1295.995400]  ffff88005b2f5ec8 ffff88005bbf5228 0000000002344b78 00000000000000d8
[ 1295.995403] Call Trace:
[ 1295.995406]  [<ffffffffa02322f8>] ? clearDirEntries+0x66/0x85 [second]
[ 1295.995409]  [<ffffffffa0232407>] ? newGetDents+0xf0/0x180 [second]
[ 1295.995774]  [<ffffffff810eb5f8>] ? kmem_cache_free+0x2d/0x69
[ 1295.995862]  [<ffffffff81354a12>] ? system_call_fastpath+0x16/0x1b
[ 1295.995864] Code: df e8 fb 6f ec e0 48 85 c0 49 89 c4 75 16 48 89 de 48 c7 c7 56 30 23 a0 31 c0 e8 88 70 11 e1 e9 8f 00 00 00 4c 89 b5 48 e0 ff ff <48> 83 78 20 00 75 33 48 89 de 48 c7 c7 66 30 23 a0 31 c0 e8 64 
[ 1295.995884] RIP  [<ffffffffa0232172>] needHideProc+0xdf/0x1ff [second]
[ 1295.995887]  RSP <ffff88005b2f5e38>
[ 1295.995888] CR2: 000000000000001e
[ 1295.995890] ---[ end trace d3ec686b2224fc47 ]---

*/







