#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>

#define CONFIG_PTE_SPRAY_AMOUNT 1024

#define SPINLOCK(cmp) while (cmp) { usleep(10 * 1000); }

#define _pte_index_to_virt(i) (i << 12)
#define _pmd_index_to_virt(i) (i << 21)
#define _pud_index_to_virt(i) (i << 30)
#define _pgd_index_to_virt(i) (i << 39)

#define PTI_TO_VIRT(pgd_index, pud_index, pmd_index, pte_index, page_index) \
	((void *)(_pgd_index_to_virt((unsigned long long)(pgd_index)) + \
		  _pud_index_to_virt((unsigned long long)(pud_index)) + \
		  _pmd_index_to_virt((unsigned long long)(pmd_index)) + \
		  _pte_index_to_virt((unsigned long long)(pte_index)) + \
		  (unsigned long long)(page_index)))

void signal_handler_sleep(int sig)
{
	printf("[*] handling ctrl-c by sleeping backgorund thread\n");
	printf("!! >> if you did this while in the root shell, "
	       "the terminal will be messed up << !!\n");
	sleep(9999);
}

static void pin_cpu(int cpu_id)
{
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(cpu_id, &mask);

	if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
		perror("sched_setaffinity");
		exit(1);
	}
}

static void alloc_3ptes()
{
	void *_pmd_area, *pmd_kernel_area, *pmd_data_area;
	unsigned long long *vstart, *off;

	printf("[+] doing first useless allocs to setup caching and stuff...\n");

	pin_cpu(0);

	printf("[+] allocate a PUD (and a PMD+PTE) for PMD \n");
	vstart = PTI_TO_VIRT(0, 1, 0, 0, 0);
	mmap((void *)vstart, 0x3000, PROT_READ | PROT_WRITE,
	     MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	// Write to [0:0x1000] to trigger page fault which will allocate a PTE.
	printf("[+] Write to [0:0x1000] at %p\n", vstart);
	*vstart = 0xDEADBEEF;
	printf("[+] Write to [0:0x1000] done\n");

	// Write to [0x1000:0x2000] to trigger page fault which will allocate
	// a new PTE.
	off = vstart + (0x1000 / sizeof(unsigned long long));
	printf("[+] Write to [0x1000:0x2000] at %p\n", off);
	*off = 0xDEADBEEF;
	printf("[+] Write to [0x1000:0x2000] done\n");

	// Write to [0x2000:0x3000] to trigger page fault which will allocate
	// a new PTE.
	off = vstart + (0x2000 / sizeof(unsigned long long));
	printf("[+] Write to [0x2000:0x3000] at %p\n", off);
	*off = 0xDEADBEEF;
	printf("[+] Write to [0x2000:0x3000] done\n");

	return;
}

static void do_unshare()
{
	int retv;

	printf("[+] creating user namespace (CLONE_NEWUSER)...\n");
	retv = unshare(CLONE_NEWUSER);
	if (retv == -1) {
		perror("unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}

	printf("[+] creating network namespace (CLONE_NEWNET)...\n");
	retv = unshare(CLONE_NEWNET);
	if (retv == -1) {
		perror("unshare(CLONE_NEWNET)");
		exit(EXIT_FAILURE);
	}
}

void write_file(const char *filename, const char *buf, size_t buflen,
		unsigned int flags)
{
	int fd;

	fd = open(filename, O_WRONLY | O_CREAT | flags, 0755);
	if (fd < 0) {
		perror("open$write_file");
		exit(EXIT_FAILURE);
	}

	if (write(fd, buf, buflen) != buflen) {
		perror("write$write_file");
		exit(EXIT_FAILURE);
	}

	close(fd);
}

static void configure_uid_map(uid_t old_uid, gid_t old_gid)
{
	char uid_map[128];
	char gid_map[128];

	printf("[+] setting up UID namespace...\n");

	sprintf(uid_map, "0 %d 1\n", old_uid);
	sprintf(gid_map, "0 %d 1\n", old_gid);

	printf("[+] mapping uid %d to namespace uid 0...\n", old_uid);
	write_file("/proc/self/uid_map", uid_map, strlen(uid_map), 0);

	printf("[+] deny namespace rights to set user groups...\n");
	write_file("/proc/self/setgroups", "deny", strlen("deny"), 0);

	printf("[+] mapping gid %d to namespace gid 0...\n", old_gid);
	write_file("/proc/self/gid_map", gid_map, strlen(gid_map), 0);
}

void setup_env()
{
	uid_t uid = getuid();
	gid_t gid = getgid();

	do_unshare();
	configure_uid_map(uid, gid);
}

// gcc alloc_3ptes.c -o test
int main()
{
	int *status;
	status = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	*status = 0;

	if (fork() == 0) {
		signal(SIGINT, signal_handler_sleep);
		setup_env();

		alloc_3ptes();
		*status = 1;

		sleep(9999);
	}

	SPINLOCK(*status == 0);

	return 0;
}