/* Pixel 8 Pro, stock CP3A.261005.005. Derived from Google build 16261587.
 * Symbols and allocation return sites: artifacts/vmlinux.elf, DWARF/disassembly.
 * Do not reuse this profile for another kernel, even with the same KMI.
 */
#ifndef PIXEL_TIMER_OFFSETS_H
#define PIXEL_TIMER_OFFSETS_H
#define TARGET_RELEASE "6.1.162-android14-11-g9dd05ae3a1de-ab16261587"
#define TARGET_DEVICE "husky"
#define PAGE 4096UL
#define TRACE_CPUS 9
#define STATIC_TIMER_SITE 0xffffffc008192f7cULL
#define TIMER_ALLOC 0x108ULL
#define CRED_REQ 0xb0ULL
#define CRED_ALLOC 0xc0ULL
#define CRED_SITE_STATIC 0xffffffc0080e5018ULL
#define TASK_SITE_STATIC 0xffffffc0080ac068ULL
/* KASLR (CONFIG_ARM64_VA_BITS_39): __pi_kaslr_early_init computes the image
 * seed as (rnd & 0x1fffffffff) + 2^36 and __primary_switch rounds it down to
 * a 2MB boundary, so the runtime slide lies in [2^36, 3*2^36).  Samsung
 * builds randomize across a much smaller window; the old 1GB check is wrong
 * on this device (see artifacts/vmlinux.elf, __primary_switch). */
#define KASLR_MIN_SLIDE 0x1000000000ULL
#define KASLR_MAX_SLIDE 0x3000000000ULL
#define KASLR_SLIDE_ALIGN 0x1fffffULL
#define TASK_ALLOC_BYTES 0x12c0ULL
#define OFF_TASK_CRED 0x838ULL
#define OFF_TASK_LOGINUID 0x8f8ULL
#define OFF_TQ_LEFTMOST_0 0x7a0ULL
#define OFF_TQ_LEFTMOST_1 0x7b8ULL
#define OFF_TQ_LEFTMOST_2 0x7d0ULL
#define CRED_UID_OFF 4ULL
#define SELINUX_STATE_STATIC 0xffffffc00a25b448ULL
/* This kernel places notif_lock at -8; initialized at +2 must survive. */
#define SELINUX_ENFORCE_ZAP (SELINUX_STATE_STATIC - 7ULL)
#define PANIC_ON_WARN_STATIC 0xffffffc00a00ac08ULL
#define ROOT_USER_STATIC 0xffffffc00a0305c0ULL
#define INIT_USER_NS_STATIC 0xffffffc00a030330ULL
#define INIT_UCOUNTS_STATIC 0xffffffc00a031e48ULL
#define INIT_GROUPS_STATIC 0xffffffc00a0318e0ULL
#define SELINUX_BLOB_OFF 0ULL
#define SELINUX_SID_KERNEL 1U
#define FULLCAP 0x1ffffffffffULL
#endif
