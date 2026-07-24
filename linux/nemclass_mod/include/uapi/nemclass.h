/* SPDX-License-Identifier: GPL-2.0 */
/*
 * nemclass_mod UAPI — shared ABI between the kernel module and userspace
 * (the nemclass-core Rust provider mirrors this file).
 *
 * All ioctl argument structs are fixed-size and naturally aligned. Userspace
 * buffers are passed as __u64 addresses (never as native pointers) so the ABI
 * is identical for 32- and 64-bit callers.
 */
#ifndef _UAPI_NEMCLASS_H
#define _UAPI_NEMCLASS_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define NEMCLASS_ABI_VERSION	1u
#define NEMCLASS_IOC_MAGIC	'N'

/* Maximum symmetric-key length accepted by NEMCLASS_IOC_AUTH. */
#define NEMCLASS_KEY_MAX	64u

/* Breakpoint kinds (nemclass_bp_set.kind). */
#define NEMCLASS_BP_KIND_HW	0u	/* hardware breakpoint / watchpoint */
#define NEMCLASS_BP_KIND_UPROBE	1u	/* software exec breakpoint (uprobe) */

/* Hardware breakpoint trigger types (nemclass_bp_set.type). */
#define NEMCLASS_BP_X		0u	/* execute */
#define NEMCLASS_BP_W		1u	/* data write */
#define NEMCLASS_BP_RW		2u	/* data read or write */
#define NEMCLASS_BP_R		3u	/* data read */

/* --- ioctl argument structs ------------------------------------------- */

struct nemclass_auth {
	__u8  key[NEMCLASS_KEY_MAX];
	__u32 key_len;
	__u32 _pad;
};

struct nemclass_version {
	__u32 abi;		/* out: NEMCLASS_ABI_VERSION */
	__u32 _pad;
};

/* READ / WRITE: transfer [addr, addr+len) of target `pid` to/from `ubuf`. */
struct nemclass_rw {
	__s32 pid;
	__u32 _pad;
	__u64 addr;		/* target virtual address */
	__u64 len;		/* requested byte count */
	__u64 ubuf;		/* userspace buffer address */
	__u64 done;		/* out: bytes actually transferred */
};

/* One VMA record produced by ENUM_REGIONS. */
struct nemclass_region {
	__u64 start;
	__u64 end;
	__u64 file_off;		/* vma file offset, 0 for anon */
	__u32 prot;		/* bit0=r bit1=w bit2=x */
	__u32 _pad;
};

struct nemclass_enum_regions {
	__s32 pid;
	__u32 max;		/* capacity of `ubuf` array, in records */
	__u64 ubuf;		/* userspace array of struct nemclass_region */
	__u32 count;		/* out: records written (<= max) */
	__u32 total;		/* out: total regions (may exceed max) */
};

/*
 * BP_SET: register a breakpoint on target `pid`.
 *   HW     — watch `addr` with `type`/`len` (DR-backed, per-thread).
 *   UPROBE — exec breakpoint at `addr`; inode+file-offset are resolved from
 *            the target's VMA covering `addr`.
 * Returns an opaque `slot` (>=0) owned by this fd; -errno on failure.
 */
struct nemclass_bp_set {
	__s32 pid;
	__u32 kind;		/* NEMCLASS_BP_KIND_* */
	__u64 addr;		/* target virtual address */
	__u32 len;		/* HW: 1/2/4/8 */
	__u32 type;		/* HW: NEMCLASS_BP_* */
	__s32 slot;		/* out: assigned slot id */
	__u32 _pad;
};

struct nemclass_bp_clear {
	__s32 slot;
	__u32 _pad;
};

/*
 * A breakpoint/uprobe hit. Register snapshot is x86_64; execution is NOT
 * halted — this records "what accessed/executed here" and continues.
 */
struct nemclass_event {
	__s32 slot;
	__s32 pid;
	__s32 tid;
	__u32 kind;		/* NEMCLASS_BP_KIND_* */
	__u64 addr;		/* watched/probe address */
	__u64 ip;
	__u64 sp;
	__u64 flags;
	__u64 ax, bx, cx, dx, si, di, bp;
	__u64 r8, r9, r10, r11, r12, r13, r14, r15;
};

/* WAIT_EVENT: block until the next hit is available for this fd. */
struct nemclass_wait {
	__u64 ubuf;		/* userspace struct nemclass_event */
	__s32 timeout_ms;	/* <0 block forever, 0 non-blocking, >0 ms */
	__u32 _pad;
};

/* PTRACE_QUERY (fills out fields) / PTRACE_HIDE (uses pid only). */
struct nemclass_ptrace {
	__s32 pid;
	__s32 tracer_pid;	/* out */
	__u8  traced;		/* out: nonzero if currently ptraced */
	__u8  _pad[7];
};

/* --- ioctl codes ------------------------------------------------------ */

#define NEMCLASS_IOC_AUTH \
	_IOW(NEMCLASS_IOC_MAGIC, 0x01, struct nemclass_auth)
#define NEMCLASS_IOC_VERSION \
	_IOR(NEMCLASS_IOC_MAGIC, 0x02, struct nemclass_version)

#define NEMCLASS_IOC_READ \
	_IOWR(NEMCLASS_IOC_MAGIC, 0x10, struct nemclass_rw)
#define NEMCLASS_IOC_WRITE \
	_IOWR(NEMCLASS_IOC_MAGIC, 0x11, struct nemclass_rw)
#define NEMCLASS_IOC_ENUM_REGIONS \
	_IOWR(NEMCLASS_IOC_MAGIC, 0x12, struct nemclass_enum_regions)

#define NEMCLASS_IOC_BP_SET \
	_IOWR(NEMCLASS_IOC_MAGIC, 0x20, struct nemclass_bp_set)
#define NEMCLASS_IOC_BP_CLEAR \
	_IOW(NEMCLASS_IOC_MAGIC, 0x21, struct nemclass_bp_clear)
#define NEMCLASS_IOC_WAIT_EVENT \
	_IOWR(NEMCLASS_IOC_MAGIC, 0x22, struct nemclass_wait)

#define NEMCLASS_IOC_PTRACE_QUERY \
	_IOWR(NEMCLASS_IOC_MAGIC, 0x30, struct nemclass_ptrace)
#define NEMCLASS_IOC_PTRACE_HIDE \
	_IOW(NEMCLASS_IOC_MAGIC, 0x31, struct nemclass_ptrace)

#endif /* _UAPI_NEMCLASS_H */
